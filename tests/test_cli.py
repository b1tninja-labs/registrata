import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from registrata import RwhoisServer
from registrata.backends.memory import MemoryBackend
from registrata.cli import build_parser, main
from registrata.observability import MARKER

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    src = str(PROJECT_ROOT / "src")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = src if not existing else src + os.pathsep + existing
    return subprocess.run(
        [sys.executable, "-m", "registrata.cli", *args],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )


def test_cli_reports_its_version():
    """`--version` belongs on a tool that ends up in scripts and bug reports.

    It has to work with nothing else on the command line, and it has to agree with
    the package version rather than drifting into a string somebody maintains.
    """
    from registrata import __version__

    proc = _run_cli("--version")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == f"registrata {__version__}"


@pytest.fixture
def server():
    backend = MemoryBackend("example.com")
    backend.add_soa("example.com", primary="127.0.0.1:4321")
    backend.add_object(
        "domain",
        {
            "Class-Name": "domain",
            "Auth-Area": "example.com",
            "ID": "dom-1.example.com",
            "Updated": "19970107201111000",
            "Domain-Name": "example.com",
        },
        auth_area="example.com",
    )
    app = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=5
    )
    host, port = app.start()
    yield host, port
    app.shutdown()


def test_cli_help():
    proc = _run_cli("--help")
    assert proc.returncode == 0
    assert "RFC 2167 RWhois" in proc.stdout
    assert "--log-level" in proc.stdout
    assert "--log-json" in proc.stdout


def test_cli_query_help():
    proc = _run_cli("query", "--help")
    assert proc.returncode == 0
    assert "--class" in proc.stdout


def test_cli_lookup_help():
    proc = _run_cli("lookup", "--help")
    assert proc.returncode == 0
    assert "--sources" in proc.stdout
    assert "--rwhois-server" in proc.stdout
    assert "--rate-limit" in proc.stdout
    assert "--retries" in proc.stdout
    assert "--cache-ttl" in proc.stdout
    assert "--follow-referrals" in proc.stdout
    assert "--max-bytes" in proc.stdout
    assert "--circuit-failure-threshold" in proc.stdout
    assert "--no-circuit-breaker" in proc.stdout
    assert "--rdap-revalidation-ttl" in proc.stdout
    assert "--no-rdap-conditional" in proc.stdout


def test_cli_resource_command_help():
    expectations = {
        "whois": "--no-referrals",
        "domain": "--records-only",
        "ip": "--sources",
        "asn": "--sources",
        "rdap": "--record-only",
        "gateway": "--api-key",
        "compare": "--fields",
        "trace": "--sources",
        "doctor": "--no-lookup",
        "record-schema": "schema",
    }
    for command, needle in expectations.items():
        proc = _run_cli(command, "--help")
        assert proc.returncode == 0
        assert needle in proc.stdout


def test_serve_can_defer_registrations_from_the_command_line():
    """A maintenance switch that only exists as a library argument is not an option.

    The way an operator takes an RWhois server out of registration mode has to be a flag,
    otherwise the window gets skipped and writes keep landing during maintenance.
    """
    parser = build_parser()
    assert parser.parse_args(["serve"]).defer_registrations is False
    assert (
        parser.parse_args(["serve", "--defer-registrations"]).defer_registrations
        is True
    )


def test_cli_check_server_json_local(server, capsys):
    host, port = server
    rc = main(
        [
            "check-server",
            host,
            str(port),
            "--class",
            "domain",
            "--query",
            "example.com",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    data = json.loads(captured.out)
    assert data["ok"] is True
    assert data["items"]


def test_cli_query_json_local(server, capsys):
    host, port = server
    rc = main(["query", host, "example.com", str(port), "--class", "domain", "--json"])
    captured = capsys.readouterr()
    assert rc == 0
    data = json.loads(captured.out)
    assert data["ok"] is True
    assert data["objects"][0]["id"] == "dom-1.example.com"


def test_cli_unified_resource_commands_default_sources(monkeypatch, capsys):
    from registrata import experimental
    from registrata.experimental.lookup import LookupResult
    from registrata.model import RegistrationRecord

    calls = []

    def fake_lookup(resource, *, sources=None, **kwargs):
        calls.append(sources)
        record = RegistrationRecord(source="rdap", kind="domain", identifier=resource)
        return LookupResult(
            resource=resource,
            kind="domain",
            sources=sources or [],
            results={"rdap": object()},
            normalized=record.as_dict(),
            records=[record],
        )

    monkeypatch.setattr(experimental, "lookup", fake_lookup)

    assert main(["domain", "example.com", "--json", "--records-only"]) == 0
    domain_data = json.loads(capsys.readouterr().out)
    assert main(["ip", "8.8.8.8", "--json", "--records-only"]) == 0
    ip_data = json.loads(capsys.readouterr().out)
    assert main(["asn", "AS15169", "--json", "--records-only"]) == 0
    asn_data = json.loads(capsys.readouterr().out)
    assert calls == [["rdap", "whois"], ["rdap"], ["rdap"]]
    assert domain_data["resource"] == "example.com"
    assert ip_data["resource"] == "8.8.8.8"
    assert asn_data["resource"] == "AS15169"


def test_cli_whois_json_uses_direct_whois(monkeypatch, capsys):
    from registrata.experimental import whois as whois_module

    def fake_lookup(resource, **kwargs):
        return whois_module.WhoisResult(
            query=resource,
            server="whois.test",
            raw="Domain Name: EXAMPLE.COM\n",
            fields={"domain name": ["EXAMPLE.COM"]},
        )

    monkeypatch.setattr(whois_module, "lookup_whois", fake_lookup)
    rc = main(
        [
            "whois",
            "example.com",
            "--whois-server",
            "whois.test",
            "--no-referrals",
            "--json",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["normalized"]["kind"] == "domain"
    assert data["normalized"]["identifier"] == "EXAMPLE.COM"


def test_cli_rdap_json_uses_direct_rdap(monkeypatch, capsys):
    from registrata.experimental import rdap as rdap_module

    def fake_lookup(resource, **kwargs):
        return rdap_module.RdapResult(
            url="https://rdap.example/domain/" + resource,
            status=200,
            data={
                "objectClassName": "domain",
                "ldhName": resource,
                "status": ["active"],
            },
        )

    monkeypatch.setattr(rdap_module, "lookup_rdap", fake_lookup)
    rc = main(["rdap", "example.com", "--json", "--record-only"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["record"]["kind"] == "domain"
    assert data["record"]["identifier"] == "example.com"


def test_cli_log_json_emits_diagnostics(monkeypatch, capsys):
    from registrata.experimental import rdap as rdap_module

    def fake_lookup(resource, **kwargs):
        return rdap_module.RdapResult(
            url="https://rdap.example/domain/" + resource,
            status=200,
            data={"objectClassName": "domain", "ldhName": resource},
        )

    root = logging.getLogger()
    old_level = root.level
    old_handlers = list(root.handlers)
    monkeypatch.setattr(rdap_module, "lookup_rdap", fake_lookup)
    try:
        rc = main(
            ["--log-level", "info", "--log-json", "rdap", "example.com", "--json"]
        )
        captured = capsys.readouterr()
    finally:
        for handler in list(root.handlers):
            if getattr(handler, MARKER, False):
                root.removeHandler(handler)
        root.setLevel(old_level)
        for handler in old_handlers:
            if handler not in root.handlers:
                root.addHandler(handler)
    assert rc == 0
    assert any("rdap_command" in line for line in captured.err.splitlines())


def test_cli_compare_json(monkeypatch, capsys):
    from registrata import experimental
    from registrata.experimental.lookup import LookupResult
    from registrata.model import RegistrationRecord

    records = [
        RegistrationRecord(
            source="rdap", kind="domain", identifier="example.com", statuses=["active"]
        ),
        RegistrationRecord(
            source="whois", kind="domain", identifier="example.com", statuses=["ACTIVE"]
        ),
    ]

    def fake_lookup(resource, **kwargs):
        return LookupResult(
            resource=resource,
            kind="domain",
            sources=kwargs.get("sources") or ["rdap", "whois"],
            results={"rdap": object(), "whois": object()},
            records=records,
        )

    monkeypatch.setattr(experimental, "lookup", fake_lookup)
    rc = main(["compare", "example.com", "--json", "--fields", "identifier,statuses"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["sources"] == ["rdap", "whois"]
    assert data["report"]["matches"] == ["identifier", "statuses"]
    assert data["report"]["score"] == 1.0


def test_cli_compare_one_source_does_not_claim_agreement(monkeypatch, capsys):
    """The symptom was on a terminal, not in JSON.

    One source answering while the other failed printed "score: 1.0" and a match line per field,
    a few lines above an error from the source that never answered -- two statements about the
    same lookup that contradict each other.
    """
    from registrata import experimental
    from registrata.experimental.lookup import LookupResult
    from registrata.model import RegistrationRecord

    def fake_lookup(resource, **kwargs):
        return LookupResult(
            resource=resource,
            kind="domain",
            sources=["rdap", "whois"],
            results={"rdap": object()},
            records=[
                RegistrationRecord(
                    source="rdap", kind="domain", identifier="example.com"
                )
            ],
        )

    monkeypatch.setattr(experimental, "lookup", fake_lookup)
    rc = main(["compare", "example.com", "--fields", "identifier,statuses"])
    out = capsys.readouterr().out

    assert rc == 0, "a lookup that answered is not a command failure"
    assert "score: n/a" in out, out
    assert "1.0" not in out, f"an unmeasured agreement was reported as a score: {out}"
    assert "match identifier" not in out, (
        f"fields were reported as matching with one source: {out}"
    )


def test_cli_lookup_provenance_json(monkeypatch, capsys):
    from registrata import experimental
    from registrata.experimental import rdap as rdap_module
    from registrata.experimental.lookup import LookupResult
    from registrata.model import RegistrationRecord

    rdap_result = rdap_module.RdapResult(
        url="https://rdap.example/domain/example.com",
        status=200,
        data={"objectClassName": "domain", "ldhName": "example.com"},
    )

    def fake_lookup(resource, **kwargs):
        return LookupResult(
            resource=resource,
            kind="domain",
            sources=kwargs.get("sources") or ["rdap"],
            results={"rdap": rdap_result},
            records=[
                RegistrationRecord(
                    source="rdap", kind="domain", identifier="example.com"
                )
            ],
        )

    monkeypatch.setattr(experimental, "lookup", fake_lookup)
    rc = main(["lookup", "example.com", "--json", "--provenance"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert "records" not in data
    hop = data["provenance"]["hops"][0]
    assert hop["source"] == "rdap"
    assert hop["url"] == "https://rdap.example/domain/example.com"


def test_cli_record_schema_json_no_resource(capsys):
    rc = main(["record-schema", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["title"] == "registrata RegistrationRecord"
    assert "properties" in data


def test_cli_record_schema_resource_validates_records(monkeypatch, capsys):
    from registrata import experimental
    from registrata.experimental.lookup import LookupResult
    from registrata.model import RegistrationRecord

    def fake_lookup(resource, **kwargs):
        return LookupResult(
            resource=resource,
            kind="domain",
            sources=kwargs.get("sources") or ["rdap"],
            results={"rdap": object()},
            records=[
                RegistrationRecord(
                    source="rdap", kind="domain", identifier="example.com"
                )
            ],
        )

    monkeypatch.setattr(experimental, "lookup", fake_lookup)
    rc = main(["record-schema", "example.com", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["schema_version"]
    assert data["records"][0]["record"]["identifier"] == "example.com"
    assert data["invalid"] == []


def test_cli_trace_json(monkeypatch, capsys):
    from registrata import experimental
    from registrata.experimental import rdap as rdap_module
    from registrata.experimental.lookup import LookupResult
    from registrata.model import RegistrationRecord

    rdap_result = rdap_module.RdapResult(
        url="https://rdap.example/domain/example.com",
        status=200,
        data={"objectClassName": "domain", "ldhName": "example.com"},
        headers={"ETag": "v1"},
        cache_mode="revalidated",
        stale=False,
    )

    def fake_lookup(resource, **kwargs):
        return LookupResult(
            resource=resource,
            kind="domain",
            sources=kwargs.get("sources") or ["rdap"],
            results={"rdap": rdap_result},
            records=[
                RegistrationRecord(
                    source="rdap", kind="domain", identifier="example.com"
                )
            ],
            breaker=kwargs.get("breaker"),
        )

    monkeypatch.setattr(experimental, "lookup", fake_lookup)
    rc = main(["trace", "example.com", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert (
        data["source_status"]["rdap"]["url"]
        == "https://rdap.example/domain/example.com"
    )
    assert data["source_status"]["rdap"]["etag"] == "v1"
    assert data["source_status"]["rdap"]["cache_mode"] == "revalidated"
    assert data["provenance"]["hops"][0]["source"] == "rdap"


def test_cli_doctor_json_without_lookup(tmp_path, capsys):
    rc = main(
        ["doctor", "example.com", "--json", "--no-lookup", "--cache-dir", str(tmp_path)]
    )
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["healthy"] is True
    assert data["lookup_performed"] is False
    assert data["kind"] == "domain"
    assert {check["name"] for check in data["checks"]} == {
        "features",
        "classification",
        "lookup",
        "records",
        "comparison",
        "bootstrap_cache",
        "circuit_breakers",
    }
    assert data["suggestions"]


def test_cli_doctor_json_with_lookup(monkeypatch, capsys):
    from registrata import experimental
    from registrata.experimental.lookup import LookupResult
    from registrata.model import RegistrationRecord

    records = [
        RegistrationRecord(
            source="rdap", kind="domain", identifier="example.com", statuses=["active"]
        ),
        RegistrationRecord(
            source="whois", kind="domain", identifier="EXAMPLE.COM", statuses=["ACTIVE"]
        ),
    ]

    def fake_lookup(resource, **kwargs):
        return LookupResult(
            resource=resource,
            kind="domain",
            sources=kwargs.get("sources") or ["rdap", "whois"],
            results={"rdap": object(), "whois": object()},
            records=records,
            breaker=kwargs.get("breaker"),
        )

    monkeypatch.setattr(experimental, "lookup", fake_lookup)
    rc = main(["doctor", "example.com", "--json", "--fields", "identifier,statuses"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["healthy"] is True
    comparison = next(
        check for check in data["checks"] if check["name"] == "comparison"
    )["report"]
    assert comparison["score"] == 1.0


def test_cli_gateway_help_lists_tls_flags():
    proc = _run_cli("gateway", "--help")
    assert proc.returncode == 0
    assert "--tls-certfile" in proc.stdout
    assert "--tls-keyfile" in proc.stdout


def test_cli_gateway_reports_tls_configuration_error(tmp_path):
    # Regression guard: this command once died with TypeError while enabling the
    # gateway feature flag, so the failure must stay a clean operator message.
    missing = tmp_path / "missing-cert.pem"
    proc = _run_cli(
        "gateway",
        "--tls-certfile",
        str(missing),
        "--tls-keyfile",
        str(missing),
        "--port",
        "0",
    )
    assert proc.returncode == 2
    assert "gateway configuration error" in proc.stderr
    assert "certificate file not found" in proc.stderr


def test_cli_gateway_requires_cert_and_key_pair(tmp_path):
    cert = tmp_path / "only-cert.pem"
    cert.write_text("stub", encoding="utf-8")
    proc = _run_cli("gateway", "--tls-certfile", str(cert), "--port", "0")
    assert proc.returncode == 2
    assert "requires both tls_certfile and tls_keyfile" in proc.stderr


def _rdap_extension_body(resource: str) -> dict:
    return {
        "objectClassName": "domain",
        "ldhName": resource,
        "lang": "en",
        "rdapConformance": ["rdap_level_0", "redacted", "subsetting"],
        "notices": [
            {
                "title": "Data Policy",
                "type": "object truncated due to authorization",
                "description": ["Some fields are withheld."],
            }
        ],
        "redacted": [{"name": {"type": "Registrant Name"}, "method": "removal"}],
        "subsetting_metadata": {
            "currentFieldSet": "brief",
            "availableFieldSets": [{"name": "brief", "default": True}],
        },
    }


def test_cli_rdap_json_reports_rdap_extensions(monkeypatch, capsys):
    from registrata.experimental import rdap as rdap_module

    def fake_lookup(resource, **kwargs):
        return rdap_module.RdapResult(
            url="https://rdap.example/domain/" + resource,
            status=200,
            headers={
                "Content-Type": "application/rdap+json",
                # A Link header is a link too (RFC 8288), so it must show up with
                # the body links rather than only in the raw header dump.
                "Link": '<https://rdap.example/domain/other.example>; rel="related"',
            },
            data=_rdap_extension_body(resource),
        )

    monkeypatch.setattr(rdap_module, "lookup_rdap", fake_lookup)
    assert main(["rdap", "example.com", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    record = payload["normalized"]
    assert record["conformance"] == ["rdap_level_0", "redacted", "subsetting"]
    assert record["lang"] == "en"
    assert record["truncated"] is True
    assert record["truncation"][0]["type"] == "object truncated due to authorization"
    assert record["redacted"][0]["name_type"] == "Registrant Name"
    assert record["subsetting"]["current_field_set"] == "brief"
    assert [link["scope"] for link in record["links"] if link["rel"] == "related"] == [
        "http:link"
    ]
    assert record["context"]["http"]["status"] == 200
    assert "rdap_error" not in payload


def test_cli_rdap_json_reports_error_response_body(monkeypatch, capsys):
    from registrata.experimental import rdap as rdap_module

    def fake_lookup(resource, **kwargs):
        return rdap_module.RdapResult(
            url="https://rdap.example/domain/" + resource,
            status=404,
            data={
                "errorCode": 404,
                "title": "Not found",
                "description": ["no such domain"],
                "lang": "en",
            },
        )

    monkeypatch.setattr(rdap_module, "lookup_rdap", fake_lookup)
    assert main(["rdap", "missing.example", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["rdap_error"]["error_code"] == 404
    assert payload["rdap_error"]["title"] == "Not found"
    assert payload["rdap_error"]["description"] == ["no such domain"]


def test_cli_rdap_human_output_flags_partial_answer(monkeypatch, capsys):
    from registrata.experimental import rdap as rdap_module

    monkeypatch.setattr(
        rdap_module,
        "lookup_rdap",
        lambda resource, **kwargs: rdap_module.RdapResult(
            url="https://rdap.example/domain/" + resource,
            status=200,
            headers={},
            data=_rdap_extension_body(resource),
        ),
    )
    assert main(["rdap", "example.com"]) == 0
    captured = capsys.readouterr()
    assert "conformance: rdap_level_0, redacted, subsetting" in captured.out
    assert "truncated (object): top: Data Policy" in captured.out
    assert "redacted: Registrant Name [removal]" in captured.out
    assert "field set: brief of [brief]" in captured.out
    assert "registry sent a truncated response" in captured.err


def test_cli_rdap_requests_a_field_set(monkeypatch, capsys):
    from registrata.experimental import rdap as rdap_module

    seen: dict = {}

    def fake_lookup(resource, **kwargs):
        seen.update(kwargs)
        return rdap_module.RdapResult(
            url="https://rdap.example/domain/" + resource,
            status=200,
            data=_rdap_extension_body(resource),
        )

    monkeypatch.setattr(rdap_module, "lookup_rdap", fake_lookup)
    assert main(["rdap", "example.com", "--field-set", "brief", "--json"]) == 0
    capsys.readouterr()
    assert seen["field_set"] == "brief"


def _run_cli_with_stdin(
    input_text: str, *args: str
) -> subprocess.CompletedProcess[str]:
    """``_run_cli`` for commands that read stdin; identical apart from the input pipe."""
    env = os.environ.copy()
    src = str(PROJECT_ROOT / "src")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = src if not existing else src + os.pathsep + existing
    return subprocess.run(
        [sys.executable, "-m", "registrata.cli", *args],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
        input=input_text,
    )


def _bulk_source_args(server) -> list[str]:
    """Point every bulk test at the in-process server above; nothing reaches the internet."""
    host, port = server
    return [
        "--sources",
        "rwhois",
        "--rwhois-server",
        host,
        "--rwhois-port",
        str(port),
        "--class",
        "domain",
    ]


def _bulk_file(tmp_path, *lines: str) -> str:
    path = tmp_path / "resources.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def test_cli_bulk_json_reports_summary_and_items_in_input_order(
    server, tmp_path, capsys
):
    path = _bulk_file(
        tmp_path,
        "# sweep of the demo zone",
        "",
        "dom-1.example.com",
        "example.com",
        "missing.example.com",
    )

    rc = main(["bulk", path, *_bulk_source_args(server), "--json"])
    captured = capsys.readouterr()

    assert rc == 0
    payload = json.loads(captured.out)
    assert set(payload) == {"summary", "items"}
    # The comment and the blank line never reach the runner, and what does is reported
    # in the order the file listed them.
    assert [item["resource"] for item in payload["items"]] == [
        "dom-1.example.com",
        "example.com",
        "missing.example.com",
    ]
    counts = payload["summary"]["counts"]
    assert counts["total"] == 3
    statuses = {item["resource"]: item["status"] for item in payload["items"]}
    assert statuses["dom-1.example.com"] == "ok"
    # "%error 230 No objects found" is what a working registry says when the object is not
    # there. It is an answer rather than a fault -- the circuit breaker has always counted it as
    # the endpoint working -- so the id reads "empty" and the sweep reports no source errors at
    # all. Counting it as an error made every negative answer indistinguishable from an outage,
    # which is the distinction this whole status vocabulary exists to keep.
    assert statuses["missing.example.com"] == "empty"
    assert not payload["summary"]["source_errors"]
    assert "bulk: total=3" in captured.err
    assert "bulk: total" not in captured.out


def test_cli_bulk_reads_resources_from_stdin(server):
    # "-" reads stdin, so this run goes through a child process; it still only talks to
    # the in-process server, which is listening on a loopback port.
    proc = _run_cli_with_stdin(
        "# from the pipe\n\ndom-1.example.com\nmissing.example.com\n",
        "bulk",
        "-",
        *_bulk_source_args(server),
        "--json",
    )

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert [item["resource"] for item in payload["items"]] == [
        "dom-1.example.com",
        "missing.example.com",
    ]
    assert payload["summary"]["counts"]["total"] == 2


def test_cli_bulk_missing_resource_file_exits_two(tmp_path, capsys):
    rc = main(["bulk", str(tmp_path / "no-such-file.txt")])
    captured = capsys.readouterr()

    assert rc == 2
    assert "resource file not found" in captured.err
    assert captured.out == ""


def test_cli_bulk_jsonl_streams_one_object_per_resource(server, tmp_path, capsys):
    path = _bulk_file(
        tmp_path, "dom-1.example.com", "example.com", "missing.example.com"
    )

    rc = main(["bulk", path, *_bulk_source_args(server), "--jsonl"])
    captured = capsys.readouterr()

    assert rc == 0
    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert len(lines) == 3
    emitted = [json.loads(line) for line in lines]
    # Streaming follows completion order, so only the set of resources is guaranteed.
    assert {entry["resource"] for entry in emitted} == {
        "dom-1.example.com",
        "example.com",
        "missing.example.com",
    }
    assert all(
        {"resource", "status", "ok", "duration_ms"} <= set(entry) for entry in emitted
    )
    assert "summary" not in captured.out
    assert "bulk: total=3" in captured.err


def test_cli_bulk_records_json_replaces_items_with_records(server, tmp_path, capsys):
    path = _bulk_file(tmp_path, "dom-1.example.com", "missing.example.com")

    rc = main(["bulk", path, *_bulk_source_args(server), "--records", "--json"])
    captured = capsys.readouterr()

    assert rc == 0
    payload = json.loads(captured.out)
    assert "records" in payload
    assert "items" not in payload
    assert payload["summary"]["counts"]["total"] == 2
    assert "dom-1.example.com" in [
        record["identifier"] for record in payload["records"]
    ]


def test_cli_bulk_human_output_lists_every_resource_and_the_totals(
    server, tmp_path, capsys
):
    path = _bulk_file(tmp_path, "dom-1.example.com", "missing.example.com")

    rc = main(["bulk", path, *_bulk_source_args(server)])
    captured = capsys.readouterr()

    assert rc == 0
    lines = captured.out.splitlines()
    assert any(
        line.startswith("ok") and line.endswith("dom-1.example.com") for line in lines
    )
    assert any(
        line.startswith("empty") and "missing.example.com" in line for line in lines
    )
    assert "bulk: total=2" in captured.err


def test_cli_bulk_deadline_stops_before_the_first_lookup(server, tmp_path, capsys):
    # "--deadline 0" is an explicit stop, not a way of switching the deadline off: the
    # limit is re-checked before each resource is dispatched, so an already-expired
    # deadline means the run never dials a registry at all and still accounts for every
    # resource as a skip.
    path = _bulk_file(
        tmp_path, "dom-1.example.com", "example.com", "missing.example.com"
    )

    rc = main(["bulk", path, *_bulk_source_args(server), "--deadline", "0", "--json"])
    captured = capsys.readouterr()

    assert rc == 0
    payload = json.loads(captured.out)
    counts = payload["summary"]["counts"]
    assert counts["total"] == 3
    assert counts["skipped"] == counts["total"]
    assert payload["summary"]["stopped_reason"] == "deadline exceeded"
    assert [item["status"] for item in payload["items"]] == ["skipped"] * 3
    assert {item["skipped"] for item in payload["items"]} == {"deadline exceeded"}
    assert "bulk: stopped early: deadline exceeded" in captured.err


def test_cli_bulk_a_generous_deadline_leaves_the_run_alone(server, tmp_path, capsys):
    # The other side of "--deadline 0": a deadline that is nowhere near being reached must
    # not colour the report. The run completes, nothing is skipped, and neither the JSON
    # summary nor the stderr line says it stopped early.
    path = _bulk_file(tmp_path, "dom-1.example.com", "example.com")

    rc = main(
        ["bulk", path, *_bulk_source_args(server), "--deadline", "3600", "--json"]
    )
    captured = capsys.readouterr()

    assert rc == 0
    payload = json.loads(captured.out)
    counts = payload["summary"]["counts"]
    assert counts["total"] == 2
    assert counts["skipped"] == 0
    assert [item["resource"] for item in payload["items"]] == [
        "dom-1.example.com",
        "example.com",
    ]
    assert "stopped_reason" not in payload["summary"]
    assert "bulk: stopped early" not in captured.err
    assert "bulk: total=2" in captured.err


def test_cli_bulk_help_documents_the_politeness_and_stop_flags():
    proc = _run_cli("bulk", "--help")

    assert proc.returncode == 0
    for flag in (
        "--concurrency",
        "--aggregate-rate",
        "--aggregate-burst",
        "--fail-fast",
        "--stop-on-open-circuit",
        "--deadline",
        "--jsonl",
        "--records",
    ):
        assert flag in proc.stdout


def test_cli_bulk_exits_one_when_a_registry_is_being_left_alone(tmp_path, capsys):
    """An endpoint that refuses service is status "blocked" and exits 1.

    This is exercised end to end rather than simulated. The local server cannot open a
    circuit: it answers a lookup with no objects as "%error 230", and 230 is below 400,
    so the breaker counts that exchange as the endpoint working. What does open a
    circuit is an endpoint that cannot be reached at all, so the run is pointed at a
    loopback port that was bound and immediately released - guaranteed to have nothing
    listening - with the failure threshold at 1 and one worker, so the second resource
    meets an open circuit.
    """
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    path = _bulk_file(tmp_path, "dom-1.example.com", "missing.example.com")

    rc = main(
        [
            "bulk",
            path,
            "--sources",
            "rwhois",
            "--rwhois-server",
            "127.0.0.1",
            "--rwhois-port",
            str(dead_port),
            "--class",
            "domain",
            "--concurrency",
            "1",
            "--timeout",
            "0.5",
            "--circuit-failure-threshold",
            "1",
            "--json",
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    counts = payload["summary"]["counts"]
    # Nothing listening is a failure, not an absence of data. Calling this "empty" -- which is
    # what it used to be -- would tell a script the sweep ran fine and these domains simply do
    # not exist, which is the one thing the status vocabulary promises not to do.
    assert [item["status"] for item in payload["items"]] == ["error", "blocked"]
    assert counts["blocked"] == 1
    assert payload["summary"]["circuit_open_errors"] == 1
    assert (
        payload["summary"]["circuit_breakers"][f"rwhois:127.0.0.1:{dead_port}"]["state"]
        == "open"
    )
    assert rc == 1
    # Being refused is reported, but nothing told the run to stop early.
    assert "stopped early" not in captured.err


def test_cli_bulk_misconfigured_source_exits_two(tmp_path, capsys):
    """Forgetting the server must not read as "the registries have no data".

    With ``--sources rwhois`` and no ``--rwhois-server`` nothing is ever asked, so
    every resource comes back empty. Exiting 0 there would tell a cron job that the
    list was answered, which is the difference between a bad domain list and a bad
    command line.
    """
    path = _bulk_file(tmp_path, "example.com")

    rc = main(["bulk", str(path), "--sources", "rwhois", "--json"])
    captured = capsys.readouterr()

    assert rc == 2
    assert "configuration error" in captured.err
    assert "server and port are required" in captured.err
    # The report is still emitted, because the detail is what tells you what to fix.
    payload = json.loads(captured.out)
    assert payload["summary"]["counts"]["total"] == 1
    assert payload["items"][0]["errors"] == [
        {
            "source": "rwhois",
            "message": "server and port are required",
            "kind": "configuration",
        }
    ]


def test_cli_bulk_empty_answer_from_a_configured_source_is_not_a_usage_error(
    server, tmp_path, capsys
):
    """The guard above must not turn a genuine no-data answer into exit 2."""
    path = _bulk_file(tmp_path, "does-not-exist.example.com")

    rc = main(
        [
            "bulk",
            str(path),
            "--sources",
            "rwhois",
            "--rwhois-server",
            server[0],
            "--rwhois-port",
            str(server[1]),
            "--class",
            "domain",
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert rc == 0
    assert "configuration error" not in captured.err
    payload = json.loads(captured.out)
    # A 230 from a server that is working is neither a misuse nor a fault: it is the answer
    # "not here". The point of the test is unchanged -- exit 0, not exit 2 -- but the report now
    # says so instead of logging a source error for a correct reply.
    assert payload["items"][0]["status"] == "empty"
    assert payload["items"][0]["errors"] == []
