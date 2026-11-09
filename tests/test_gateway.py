import json
import os
import shutil
import ssl
import subprocess
import urllib.error
import urllib.request

import pytest

from registrata import RwhoisServer
from registrata._flags import ExperimentalDisabled
from registrata.backends.memory import MemoryBackend
from registrata.experimental import gateway
from registrata.experimental.lookup import LookupResult
from registrata.experimental.rdap import RdapResult
from registrata.experimental.whois import WhoisResult
from registrata.model import RegistrationRecord


def _http_json(url: str):
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def _http_request(url: str, headers: dict[str, str] | None = None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _enable_gateway(monkeypatch):
    for name in (
        "REGISTRATA_ENABLE_EXPERIMENTAL",
        "RWHOIS_ENABLE_EXPERIMENTAL",
        "RWHOIS_ENABLE_EXPERIMENTAL_GATEWAY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REGISTRATA_ENABLE_EXPERIMENTAL_GATEWAY", "1")


def _disable_gateway(monkeypatch):
    for name in (
        "REGISTRATA_ENABLE_EXPERIMENTAL",
        "REGISTRATA_ENABLE_EXPERIMENTAL_GATEWAY",
        "RWHOIS_ENABLE_EXPERIMENTAL",
        "RWHOIS_ENABLE_EXPERIMENTAL_GATEWAY",
    ):
        monkeypatch.delenv(name, raising=False)


def _find_openssl() -> str | None:
    """Locate an openssl binary (Git for Windows bundles one outside PATH)."""
    found = shutil.which("openssl")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\bin\openssl.exe",
        "/usr/bin/openssl",
        "/opt/homebrew/bin/openssl",
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


OPENSSL = _find_openssl()
needs_openssl = pytest.mark.skipif(
    OPENSSL is None, reason="openssl is required to mint a throwaway test certificate"
)


def _self_signed_pair(tmp_path):
    cert = tmp_path / "gateway-cert.pem"
    key = tmp_path / "gateway-key.pem"
    subprocess.run(
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return cert, key


def test_gateway_disabled_by_default(monkeypatch):
    _disable_gateway(monkeypatch)
    with pytest.raises(ExperimentalDisabled):
        gateway.GatewayServer(gateway.GatewayConfig(bind="127.0.0.1", port=0))


def test_gateway_refuses_non_local_bind_without_allow_remote(monkeypatch):
    _enable_gateway(monkeypatch)
    with pytest.raises(ValueError):
        gateway.GatewayServer(gateway.GatewayConfig(bind="0.0.0.0", port=0))


def test_gateway_health_lookup_and_records_only(monkeypatch):
    _enable_gateway(monkeypatch)

    record = RegistrationRecord(source="rdap", kind="domain", identifier="example.com")

    def fake_lookup(resource, *, sources=None, **kwargs):
        return LookupResult(
            resource=resource,
            kind="domain",
            sources=sources or [],
            results={"rdap": object()},
            normalized=record.as_dict(),
            records=[record],
        )

    monkeypatch.setattr(gateway, "lookup", fake_lookup)
    server = gateway.GatewayServer(
        gateway.GatewayConfig(bind="127.0.0.1", port=0, lookup_sources="rdap,whois")
    )
    host, port = server.start()
    try:
        status, health = _http_json(f"http://{host}:{port}/health")
        assert status == 200
        assert health["status"] == "ok"
        assert "circuit_breakers" in health

        status, full = _http_json(f"http://{host}:{port}/lookup?resource=example.com")
        assert status == 200
        assert full["records"][0]["identifier"] == "example.com"

        status, compact = _http_json(
            f"http://{host}:{port}/lookup?resource=example.com&records=1"
        )
        assert status == 200
        assert set(compact) == {
            "resource",
            "kind",
            "sources",
            "ok",
            "unqueryable",
            "errors",
            "provenance",
            "records",
        }
        assert compact["provenance"]["sources"] == ["rdap", "whois"]
    finally:
        server.shutdown()


def test_gateway_settles_reserved_names_without_opening_a_socket(monkeypatch):
    """A gateway is somebody else's quota, in both directions.

    No ``lookup`` is injected here on purpose: the point is that the real code
    path refuses a reserved name locally, so a client cannot use a gateway to
    hammer registries about names that cannot be registered -- and cannot get a
    plausible fixture object back and read it as an answer.
    """
    _enable_gateway(monkeypatch)

    server = gateway.GatewayServer(
        gateway.GatewayConfig(bind="127.0.0.1", port=0, lookup_sources="rdap")
    )
    host, port = server.start()
    try:
        status, full = _http_json(f"http://{host}:{port}/lookup?resource=example.com")
        assert status == 200
        assert full["ok"] is False
        assert full["errors"] == [], "refusing a name is not an error"
        assert "RFC 2606" in full["unqueryable"]

        # The compact shape carries the reason too, or it reads as a request
        # that never happened.
        status, compact = _http_json(
            f"http://{host}:{port}/lookup?resource=example.com&records=1"
        )
        assert "RFC 2606" in compact["unqueryable"]

        # Opt-in: the name is asked about, and here the only source available is
        # one with no server configured, which proves the attempt was made.
        status, asked = _http_json(
            f"http://{host}:{port}/lookup?resource=example.com"
            "&query_reserved=1&sources=rwhois"
        )
        assert status == 200
        assert asked["unqueryable"] is None
        assert asked["errors"]
    finally:
        server.shutdown()


def test_gateway_whois_and_rdap_endpoints(monkeypatch):
    _enable_gateway(monkeypatch)

    def fake_lookup_whois(resource, **kwargs):
        return WhoisResult(
            query=resource,
            server="whois.test",
            raw="Domain Name: EXAMPLE.COM\n",
            fields={"domain name": ["EXAMPLE.COM"]},
        )

    def fake_lookup_rdap(resource, **kwargs):
        return RdapResult(
            url="https://rdap.example/domain/" + resource,
            status=200,
            data={
                "objectClassName": "domain",
                "ldhName": resource,
                "status": ["active"],
            },
        )

    monkeypatch.setattr(gateway, "lookup_whois", fake_lookup_whois)
    monkeypatch.setattr(gateway, "lookup_rdap", fake_lookup_rdap)
    server = gateway.GatewayServer(gateway.GatewayConfig(bind="127.0.0.1", port=0))
    host, port = server.start()
    try:
        status, whois_payload = _http_json(
            f"http://{host}:{port}/whois?resource=example.com"
        )
        assert status == 200
        assert whois_payload["normalized"]["kind"] == "domain"

        status, rdap_payload = _http_json(
            f"http://{host}:{port}/rdap?resource=example.com"
        )
        assert status == 200
        assert rdap_payload["normalized"]["identifier"] == "example.com"
    finally:
        server.shutdown()


def test_gateway_rdap_reports_extensions_error_body_and_field_set(monkeypatch):
    _enable_gateway(monkeypatch)
    seen: dict = {}

    def fake_lookup_rdap(resource, **kwargs):
        seen.update(kwargs)
        if kwargs.get("field_set") == "missing":
            return RdapResult(
                url="https://rdap.example/domain/" + resource,
                status=404,
                data={
                    "errorCode": 404,
                    "title": "Not found",
                    "description": ["no such domain"],
                },
            )
        return RdapResult(
            url="https://rdap.example/domain/" + resource,
            status=200,
            headers={
                "Content-Type": "application/rdap+json",
                "Content-Language": "en-CA",
                "Link": '<https://rdap.example/domain/other.example>; rel="related"',
            },
            data={
                "objectClassName": "domain",
                "ldhName": resource,
                "rdapConformance": ["rdap_level_0", "redacted"],
                "redacted": [
                    {
                        "name": {"type": "Registrant Name"},
                        "method": "emptyValue",
                        "postPath": "$.entities",
                    }
                ],
                "notices": [
                    {
                        "title": "Search Policy",
                        "type": "result set truncated due to excessive load",
                        "description": ["Fewer results than usual."],
                    }
                ],
            },
        )

    monkeypatch.setattr(gateway, "lookup_rdap", fake_lookup_rdap)
    server = gateway.GatewayServer(gateway.GatewayConfig(bind="127.0.0.1", port=0))
    host, port = server.start()
    try:
        status, payload = _http_json(
            f"http://{host}:{port}/rdap?resource=example.com&field_set=brief"
        )
        assert status == 200
        assert seen["field_set"] == "brief"
        record = payload["normalized"]
        assert record["conformance"] == ["rdap_level_0", "redacted"]
        assert record["redacted"][0]["method"] == "emptyValue"
        assert record["truncated"] is True
        assert record["truncation"][0]["truncation"] == "result set"
        # Language comes from the body, so Content-Language stays as context.
        assert record["lang"] is None
        assert record["context"]["http"]["content_language"] == "en-CA"
        assert [
            link["href"] for link in record["links"] if link["scope"] == "http:link"
        ] == ["https://rdap.example/domain/other.example"]

        # A negative answer is mirrored in the status line instead of being
        # reported as a success the client has to inspect the body to notice.
        status, payload = _http_request(
            f"http://{host}:{port}/rdap?resource=example.com&field_set=missing"
        )
        assert status == 404
        assert payload["rdap_error"]["error_code"] == 404
        assert payload["rdap_error"]["description"] == ["no such domain"]
    finally:
        server.shutdown()


def test_gateway_rate_limit_returns_429(monkeypatch):
    _enable_gateway(monkeypatch)
    server = gateway.GatewayServer(
        gateway.GatewayConfig(bind="127.0.0.1", port=0, rate_limit=0.001, burst=1)
    )
    host, port = server.start()
    try:
        status, health = _http_json(f"http://{host}:{port}/health")
        assert status == 200
        try:
            urllib.request.urlopen(f"http://{host}:{port}/health", timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 429
            assert b"rate limit" in exc.read()
        else:
            pytest.fail("expected 429")
    finally:
        server.shutdown()


def test_gateway_rwhois_endpoint_local_server(monkeypatch):
    _enable_gateway(monkeypatch)
    backend = MemoryBackend("example.com")
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
    rwhois_host, rwhois_port = app.start()
    server = gateway.GatewayServer(gateway.GatewayConfig(bind="127.0.0.1", port=0))
    host, port = server.start()
    try:
        url = (
            f"http://{host}:{port}/rwhois?resource=example.com"
            f"&server={rwhois_host}&port={rwhois_port}&class=domain&records=1"
        )
        status, payload = _http_json(url)
        assert status == 200
        assert payload["ok"] is True
        assert any(record["source"] == "rwhois" for record in payload["records"])
    finally:
        server.shutdown()
        app.shutdown()


def test_gateway_metrics_endpoint(monkeypatch):
    _enable_gateway(monkeypatch)
    server = gateway.GatewayServer(gateway.GatewayConfig(bind="127.0.0.1", port=0))
    host, port = server.start()
    try:
        health_status, _ = _http_request(f"http://{host}:{port}/health")
        metrics_status, metrics = _http_request(f"http://{host}:{port}/metrics")
        assert health_status == 200
        assert metrics_status == 200
        assert metrics["counters"]["gateway_request_total{path=/health}"] == 1
        assert (
            metrics["counters"]["gateway_response_total{path=/health,status=200}"] == 1
        )
        assert metrics["uptime_seconds"] >= 0.0
    finally:
        server.shutdown()


def test_gateway_requires_api_key_for_lookup(monkeypatch):
    _enable_gateway(monkeypatch)
    record = RegistrationRecord(source="rdap", kind="domain", identifier="example.com")

    def fake_lookup(resource, *, sources=None, **kwargs):
        return LookupResult(
            resource=resource,
            kind="domain",
            sources=sources or [],
            results={"rdap": object()},
            records=[record],
        )

    monkeypatch.setattr(gateway, "lookup", fake_lookup)
    server = gateway.GatewayServer(
        gateway.GatewayConfig(bind="127.0.0.1", port=0, api_key="secret")
    )
    host, port = server.start()
    try:
        health_status, _ = _http_request(f"http://{host}:{port}/health")
        missing_status, missing = _http_request(
            f"http://{host}:{port}/lookup?resource=example.com"
        )
        header_status, header_payload = _http_request(
            f"http://{host}:{port}/lookup?resource=example.com",
            headers={"X-API-Key": "secret"},
        )
        bearer_status, bearer_payload = _http_request(
            f"http://{host}:{port}/lookup?resource=example.com",
            headers={"Authorization": "Bearer secret"},
        )

        assert health_status == 200
        assert missing_status == 401
        assert missing["error"] == "unauthorized"
        assert header_status == 200
        assert header_payload["records"][0]["identifier"] == "example.com"
        assert bearer_status == 200
        assert bearer_payload["records"][0]["identifier"] == "example.com"
    finally:
        server.shutdown()


def test_gateway_metrics_track_unauthorized_requests(monkeypatch):
    _enable_gateway(monkeypatch)
    server = gateway.GatewayServer(
        gateway.GatewayConfig(bind="127.0.0.1", port=0, api_key="secret")
    )
    host, port = server.start()
    try:
        status, _ = _http_request(f"http://{host}:{port}/lookup?resource=example.com")
        metrics_status, metrics = _http_request(
            f"http://{host}:{port}/metrics", headers={"X-API-Key": "secret"}
        )
        assert status == 401
        assert metrics_status == 200
        assert metrics["counters"]["gateway_unauthorized_total{path=/lookup}"] == 1
        assert metrics["counters"]["gateway_status_total{path=/lookup,status=401}"] == 1
    finally:
        server.shutdown()


def test_gateway_tls_requires_both_cert_and_key():
    with pytest.raises(ValueError, match="both tls_certfile and tls_keyfile"):
        gateway.GatewayConfig(tls_certfile="cert.pem").validate()
    with pytest.raises(ValueError, match="both tls_certfile and tls_keyfile"):
        gateway.GatewayConfig(tls_keyfile="key.pem").validate()


def test_gateway_tls_rejects_missing_files(monkeypatch, tmp_path):
    _enable_gateway(monkeypatch)
    missing = tmp_path / "absent.pem"
    with pytest.raises(ValueError, match="certificate file not found"):
        gateway.GatewayServer(
            gateway.GatewayConfig(
                bind="127.0.0.1", port=0, tls_certfile=missing, tls_keyfile=missing
            )
        )


def test_gateway_tls_wraps_listening_socket(monkeypatch, tmp_path):
    _enable_gateway(monkeypatch)
    cert = tmp_path / "stub-cert.pem"
    key = tmp_path / "stub-key.pem"
    cert.write_text("stub", encoding="utf-8")
    key.write_text("stub", encoding="utf-8")
    # A bare context proves the listener gets wrapped; a real certificate is only
    # needed once a client performs a handshake.
    monkeypatch.setattr(
        gateway.GatewayConfig,
        "build_ssl_context",
        lambda self: ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER),
    )
    server = gateway.GatewayServer(
        gateway.GatewayConfig(
            bind="127.0.0.1", port=0, tls_certfile=cert, tls_keyfile=key
        )
    )
    server.start()
    try:
        assert isinstance(server._httpd.socket, ssl.SSLSocket)
        assert server.config.scheme == "https"
    finally:
        server.shutdown()


def test_gateway_health_reports_tls_disabled(monkeypatch):
    _enable_gateway(monkeypatch)
    server = gateway.GatewayServer(
        gateway.GatewayConfig(bind="127.0.0.1", port=0, metrics_enabled=False)
    )
    host, port = server.start()
    try:
        status, health = _http_json(f"http://{host}:{port}/health")
        assert status == 200
        assert health["tls"] is False
    finally:
        server.shutdown()


def test_gateway_tls_context_requires_configured_pair(monkeypatch, tmp_path):
    _enable_gateway(monkeypatch)
    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    cert.write_text("stub", encoding="utf-8")
    key.write_text("stub", encoding="utf-8")
    with pytest.raises(ssl.SSLError):
        gateway.GatewayConfig(
            bind="127.0.0.1", port=0, tls_certfile=cert, tls_keyfile=key
        ).build_ssl_context()


@needs_openssl
def test_gateway_serves_health_over_https(monkeypatch, tmp_path):
    _enable_gateway(monkeypatch)
    cert, key = _self_signed_pair(tmp_path)
    server = gateway.GatewayServer(
        gateway.GatewayConfig(
            bind="127.0.0.1",
            port=0,
            tls_certfile=cert,
            tls_keyfile=key,
            metrics_enabled=False,
        )
    )
    server.start()
    port = server.address[1]
    try:
        context = ssl._create_unverified_context()
        with urllib.request.urlopen(
            f"https://127.0.0.1:{port}/health", timeout=10, context=context
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert response.status == 200
        assert payload["status"] == "ok"
        assert payload["tls"] is True

        cleartext_error = None
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5)
        except Exception as exc:  # noqa: BLE001 - a TLS listener must refuse cleartext
            cleartext_error = exc
        assert cleartext_error is not None
    finally:
        server.shutdown()
