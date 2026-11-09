"""Replay of payloads recorded from real registry services; see fixtures/live/README.md.

Offline on purpose: CI has no egress, and a test that goes red because a registry reworded its
terms of use is testing nothing. What is asserted here is structure -- which fields the parser
found, and which ones it must not invent -- because that is exactly what the live recordings got
wrong. Set ``REGISTRATA_RUN_LIVE=1`` to additionally exercise the live services at the end.
"""

import json
import os
import pathlib
import socket
import threading

import pytest

from registrata.client import RwhoisClient
from registrata.errors import RwhoisProtocolError
from registrata.experimental import rdap as rdap_module
from registrata.experimental import whois
from registrata.experimental.whois_adapters import (
    WHOIS_PROFILE_LABELS,
    detect_whois_profile,
)

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures" / "live"

# A key that ends in a URI scheme means the colon that split the line belonged to a URL.
_SCHEME_TAILS = ("http", "https", "ftp", "ftps", "mailto", "ldap", "ldaps", "telnet", "file")


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8", errors="replace")


def whois_fields(name: str) -> dict[str, list[str]]:
    return whois.parse_whois_fields(load(name))


def test_pir_output_is_the_verisign_profile_and_that_is_correct():
    """PIR's .org WHOIS reads as the "verisign" profile, and that is not a bug.

    The id names the format family -- ICANN gTLD thin WHOIS -- which Verisign and
    PIR emit field for field, so renaming it to match the operator would make the
    id lie about the thing it describes. Pinned here against the recording, with
    the operator-facing label as the place both names appear.
    """
    fields = whois_fields("whois_example_org_pir.txt")

    assert detect_whois_profile(fields, server="whois.pir.org") == "verisign"
    label = WHOIS_PROFILE_LABELS["verisign"]
    assert "PIR" in label and "Verisign" in label


@pytest.mark.parametrize(
    "fixture",
    ["whois_example_org_pir.txt", "whois_example_com_verisign.txt", "whois_org_iana.txt"],
)
def test_registry_prose_never_becomes_a_field(fixture: str) -> None:
    """Every one of these payloads contains a sentence with a URL in it.

    Splitting on the first colon made a field out of that sentence: Verisign's status-code pointer
    became a key ending in "https" whose value was "//icann.org/epp". Banner and commentary lines
    (">>> Last update of WHOIS database", "% for more information on IANA") were inventing fields
    the same way.
    """
    fields = whois_fields(fixture)

    assert fields, "a registry record with no fields at all means the parser found nothing"
    for key in fields:
        assert not key.endswith(_SCHEME_TAILS), f"URL colon parsed as a field separator: {key!r}"
        assert "://" not in key, f"URL parsed as a field name: {key!r}"
        assert not key.startswith(("%", "#", ">", "!")), f"commentary parsed as a field: {key!r}"


def test_pir_publishes_the_fields_a_domain_record_is_judged_by() -> None:
    """Values here are promises the registry makes, so they are fair to assert on."""
    fields = whois_fields("whois_example_org_pir.txt")

    assert fields["domain name"] == ["example.org"]
    assert fields["registrar"] == ["ICANN"]
    assert fields["registry domain id"] == ["REDACTED"]
    assert fields["dnssec"] == ["signedDelegation"]
    assert len(fields["domain status"]) == 3
    assert len(fields["name server"]) == 2


def test_a_blank_referral_field_is_not_a_referral() -> None:
    """PIR prints ``Registrar WHOIS Server:`` with no value, meaning "nowhere else to ask"."""
    fields = whois_fields("whois_example_org_pir.txt")
    result = whois.WhoisResult(query="example.org", server="whois.pir.org", fields=fields)

    assert "registrar whois server" not in fields
    assert whois.parse_whois_referrals(result.raw) == []
    assert whois.discover_next_whois_server(result, current_server="whois.pir.org") is None


def test_verisign_refers_a_reserved_domain_to_iana_and_says_so() -> None:
    """Live Verisign data really does name whois.iana.org as the registrar service."""
    raw = load("whois_example_com_verisign.txt")
    fields = whois.parse_whois_fields(raw)

    assert fields["domain name"] == ["EXAMPLE.COM"]
    assert fields["registrar"][0].startswith("RESERVED")
    assert whois.parse_whois_referrals(raw) == ["whois.iana.org"]
    assert detect_whois_profile(fields, "whois.verisign-grs.com") == "verisign"


def test_the_iana_root_record_refers_on_to_the_registry_operator() -> None:
    """A TLD query at IANA is the entry point of the chain, not the end of it."""
    raw = load("whois_org_iana.txt")
    fields = whois.parse_whois_fields(raw)

    assert whois.parse_whois_referrals(raw) == ["whois.publicinterestregistry.org"]
    assert detect_whois_profile(fields, "whois.iana.org") in {"ripe", "generic"}


def _rdap_record(fixture: str, url: str):
    return rdap_module.normalize_rdap(json.loads(load(fixture)), headers={}, url=url, status=200)


def test_verisign_rdap_hides_nothing_and_left_nothing_out() -> None:
    record = _rdap_record(
        "rdap_example_com_verisign.json", "https://rdap.verisign.com/com/v1/domain/example.com"
    )

    assert "rdap_level_0" in record.as_dict()["conformance"]
    assert record.truncated is False
    assert record.truncation == []
    assert record.redacted == []
    assert record.incomplete is False
    assert record.notices, "Verisign publishes its terms of service as a notice"


def test_pir_rdap_redacts_a_value_without_the_response_being_truncated() -> None:
    """The distinction live data forced: redaction is disclosure, truncation is loss.

    A modern gTLD record is redacted as a matter of course, so anything that reads "a value is
    hidden" as "the response is incomplete" reports the ordinary case as the exceptional one --
    which is what the CLI did until this payload was replayed against it.
    """
    record = _rdap_record(
        "rdap_example_org_pir.json", "https://rdap.publicinterestregistry.org/rdap/domain/example.org"
    )

    assert [entry["name_type"] for entry in record.redacted] == ["Registry Domain ID"]
    assert record.redacted[0]["method"] == "removal"
    assert record.redacted[0]["pre_path"] == "$.handle"
    assert record.truncated is False
    assert record.truncation == []


def test_cli_reports_redaction_without_warning_about_truncation(monkeypatch, capsys) -> None:
    from registrata.cli import main

    data = json.loads(load("rdap_example_org_pir.json"))
    monkeypatch.setattr(
        rdap_module,
        "lookup_rdap",
        lambda resource, **kwargs: rdap_module.RdapResult(
            url="https://rdap.example/domain/" + resource, status=200, headers={}, data=data
        ),
    )

    assert main(["rdap", "example.org"]) == 0
    captured = capsys.readouterr()

    assert "redacted: Registry Domain ID" in captured.out
    assert "warning" not in captured.err


def test_a_referral_chain_survives_into_the_result(monkeypatch) -> None:
    """Referrals are followed by default, so the route has to be recorded or the last hop looks
    like a wrong answer: this chain ends at a server that answers about the TLD, not the domain."""
    first = whois.WhoisResult(
        query="example.com",
        server="whois.verisign-grs.com",
        fields={"domain name": ["EXAMPLE.COM"]},
        referrals=["whois.iana.org"],
    )
    second = whois.WhoisResult(
        query="example.com", server="whois.iana.org", fields={"domain": ["COM"]}, referrals=[]
    )
    asked: list[str] = []

    def fake_query(text_query, server, **kwargs):
        asked.append(server)
        return first if server == "whois.verisign-grs.com" else second

    monkeypatch.setattr(whois, "whois_query", fake_query)

    # follow_referrals defaults to False in the API and to True in the CLI (`--no-referrals`
    # opts out), so the chain only forms when it is asked for -- or when a user runs the
    # command and never thinks about it, which is how this surfaced against live data.
    result = whois.lookup_whois(
        "example.com", server="whois.verisign-grs.com", follow_referrals=True
    )

    assert asked == ["whois.verisign-grs.com", "whois.iana.org"]
    assert result.hops == ["whois.verisign-grs.com", "whois.iana.org"]
    assert whois.WhoisResult.from_dict(result.as_dict()).hops == result.hops


def _silent_endpoint():
    """A port that accepts and says nothing, which is how a plain WHOIS service looks to us."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    stop = threading.Event()
    held: list[socket.socket] = []

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _peer = listener.accept()
            except OSError:
                break
            held.append(conn)
        for conn in held:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener, thread, stop


def test_an_endpoint_that_never_banners_is_named_as_not_rwhois() -> None:
    """Section 3.1.1 puts the first byte on the server, so silence is an answer of its own."""
    listener, thread, stop = _silent_endpoint()
    port = listener.getsockname()[1]
    try:
        with pytest.raises(RwhoisProtocolError) as excinfo:
            RwhoisClient.connect("127.0.0.1", port, timeout=0.5)
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=3)

    message = str(excinfo.value)
    assert "no banner" in message
    assert "3.1.6" in message
    assert str(port) in message, "the message has to name the endpoint that was silent"


live = pytest.mark.skipif(
    not os.environ.get("REGISTRATA_RUN_LIVE"),
    reason="set REGISTRATA_RUN_LIVE=1 to exercise the real registries",
)


@live
def test_live_whois_for_a_reserved_domain() -> None:
    result = whois.lookup_whois("example.org", server="whois.pir.org", follow_referrals=False)

    assert result.error is None
    assert result.fields["domain name"][0].lower() == "example.org"


@live
def test_live_rdap_bootstrap_finds_the_registry_itself() -> None:
    result = rdap_module.lookup_rdap("example.com")

    assert result.error is None
    assert result.status == 200
    assert result.data["ldhName"].lower() == "example.com"
