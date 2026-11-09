import pytest

from registrata.experimental import rdap, whois
from registrata.experimental.lookup import LookupResult, lookup


#: A queryable stand-in. `example.com` is refused before any source is asked,
#: because RFC 6761 reserves it for documentation -- see test_special_names.py.
QUERYABLE = "widgits.net"


@pytest.fixture(autouse=True)
def fake_sources(monkeypatch):
    monkeypatch.setattr(
        rdap,
        "lookup_rdap",
        lambda resource, **kwargs: rdap.RdapResult(
            url="https://rdap.example/domain/" + resource,
            status=200,
            data={
                "objectClassName": "domain",
                "ldhName": resource,
                "status": ["active"],
            },
        ),
    )

    monkeypatch.setattr(
        whois,
        "lookup_whois",
        lambda resource, **kwargs: whois.WhoisResult(
            query=resource,
            server="whois.example",
            raw="Domain Name: EXAMPLE.COM",
            fields={"domain name": ["EXAMPLE.COM"]},
        ),
    )


def test_lookup_rdap_and_whois_normalizes_rdap():
    result = lookup(QUERYABLE, sources=["rdap", "whois"])
    assert isinstance(result, LookupResult)
    assert result.ok
    assert result.normalized["kind"] == "domain"
    assert result.results["whois"].fields["domain name"] == ["EXAMPLE.COM"]


def test_lookup_rwhois_source_records():
    from registrata import RwhoisServer
    from registrata.backends.memory import MemoryBackend

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
    host, port = app.start()
    try:
        result = lookup(
            "example.com",
            sources=["rwhois"],
            server=host,
            port=port,
            rwhois_class="domain",
        )
    finally:
        app.shutdown()
    assert result.ok
    assert result.normalized["source"] == "rwhois"
    assert result.records[0].identifier == "dom-1.example.com"


def test_lookup_breaker_open_reports_errors(monkeypatch):
    from registrata.circuitbreaker import CircuitBreakerRegistry

    registry = CircuitBreakerRegistry(default_failure_threshold=1)
    registry.record_failure("rdap:bootstrap", reason="offline")
    result = lookup(QUERYABLE, sources=["rdap"], breaker=registry)
    assert not result.ok
    assert result.errors[0].source == "rdap"
    assert "circuit open" in result.errors[0].message
    assert result.provenance()["circuit_breakers"]["rdap:bootstrap"]["state"] == "open"


@pytest.fixture()
def rwhois_zone():
    """A live server holding one domain, so the registry can answer "here it is" and "not here"."""
    from registrata import RwhoisServer
    from registrata.backends.memory import MemoryBackend

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
    host, port = app.start()
    try:
        yield host, port
    finally:
        app.shutdown()


def test_an_authoritative_no_objects_answer_is_an_answer_not_an_error(rwhois_zone):
    """``%error 230 No objects found`` is a working registry saying "not here".

    It used to be recorded as a source error, which made every negative answer in a sweep
    indistinguishable from an outage -- and contradicted the circuit breaker, which counts 230 as
    the endpoint working because it sits below 400.
    """
    host, port = rwhois_zone
    result = lookup(
        "nosuch.example.com",
        sources=["rwhois"],
        server=host,
        port=port,
        rwhois_class="domain",
    )

    assert result.ok, "an empty answer is still an answer"
    assert result.errors == []
    assert result.records == []
    assert result.results["rwhois"].error_code == 230


def test_an_error_answer_from_a_server_is_not_counted_as_an_answer(monkeypatch):
    """A 3xx/4xx reply is a failure; a 2xx reply is an answer (see the 230 test above).

    Scripted rather than provoked from the real server, because this library only emits
    INVALID_CLASS for the ``-class`` and ``-schema`` directives and answers an unknown-class query
    with 230 -- whether it should answer 341 there is recorded as an open question in ROADMAP.md,
    and a test must not settle it by assumption.
    """
    from registrata.experimental.lookup import RwhoisClient

    class _Answer:
        error_code = 402
        error_text = "Syntax error"

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def query(self, *args, **kwargs):
            return _Answer()

    # Patched on the class, because `registrata.experimental.lookup` resolves to the re-exported
    # function of that name rather than to the module.
    monkeypatch.setattr(
        RwhoisClient, "connect", staticmethod(lambda *a, **k: _Session())
    )

    result = lookup(
        "example.com",
        sources=["rwhois"],
        server="rwhois.example",
        port=4321,
        rwhois_class="domain",
    )

    assert not result.ok
    assert result.results == {}
    assert result.errors[0].message == "402 Syntax error"


def test_a_failed_whois_source_does_not_count_as_an_answer(monkeypatch):
    """No source may both fail and be stored, or ``ok`` stops meaning anything.

    ``ok`` is ``bool(results)``, and the whois branch stored the item even after recording its
    error -- so a lookup whose only source could not connect reported success with nothing behind
    it. The rdap branch had it right all along; these two disagreed with it.
    """
    monkeypatch.setattr(
        whois,
        "lookup_whois",
        lambda resource, **kwargs: whois.WhoisResult(
            query=resource, server="whois.example", error="connection refused"
        ),
    )

    result = lookup(QUERYABLE, sources=["whois"])

    assert not result.ok
    assert result.results == {}
    assert [item.source for item in result.errors] == ["whois"]
    # Guards against the vacuous version of this test: a double that does not satisfy its own
    # constructor raises a TypeError, which lookup() reports as a source error just the same, and
    # every assertion above then passes without the behaviour under test ever running.
    assert result.errors[0].message == "connection refused"
