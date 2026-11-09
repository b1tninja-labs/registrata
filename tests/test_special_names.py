"""Special-use domain names: a reserved name is answered, never "not found".

The table is checked against the IANA registry that RFC 6761 establishes (read
2026-11-02). Pinning it is not about freezing the set -- the registry takes new
entries -- it is about every row carrying the document that put it there, so a
refresh is a deliberate edit instead of silent drift, and about proving that a
name nobody can register costs no quota and never reads as a miss.
"""

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from registrata import special_names
from registrata.experimental.batch import BatchItem, BatchResult, batch_lookup
from registrata.experimental.lookup import LookupResult, lookup

PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: Non-`.arpa` rows of the IANA Special-Use Domain Names registry.
IANA_TLDS = {
    "alt": "RFC 9476",
    "example": "RFC 6761",
    "invalid": "RFC 6761",
    "local": "RFC 6762",
    "localhost": "RFC 6761",
    "onion": "RFC 7686",
    "test": "RFC 6761",
}


def test_tld_table_matches_the_iana_registry_with_references():
    assert special_names.SPECIAL_USE_TLDS == IANA_TLDS


def test_documentation_names_are_the_rfc_2606_trio():
    assert special_names.RESERVED_DOCUMENT_NAMES == {
        "example.com": "RFC 2606",
        "example.net": "RFC 2606",
        "example.org": "RFC 2606",
    }


@pytest.mark.parametrize(
    "name",
    [
        "example.com",
        "www.example.com",
        "a.b.c.example.org",
        "EXAMPLE.NET",
        "example.com.",
        "  example.com  ",
        "example",
        "test",
        "test.",
        "www.example.test",
        "test.example",
        "anything.invalid",
        "x.localhost",
        "printer.local",
        "service.onion",
        "alt",
    ],
)
def test_special_use_names_are_recognised(name):
    reason = special_names.special_use_reason(name)
    assert reason is not None
    assert "RFC" in reason, "every refusal must name the document that refuses"


@pytest.mark.parametrize(
    "name",
    [
        "example.co",
        "notexample.com",
        "example.computer",
        "mytest.com",
        "snugglepuffz.com",
        "192.0.2.1",
        "2001:db8::1",
    ],
)
def test_queryable_names_are_left_alone(name):
    # "example.co" and "example.computer" sit one character from a reserved name
    # and are perfectly registrable. An address is not a name at all -- reserved
    # IP ranges (TEST-NET) are a separate registry from this one.
    assert special_names.special_use_reason(name) is None


@pytest.mark.parametrize(
    "junk",
    ["", "   ", ".", "..", "a..b", ".example.com", "x." * 130, "ex ample.com"],
)
def test_malformed_input_is_not_a_name_and_raises_nothing(junk):
    assert special_names.special_use_reason(junk) is None


def _exploded(*_args, **_kwargs):
    raise AssertionError("a reserved name must never reach a registry")


@pytest.fixture
def no_registries(monkeypatch):
    # `from registrata.experimental import lookup` yields the *function*: the
    # package re-exports it over the submodule, so grab the module itself.
    lookup_module = importlib.import_module("registrata.experimental.lookup")
    monkeypatch.setattr(lookup_module.rdap, "lookup_rdap", _exploded)
    monkeypatch.setattr(lookup_module.whois, "lookup_whois", _exploded)


def test_lookup_short_circuits_without_touching_a_registry(no_registries):
    result = lookup("www.example.com", sources=["rdap", "whois"])
    assert result.unqueryable and "RFC" in result.unqueryable
    assert result.kind == "domain"
    # Not an error, not a miss: nothing was asked, so nothing failed.
    assert result.ok is False
    assert result.errors == []
    assert result.records == []


def test_unqueryable_is_part_of_the_stable_json_shape(no_registries):
    result = lookup("example.org", sources=["rdap"])
    payload = result.as_dict()
    assert payload["unqueryable"] == result.unqueryable
    assert payload["errors"] == []
    assert payload["ok"] is False


def test_only_domain_shaped_values_are_short_circuited():
    # A bare "test" classifies as a keyword, which a server may legitimately
    # answer, so it must be asked rather than refused.
    result = lookup("test", sources=["rwhois"])
    assert result.unqueryable is None
    assert result.errors, "the source really was attempted (and has no server)"


def test_skip_reserved_false_asks_about_a_reserved_name():
    result = lookup("example.com", sources=["rwhois"], skip_reserved=False)
    assert result.unqueryable is None
    assert result.errors, "opt-out means the query is attempted"


_RESERVED = "example.com is reserved for documentation (RFC 2606)"


def _reserved(resource):
    return LookupResult(
        resource=resource, kind="domain", sources=["rdap"], unqueryable=_RESERVED
    )


def _answered(resource):
    return LookupResult(
        resource=resource, kind="domain", sources=["rdap"], results={"rdap": object()}
    )


def test_reserved_name_has_its_own_batch_status():
    item = BatchItem(resource="example.com", index=0, result=_reserved("example.com"))
    assert item.status == "reserved"
    assert item.as_dict()["unqueryable"] == _RESERVED


def test_counts_distinguish_reserved_from_error_and_empty():
    run = BatchResult(
        items=[
            BatchItem(resource="a", index=0, result=_reserved("a")),
            BatchItem(resource="b", index=1, error="timeout"),
            BatchItem(resource="c", index=2),
        ]
    )
    counts = run.counts()
    assert counts["reserved"] == 1
    assert counts["error"] == 1
    assert counts["empty"] == 1


def test_fail_fast_does_not_abandon_a_sweep_over_a_name_that_cannot_exist():
    seen = []

    def fake(resource, **_kwargs):
        seen.append(resource)
        return _reserved(resource) if resource == "example.com" else _answered(resource)

    run = batch_lookup(
        ["a.com", "example.com", "b.com"],
        concurrency=1,
        lookup_fn=fake,
        fail_fast=True,
    )
    assert seen == ["a.com", "example.com", "b.com"]
    assert run.stopped_reason is None
    assert run.counts()["reserved"] == 1


def test_batch_forwards_the_opt_out_to_every_lookup():
    captured = []

    def fake(resource, **kwargs):
        captured.append(kwargs.get("skip_reserved"))
        return _answered(resource)

    batch_lookup(["a.com"], concurrency=1, lookup_fn=fake)
    batch_lookup(["a.com"], concurrency=1, lookup_fn=fake, skip_reserved=False)
    assert captured == [True, False]


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    src = str(PROJECT_ROOT / "src")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = src if not existing else src + os.pathsep + existing
    return subprocess.run(
        [sys.executable, "-m", "registrata.cli", *args],
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
    )


def test_cli_reports_a_reserved_name_without_failing():
    proc = _run_cli("lookup", "example.com", "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["unqueryable"] == _RESERVED
    assert payload["errors"] == []
    assert "not queryable" in proc.stderr
