import pathlib

from registrata.diagnostics import (
    doctor_report,
    rdap_bootstrap_cache_status,
    trace_report,
)
from registrata.experimental.lookup import LookupResult
from registrata.model import RegistrationRecord


def test_trace_report_includes_source_status_and_provenance():
    result = LookupResult(
        resource="example.com",
        kind="domain",
        sources=["rdap", "whois"],
        records=[
            RegistrationRecord(source="rdap", kind="domain", identifier="example.com")
        ],
    )
    report = trace_report(result)
    assert report["resource"] == "example.com"
    assert report["sources"] == ["rdap", "whois"]
    assert report["provenance"]["resource"] == "example.com"


def test_doctor_report_without_lookup_reports_classification_and_suggestions():
    report = doctor_report("8.8.8.8")
    assert report["healthy"] is True
    assert report["lookup_performed"] is False
    assert report["kind"] == "ipv4"
    assert any("trace" in item for item in report["suggestions"])


def test_rdap_bootstrap_cache_status_reports_invalid_cache(tmp_path: pathlib.Path):
    path = tmp_path / "rdap_bootstrap_domain.json"
    path.write_text("{", encoding="utf-8")
    status = rdap_bootstrap_cache_status(tmp_path)
    domain = next(item for item in status["files"] if item["kind"] == "domain")
    assert domain["exists"] is True
    assert domain["valid"] is False
    assert "error" in domain
