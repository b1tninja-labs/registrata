"""Operator diagnostics for unified registration-data lookups."""

from __future__ import annotations

import json
import pathlib
import time
from typing import Any

from ._flags import status as feature_status
from .circuitbreaker import CircuitBreakerRegistry
from .comparison import DEFAULT_COMPARE_FIELDS, compare_records
from .record_schema import validate_record


def _header_value(headers: dict[str, str] | None, name: str) -> str | None:
    if not headers:
        return None
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    return lowered.get(name.lower())


def trace_report(result: Any) -> dict[str, Any]:
    """Build a stable trace report from a unified LookupResult."""
    provenance = result.provenance() if hasattr(result, "provenance") else {}
    source_status: dict[str, Any] = {}
    for source, item in getattr(result, "results", {}).items():
        if source == "rdap":
            source_status[source] = {
                "ok": bool(getattr(item, "ok", False)),
                "url": getattr(item, "url", None),
                "status": getattr(item, "status", None),
                "cache_mode": getattr(item, "cache_mode", None),
                "stale": getattr(item, "stale", False),
                "etag": _header_value(getattr(item, "headers", {}), "etag"),
                "last_modified": _header_value(
                    getattr(item, "headers", {}), "last-modified"
                ),
                "error": getattr(item, "error", None),
                "record_count": 1 if getattr(item, "data", None) else 0,
            }
        elif source == "whois":
            source_status[source] = {
                "ok": bool(getattr(item, "error", None) is None),
                "server": getattr(item, "server", None),
                "port": getattr(item, "port", None),
                "error": getattr(item, "error", None),
                "fields": len(getattr(item, "fields", {}) or {}),
                "referrals": list(getattr(item, "referrals", []) or []),
            }
        elif source == "rwhois":
            objects = list(getattr(item, "objects", []) or [])
            source_status[source] = {
                "ok": bool(getattr(item, "ok", False)),
                "server": getattr(item, "server", None),
                "port": getattr(item, "port", None),
                "query": getattr(item, "query", None),
                "objects": len(objects),
                "error_code": getattr(item, "error_code", None),
                "error_text": getattr(item, "error_text", None),
                "referrals": [ref.url for ref in getattr(item, "referrals", [])],
            }
        else:
            source_status[source] = {"ok": True, "repr": repr(item)}

    return {
        "version": 1,
        "resource": getattr(result, "resource", None),
        "kind": getattr(result, "kind", None),
        "sources": list(getattr(result, "sources", [])),
        "ok": bool(getattr(result, "ok", False)),
        "errors": [
            {"source": err.source, "message": err.message}
            for err in getattr(result, "errors", [])
        ],
        "provenance": provenance,
        "source_status": source_status,
        "circuit_breakers": provenance.get("circuit_breakers", {}),
    }


def _feature_check() -> list[dict[str, Any]]:
    return [
        {
            "feature": item.feature.value,
            "enabled": item.enabled,
            "default": item.default,
            "env_name": item.env_name,
        }
        for item in feature_status()
    ]


def _classify_resource(resource: str) -> str:
    from .experimental.whois import classify_resource

    return classify_resource(resource)


def rdap_bootstrap_cache_status(cache_dir: str | pathlib.Path | None) -> dict[str, Any]:
    if not cache_dir:
        return {"cache_dir": None, "files": []}

    try:
        from .experimental.rdap import BOOTSTRAP_URLS
    except Exception:
        BOOTSTRAP_URLS = {
            "domain": "https://data.iana.org/rdap/dns.json",
            "ipv4": "https://data.iana.org/rdap/ipv4.json",
            "ipv6": "https://data.iana.org/rdap/ipv6.json",
            "autnum": "https://data.iana.org/rdap/as-numbers.json",
        }

    root = pathlib.Path(cache_dir)
    files: list[dict[str, Any]] = []
    for kind in BOOTSTRAP_URLS:
        path = root / f"rdap_bootstrap_{kind}.json"
        info: dict[str, Any] = {
            "kind": kind,
            "path": str(path),
            "exists": path.exists(),
        }
        if info["exists"]:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                cached_at = float(payload.get("_cached_at") or 0)
                info.update(
                    {
                        "valid": isinstance(payload, dict) and "services" in payload,
                        "age_seconds": max(0.0, time.time() - cached_at)
                        if cached_at
                        else None,
                        "etag": bool(payload.get("_etag")),
                        "last_modified": bool(payload.get("_last_modified")),
                    }
                )
            except Exception as exc:
                info.update({"valid": False, "error": str(exc)})
        files.append(info)
    return {"cache_dir": str(root), "files": files}


def doctor_report(
    resource: str,
    *,
    result: Any = None,
    fields: tuple[str, ...] | list[str] = DEFAULT_COMPARE_FIELDS,
    cache_dir: str | pathlib.Path | None = None,
    breaker: CircuitBreakerRegistry | None = None,
) -> dict[str, Any]:
    classification = _classify_resource(resource)
    features = _feature_check()

    records = list(getattr(result, "records", []) or [])
    invalid_records = []
    completeness: list[dict[str, Any]] = []
    for record in records:
        payload = record.as_dict()
        errors = validate_record(payload)
        if errors:
            invalid_records.append({"source": record.source, "errors": errors})
        truncation = payload.get("truncation") or []
        redacted = payload.get("redacted") or []
        subsetting = payload.get("subsetting") or None
        conformance = list(payload.get("conformance") or [])
        if truncation or redacted or subsetting or conformance:
            # RDAP servers mark deliberately partial data in the body: typed
            # truncation notices/remarks (RFC 9083 section 9), redacted fields
            # (RFC 9537), and field sets (RFC 8982). Surface that, because a
            # partial answer otherwise looks like the whole truth.
            completeness.append(
                {
                    "source": record.source,
                    "incomplete": bool(truncation or redacted),
                    "truncated": bool(payload.get("truncated")),
                    "truncation": [
                        {
                            "scope": entry.get("scope"),
                            "type": entry.get("type"),
                            "truncation": entry.get("truncation"),
                        }
                        for entry in truncation
                    ],
                    "redacted_count": len(redacted),
                    "field_set": subsetting.get("current_field_set")
                    if subsetting
                    else None,
                    "conformance": conformance,
                    "lang": payload.get("lang"),
                }
            )

    comparison = {}
    if len(records) >= 2:
        comparison = compare_records(records, fields=fields)

    provenance = result.provenance() if hasattr(result, "provenance") else {}
    circuits = (
        provenance.get("circuit_breakers")
        if provenance
        else (breaker.snapshot() if breaker is not None else {})
    )
    errors = [
        {"source": err.source, "message": err.message}
        for err in getattr(result, "errors", [])
    ]
    bootstrap = rdap_bootstrap_cache_status(cache_dir)
    looked_up = result is not None

    checks = [
        {"name": "features", "ok": True, "items": features},
        {"name": "classification", "ok": bool(classification), "kind": classification},
        {
            "name": "lookup",
            "ok": bool(getattr(result, "ok", False)) if looked_up else None,
            "performed": looked_up,
        },
        {
            "name": "records",
            "ok": bool(records) if looked_up else None,
            "count": len(records),
            "invalid": invalid_records,
            "completeness": completeness,
        },
        {
            "name": "comparison",
            "ok": bool(comparison) if comparison else None,
            "report": comparison,
        },
        {"name": "bootstrap_cache", "ok": True, **bootstrap},
        {"name": "circuit_breakers", "ok": True, "items": circuits or {}},
    ]

    suggestions: list[str] = []
    if looked_up and not getattr(result, "ok", False):
        suggestions.append(f"rwhois whois {resource} --json")
        suggestions.append(
            f"rwhois domain {resource} --sources rdap,whois --follow-referrals --json"
        )
    if looked_up and invalid_records:
        suggestions.append(f"rwhois record-schema {resource} --json")
    incomplete_records = [item for item in completeness if item["incomplete"]]
    if incomplete_records:
        # The notices and remarks carried by the response explain what was
        # withheld, which is worth showing before anyone diffs the records.
        suggestions.append(f"rwhois rdap {resource} --json")
    if comparison and comparison.get("differences"):
        suggestions.append(
            f"rwhois compare {resource} --fields {','.join(comparison.get('fields', []))} --json"
        )
    if classification in {"ipv4", "ipv6", "cidr", "autnum"} and "whois" in getattr(
        result, "sources", []
    ):
        suggestions.append(
            f"rwhois {classification} {resource} --whois-server <registry-server> --json"
        )
    if not looked_up:
        suggestions.append(f"rwhois trace {resource} --json")
        suggestions.append(f"rwhois lookup {resource} --json")

    healthy = (
        not looked_up or bool(getattr(result, "ok", False))
    ) and not invalid_records

    return {
        "version": 1,
        "resource": resource,
        "kind": classification,
        "healthy": healthy,
        "lookup_performed": looked_up,
        "sources": list(getattr(result, "sources", []) or []),
        "errors": errors,
        "checks": checks,
        "provenance": provenance,
        "circuit_breakers": circuits or {},
        "suggestions": suggestions,
    }


__all__ = [
    "doctor_report",
    "rdap_bootstrap_cache_status",
    "trace_report",
]
