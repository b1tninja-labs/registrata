"""Comparison and diffing for normalized registration records.

The goal is not to prove one source is correct. Registration-data sources often
disagree because of privacy redaction, cache age, or registry policy. This module
makes disagreement explicit and stable enough for operator comparison.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

from .model import RegistrationRecord

DEFAULT_COMPARE_FIELDS = (
    "identifier",
    "statuses",
    "nameservers",
    "registrar",
    "events",
    "contacts",
    "networks",
    "dnssec",
)

_COMPARISON_FIELDS = set(DEFAULT_COMPARE_FIELDS)


def _normalized_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower().rstrip(".")
    return text or None


def _normalized_set(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        items = [value]
    else:
        items = value
    return sorted({x for x in (_normalized_string(item) for item in items) if x})


def _normalized_phone(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower().startswith("tel:"):
        text = text[4:]
    digits = re.sub(r"\D", "", text)
    return digits or None


def _normalized_contact(contact: dict[str, Any]) -> dict[str, Any]:
    return {
        "roles": _normalized_set(contact.get("roles")),
        "emails": _normalized_set(contact.get("emails") or contact.get("email")),
        "phones": _normalized_set(
            _normalized_phone(x)
            for x in (contact.get("phones") or contact.get("phone") or [])
        ),
        "handle": _normalized_string(contact.get("handle")),
        "name": _normalized_string(contact.get("name")),
        "organization": _normalized_string(contact.get("organization")),
    }


def _normalized_contacts(value: Any) -> list[dict[str, Any]]:
    contacts = [_normalized_contact(c) for c in (value or []) if isinstance(c, dict)]
    return sorted(
        [
            c
            for c in contacts
            if any(
                c.get(key)
                for key in (
                    "roles",
                    "emails",
                    "phones",
                    "handle",
                    "name",
                    "organization",
                )
            )
        ],
        key=lambda item: (
            item.get("roles", []),
            item.get("emails", []),
            item.get("handle") or "",
        ),
    )


def _normalized_event(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        return {"action": _normalized_string(event)}
    action = _normalized_string(event.get("action") or event.get("eventAction"))
    date = _normalized_string(
        event.get("date") or event.get("eventDate") or event.get("raw_date")
    )
    if date and date.endswith("+00:00"):
        date = date[:-6] + "z"
    return {"action": action, "date": date}


def _normalized_events(value: Any) -> list[dict[str, Any]]:
    events = [_normalized_event(x) for x in (value or [])]
    return sorted(
        [e for e in events if e.get("action") or e.get("date")],
        key=lambda item: (item.get("action") or "", item.get("date") or ""),
    )


def _normalized_registrar(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"name": _normalized_string(value)}
    return {
        "name": _normalized_string(value.get("name")),
        "iana_id": _normalized_string(value.get("iana_id")),
        "url": _normalized_string(value.get("url")),
        "whois_server": _normalized_string(
            value.get("whois_server") or value.get("whois-server")
        ),
    }


def _normalized_network(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"name": _normalized_string(value)}
    return {
        "name": _normalized_string(value.get("name")),
        "start": _normalized_string(
            value.get("start") or value.get("start_address") or value.get("ip")
        ),
        "end": _normalized_string(value.get("end") or value.get("end_address")),
        "handle": _normalized_string(value.get("handle")),
    }


def _normalized_dnssec(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return {"raw": _normalized_string(value)}
    signed = value.get("signed")
    if signed is None:
        signed = value.get("delegation_signed") or value.get("delegationSigned")
    if signed is None:
        raw = _normalized_string(value.get("raw"))
        if raw:
            signed = any(word in raw for word in ("signed", "delegated"))
    return {
        "signed": bool(signed) if signed is not None else None,
        "max_sig_life": value.get("maxSigLife") or value.get("max_sig_life"),
        "raw": _normalized_string(value.get("raw")),
    }


def _normalized_field(field_name: str, value: Any) -> Any:
    if field_name == "identifier":
        return _normalized_string(value)
    if field_name in {"statuses", "nameservers"}:
        return _normalized_set(value)
    if field_name == "registrar":
        return _normalized_registrar(value)
    if field_name == "events":
        return _normalized_events(value)
    if field_name == "contacts":
        return _normalized_contacts(value)
    if field_name == "networks":
        return [_normalized_network(item) for item in (value or [])]
    if field_name == "dnssec":
        return _normalized_dnssec(value)
    return value


def compare_records(
    records: list[RegistrationRecord],
    *,
    fields: tuple[str, ...] | list[str] = DEFAULT_COMPARE_FIELDS,
) -> dict[str, Any]:
    """Compare records from different sources and return a stable JSON report.

    ``comparable`` states whether a comparison actually happened, and ``score`` is ``None`` when
    it did not. Without that, one record, no records, and a mistyped ``--fields`` list all produce
    the same output as a healthy cross-check -- a perfect score and no differences -- which is the
    most misleading thing this module can emit: one record is exactly what a lookup returns when
    the other source failed, so the report would assert agreement in the one case where the
    operator needs to see that nothing was cross-checked.
    """
    named_fields = [f for f in fields if f in _COMPARISON_FIELDS]
    labels: list[str] = []
    counts: dict[str, int] = {}
    per_source: dict[str, dict[str, Any]] = {}
    for record in records:
        base = record.source or "unknown"
        counts[base] = counts.get(base, 0) + 1
        label = base if counts[base] == 1 else f"{base}#{counts[base]}"
        labels.append(label)
        payload = record.as_dict()
        per_source[label] = {
            field_name: _normalized_field(field_name, payload.get(field_name))
            for field_name in named_fields
        }

    reason: str | None = None
    if len(labels) < 2:
        reason = "fewer than two sources returned records"
    elif not named_fields:
        reason = "no recognised fields to compare"
    if reason is not None:
        return {
            "version": 1,
            "kind": records[0].kind if records else None,
            "sources": labels,
            "fields": named_fields,
            "matches": [],
            "differences": {},
            "missing_or_empty": {},
            "score": None,
            "comparable": False,
            "reason": reason,
        }

    differences: dict[str, dict[str, Any]] = {}
    missing_or_empty: dict[str, list[str]] = {}
    matches: list[str] = []
    for field_name in named_fields:
        values = {label: per_source[label][field_name] for label in labels}
        normalized_values = list(values.values())
        unique: list[Any] = []
        for value in normalized_values:
            if value not in unique:
                unique.append(value)
        if len(unique) <= 1:
            matches.append(field_name)
        else:
            differences[field_name] = values

        # Emptiness is reported whether or not the sources agree about it. Two sources that both
        # say nothing about nameservers do agree, and "matches" is honest as far as it goes, but
        # the absence is the fact an operator is looking for -- and the report advertises
        # missing/empty fields as one of its outputs.
        if any(not value for value in normalized_values):
            missing_or_empty[field_name] = sorted(
                label for label, value in values.items() if not value
            )

    return {
        "version": 1,
        "kind": records[0].kind if records else None,
        "sources": labels,
        "fields": named_fields,
        "matches": matches,
        "differences": differences,
        "missing_or_empty": missing_or_empty,
        "score": round(len(matches) / len(named_fields), 3),
        "comparable": True,
        "reason": None,
    }


@dataclass
class CompareReport:
    resource: str
    kind: str | None
    sources: list[str]
    report: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.sources)

    def as_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "kind": self.kind,
            "sources": self.sources,
            "ok": self.ok,
            "report": self.report,
        }


def compare_lookup_result(
    result: Any, *, fields: tuple[str, ...] | list[str] = DEFAULT_COMPARE_FIELDS
) -> CompareReport:
    records = getattr(result, "records", [])
    report = compare_records(records, fields=fields)
    return CompareReport(
        resource=getattr(result, "resource", ""),
        kind=getattr(result, "kind", None),
        sources=[record.source for record in records],
        report=report,
    )


__all__ = [
    "DEFAULT_COMPARE_FIELDS",
    "CompareReport",
    "compare_lookup_result",
    "compare_records",
]
