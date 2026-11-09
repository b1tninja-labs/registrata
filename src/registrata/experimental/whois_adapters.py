"""Registry-specific helpers for classic WHOIS normalization."""

from __future__ import annotations

from typing import Any

from ..model import RegistrationRecord, from_whois_fields


def _first(values: Any) -> str | None:
    for value in values or []:
        text = str(value).strip()
        if text:
            return text
    return None


def _contact(roles: list[str], key_values: dict[str, Any]) -> dict[str, Any] | None:
    contact: dict[str, Any] = {"roles": roles}
    name = _first(
        key_values.get("name")
        or key_values.get("fullname")
        or key_values.get("person")
        or key_values.get("orgname")
    )
    organization = _first(
        key_values.get("organization")
        or key_values.get("orgname")
        or key_values.get("org-name")
    )
    emails = [
        x
        for x in (
            _first(key_values.get("email")),
            key_values.get("emails")
            if isinstance(key_values.get("emails"), list)
            else None,
        )
        if x
    ]
    phones = [
        x
        for x in (
            _first(key_values.get("phone")),
            key_values.get("phones")
            if isinstance(key_values.get("phones"), list)
            else None,
        )
        if x
    ]
    handle = _first(
        key_values.get("handle") or key_values.get("id") or key_values.get("orgid")
    )
    if name:
        contact["name"] = name
    if organization:
        contact["organization"] = organization
    if handle:
        contact["handle"] = handle
    if emails:
        contact["emails"] = emails
    if phones:
        contact["phones"] = phones
    return contact if len(contact) > 1 else None


#: Human-facing names for the ids `detect_whois_profile` returns. The ids name a
#: *format family*, and one family is shared by two operators, so the label is
#: what belongs in a report; the id is what belongs in a switch.
WHOIS_PROFILE_LABELS: dict[str, str] = {
    "verisign": "ICANN gTLD thin WHOIS (Verisign .com/.net, PIR .org)",
    "arin": "ARIN network/object WHOIS format",
    "ripe": "RIPE NCC inetnum/organisation WHOIS format",
    "generic": "unrecognised -- read as generic key/value fields",
}


def detect_whois_profile(
    fields: dict[str, list[str]], server: str | None = None
) -> str:
    """Return the format family that produced these fields, not who sent them.

    "verisign" is the ICANN gTLD thin-WHOIS format. PIR's .org service emits the
    same field names with the same referral shape, so a .org response is reported
    as "verisign": that is a statement about the *format being read*, not about
    which registry answered. Both operators are named in WHOIS_PROFILE_LABELS,
    which is what should be shown to a person.
    """
    lowered = {k.lower().strip(): v for k, v in fields.items()}
    server_l = (server or "").lower()
    if (
        "arin.net" in server_l
        or "netname" in lowered
        or "networkname" in lowered
        or "orgid" in lowered
    ):
        return "arin"
    if "ripe.net" in server_l or "inetnum" in lowered or "organisation" in lowered:
        return "ripe"
    if (
        "verisign" in server_l
        or "domain name" in lowered
        or "registrar whois server" in lowered
    ):
        return "verisign"
    return "generic"


def normalize_whois_fields(
    fields: dict[str, list[str]],
    *,
    resource: str | None = None,
    kind: str | None = None,
    server: str | None = None,
) -> RegistrationRecord:
    record = from_whois_fields(fields, resource=resource, kind=kind, source="whois")
    profile = detect_whois_profile(fields, server)
    lowered = {k.lower().strip(): v for k, v in fields.items()}
    record.raw = dict(record.raw or {})
    if isinstance(record.raw, dict):
        record.raw["_profile"] = [profile]

    if profile == "arin":
        record.kind = record.kind or "network"
        record.identifier = (
            _first(lowered.get("networkname"))
            or _first(lowered.get("netname"))
            or record.identifier
        )
        record.port43 = record.port43 or "whois.arin.net"
        start = _first(lowered.get("startrange")) or _first(lowered.get("startrange"))
        end = _first(lowered.get("endrange")) or _first(lowered.get("limit"))
        name = _first(lowered.get("networkname")) or _first(lowered.get("netname"))
        if start or end or name:
            record.networks = [{"name": name, "start": start, "end": end}]
        for role, prefix in (
            ("abuse", "orgabuse"),
            ("technical", "orgtech"),
            ("administrative", "orgadmin"),
            ("registrant", "org"),
        ):
            contact = _contact(
                [role],
                {
                    "name": lowered.get(f"{prefix}name")
                    or lowered.get(f"{prefix}-name"),
                    "organization": lowered.get("orgname")
                    or lowered.get("organization"),
                    "email": lowered.get(f"{prefix}email")
                    or lowered.get(f"{prefix}-email"),
                    "phone": lowered.get(f"{prefix}phone")
                    or lowered.get(f"{prefix}-phone"),
                    "handle": lowered.get("orgid") if prefix == "org" else None,
                },
            )
            if contact:
                record.contacts.append(contact)
    elif profile == "ripe":
        record.kind = record.kind or "network"
        record.identifier = (
            _first(lowered.get("inetnum"))
            or _first(lowered.get("organisation"))
            or record.identifier
        )
        record.port43 = record.port43 or "whois.ripe.net"
        start = _first(lowered.get("inetnum"))
        if start:
            record.networks = [{"name": start}]
        for role, keys in (
            ("registrant", ["org"]),
            ("technical", ["tech-c"]),
            ("administrative", ["admin-c"]),
            ("abuse", ["abuse-c"]),
        ):
            contact = _contact(
                [role], {"handle": lowered.get(keys[0]), "name": lowered.get("org")}
            )
            if contact:
                record.contacts.append(contact)

    return record


__all__ = [
    "WHOIS_PROFILE_LABELS",
    "detect_whois_profile",
    "normalize_whois_fields",
]
