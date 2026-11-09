"""``validate_record`` must enforce what ``REGISTRATION_RECORD_SCHEMA`` publishes.

The schema declares item schemas for links, notices and redacted members, and enums for
``context`` and ``method``, but validation used to consult ``RECORD_TYPES`` -- a flat top-level
mapping -- so all of that was descriptive only: a bare string inside ``notices`` validated
cleanly. Since ``registrata doctor`` feeds this function into its health verdict, an unchecked
schema meant a malformed record reported healthy.
"""

from __future__ import annotations

from registrata.model import from_rdap
from registrata.record_schema import (
    RECORD_TYPES,
    RECORD_SCHEMA_VERSION,
    REGISTRATION_RECORD_SCHEMA,
    record_to_schema,
    validate_record,
)

RDAP_PAYLOAD = {
    "objectClassName": "domain",
    "handle": "2138514_DOMAIN_COM-EXMP",
    "ldhName": "EXAMPLE.COM",
    "lang": "en",
    "status": ["active", "client transfer prohibited"],
    "rdapConformance": ["rdap_level_4", "redacted"],
    "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
    "links": [
        {
            "value": "https://rdap.example.com/domain/example.com",
            "rel": "self",
            "href": "https://rdap.example.com/domain/example.com",
        }
    ],
    "notices": [
        {
            "title": "Terms of Use",
            "description": ["Data is provided as is."],
            "links": [
                {
                    "value": "https://rdap.example.com/",
                    "rel": "related",
                    "href": "https://rdap.example.com/terms",
                }
            ],
        }
    ],
    "entities": [{"handle": "1", "roles": ["registrant"], "vcardArray": ["vcard", []]}],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "NS2.EXAMPLE.COM"}],
    "secureDNS": {"zoneSigned": True, "delegationSigned": False},
    "redacted": [
        {
            "name": {"type": "Registrant Name"},
            "method": "removal",
            "pathLang": "jsonpath",
            "reason": {"description": "Server policy"},
        }
    ],
}


def payload(**overrides):
    data = from_rdap(RDAP_PAYLOAD).as_dict()
    data.update(overrides)
    return data


def test_a_normalized_rdap_record_satisfies_its_own_schema() -> None:
    """The over-strictness guard: enforcing the schema is worthless if real output fails it."""
    assert validate_record(from_rdap(RDAP_PAYLOAD).as_dict()) == []


def test_array_items_are_checked_not_just_the_array() -> None:
    errors = validate_record(payload(statuses=["active", 42]))

    assert any("statuses[1]" in error for error in errors), errors


def test_a_bare_string_in_notices_is_refused() -> None:
    """The item schema says an entry is an object; a string used to pass."""
    errors = validate_record(payload(notices=["Terms of use: none"]))

    assert any("notices[0]" in error for error in errors), errors


def test_nested_link_items_are_checked() -> None:
    errors = validate_record(
        payload(notices=[{"context": "notice", "links": ["https://x/terms"]}])
    )

    assert any("notices[0].links[0]" in error for error in errors), errors


def test_enum_members_are_enforced() -> None:
    """RFC 9537 defines four redaction methods; the normalizer maps anything else to a default
    and keeps the original in ``unknown_method``, so a stray value here means a bug upstream."""
    errors = validate_record(
        payload(redacted=[{"context": "redacted", "method": "teleportation"}])
    )

    assert any("method" in error for error in errors), errors


def test_a_boolean_is_not_a_string() -> None:
    """bool is an int subclass in Python, and the schema walker guards for it explicitly.

    Nothing in this record type is declared as a number, so the guard is not reachable from the
    public shape today; it is pinned here so it stays correct if a numeric member is added.
    """
    assert validate_record(payload(identifier=True))
    assert validate_record(payload(source=["rdap"]))


def test_the_wrapper_returned_by_record_to_schema_is_not_a_record() -> None:
    """record_to_schema wraps; validate_record expects the payload, which is what the CLI unwraps."""
    wrapped = record_to_schema(from_rdap(RDAP_PAYLOAD))

    assert validate_record(wrapped["record"]) == []
    assert "missing required field: source" in validate_record(wrapped)


def test_record_types_agree_with_the_schema_document() -> None:
    """Two representations of the same fact drift; this is what let the item schemas go unused.

    RECORD_TYPES is kept because it is importable and handy for callers that only want the
    outermost shape, but the schema document is authoritative and the validator now reads that.
    """
    expected = {
        "string": str,
        "null": type(None),
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    for key, schema in REGISTRATION_RECORD_SCHEMA["properties"].items():
        names = schema["type"]
        names = [names] if isinstance(names, str) else names
        allowed = {expected[name] for name in names if name in expected}
        assert set(RECORD_TYPES[key]) <= allowed or allowed <= set(RECORD_TYPES[key]), (
            f"{key}: RECORD_TYPES {RECORD_TYPES[key]} disagrees with schema {names}"
        )


def test_the_schema_version_is_reported_in_the_wrapper() -> None:
    wrapped = record_to_schema(from_rdap(RDAP_PAYLOAD))
    assert wrapped["schema_version"] == RECORD_SCHEMA_VERSION
