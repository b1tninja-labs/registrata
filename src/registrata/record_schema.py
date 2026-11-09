"""Stable JSON schema metadata for normalized registration records."""

from __future__ import annotations

from typing import Any

from .model import RegistrationRecord

RECORD_SCHEMA_VERSION = "0.2"

# Normalized shapes of the RDAP common data structures (RFC 9083 section 4).
# Every documented member is always present, using null when the server did not
# send it, so consumers can index without guessing.
RDAP_LINK_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        # RFC 9083 section 4.2 makes these three mandatory; "complete" records
        # whether the server actually supplied all of them.
        "value": {"type": ["string", "null"]},
        "rel": {"type": ["string", "null"]},
        "href": {"type": ["string", "null"]},
        "type": {"type": ["string", "null"]},
        "media": {"type": ["string", "null"]},
        "title": {"type": ["string", "null"]},
        "hreflang": {"type": "array", "items": {"type": "string"}},
        "scope": {"type": "string"},
        "lang": {"type": ["string", "null"]},
        "complete": {"type": "boolean"},
        # A "related" link repeating a "self" href (RFC 9083 section 4.2).
        "self_duplicate": {"type": "boolean"},
        "extra": {"type": "object"},
    },
}

RDAP_NOTICE_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        # "notice" describes the service/response, "remark" the containing
        # object (RFC 9083 section 4.3). "description" is the only mandatory
        # member of the source structure.
        "context": {"enum": ["notice", "remark"]},
        "scope": {"type": "string"},
        "title": {"type": ["string", "null"]},
        "type": {"type": ["string", "null"]},
        "description": {"type": "array", "items": {"type": "string"}},
        "links": {"type": "array", "items": RDAP_LINK_ITEM_SCHEMA},
        "lang": {"type": ["string", "null"]},
        "truncation": {"enum": ["result set", "object", None]},
        "complete": {"type": "boolean"},
        # True when the source entry was not the object RFC 9083 §4.3 specifies.
        "coerced": {"type": "boolean"},
        "extra": {"type": "object"},
    },
}

RDAP_REDACTED_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "scope": {"type": "string"},
        "lang": {"type": ["string", "null"]},
        # RFC 9537 section 4.2: "name" is required, given as a registered type
        # and/or an unregistered description.
        "name_type": {"type": ["string", "null"]},
        "name_description": {"type": ["string", "null"]},
        "pre_path": {"type": ["string", "null"]},
        "post_path": {"type": ["string", "null"]},
        "replacement_path": {"type": ["string", "null"]},
        "path_lang": {"type": "string"},
        "method": {
            "enum": ["removal", "emptyValue", "partialValue", "replacementValue"]
        },
        "unknown_method": {"type": ["string", "null"]},
        "reason_type": {"type": ["string", "null"]},
        "reason_description": {"type": ["string", "null"]},
        # prePath and postPath are mutually exclusive in RFC 9537.
        "path_conflict": {"type": "boolean"},
        "complete": {"type": "boolean"},
        "extra": {"type": "object"},
    },
}

REGISTRATION_RECORD_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "registrata RegistrationRecord",
    "version": RECORD_SCHEMA_VERSION,
    "type": "object",
    "required": [
        "source",
        "kind",
        "identifier",
        "statuses",
        "events",
        "contacts",
        "nameservers",
        "networks",
        "notices",
        "links",
        "conformance",
        "lang",
        "truncated",
        "truncation",
        "redacted",
        "subsetting",
        "context",
        "raw",
    ],
    "properties": {
        "source": {"type": "string"},
        "kind": {"type": ["string", "null"]},
        "identifier": {"type": ["string", "null"]},
        "handle": {"type": ["string", "null"]},
        "statuses": {"type": "array", "items": {"type": "string"}},
        "events": {"type": "array", "items": {"type": "object"}},
        "contacts": {"type": "array", "items": {"type": "object"}},
        "nameservers": {"type": "array", "items": {"type": "string"}},
        "registrar": {"type": ["object", "null"]},
        "dnssec": {"type": ["object", "null"]},
        "networks": {"type": "array", "items": {"type": "object"}},
        "port43": {"type": ["string", "null"]},
        "notices": {"type": "array", "items": RDAP_NOTICE_ITEM_SCHEMA},
        "links": {"type": "array", "items": RDAP_LINK_ITEM_SCHEMA},
        "conformance": {"type": "array", "items": {"type": "string"}},
        "lang": {"type": ["string", "null"]},
        "truncated": {"type": "boolean"},
        "truncation": {"type": "array", "items": {"type": "object"}},
        "redacted": {"type": "array", "items": RDAP_REDACTED_ITEM_SCHEMA},
        "subsetting": {"type": ["object", "null"]},
        "context": {"type": "object"},
        "raw": {"type": ["object", "array", "string", "number", "boolean", "null"]},
    },
}

# The outermost types only, kept for callers that want a quick mapping without the schema
# document. validate_record() reads REGISTRATION_RECORD_SCHEMA instead, because this map cannot
# express item types or enums -- which is how the item schemas went unchecked in the first place.
# tests/test_record_schema.py asserts the two agree.
RECORD_TYPES: dict[str, tuple[type, ...]] = {
    "source": (str,),
    "kind": (str, type(None)),
    "identifier": (str, type(None)),
    "handle": (str, type(None)),
    "statuses": (list,),
    "events": (list,),
    "contacts": (list,),
    "nameservers": (list,),
    "registrar": (dict, type(None)),
    "dnssec": (dict, type(None)),
    "networks": (list,),
    "port43": (str, type(None)),
    "notices": (list,),
    "links": (list,),
    "conformance": (list,),
    "lang": (str, type(None)),
    "truncated": (bool,),
    "truncation": (list,),
    "redacted": (list,),
    "subsetting": (dict, type(None)),
    "context": (dict,),
    "raw": (dict, list, str, int, float, bool, type(None)),
}


def record_to_schema(record: RegistrationRecord | dict[str, Any]) -> dict[str, Any]:
    data = record.as_dict() if isinstance(record, RegistrationRecord) else dict(record)
    return {"schema_version": RECORD_SCHEMA_VERSION, "record": data}


_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "boolean": (bool,),
    "null": (type(None),),
    "number": (int, float),
    "integer": (int,),
}


def _json_type_names(schema_type: Any) -> list[str]:
    return [schema_type] if isinstance(schema_type, str) else list(schema_type or [])


def _validate_value(
    value: Any, schema: dict[str, Any], path: str, errors: list[str]
) -> None:
    """Check one value against a fragment of REGISTRATION_RECORD_SCHEMA, descending as needed.

    The schema document is the source of truth here on purpose. ``RECORD_TYPES`` only ever
    described the outermost level, so the item schemas this module publishes for links, notices
    and redacted members -- including the enums for ``context`` and ``method`` -- described
    shapes nothing ever checked, and a bare string in ``notices`` validated cleanly.
    """
    names = _json_type_names(schema.get("type"))
    if names:
        accepted: list[type] = []
        for name in names:
            accepted.extend(_JSON_TYPES.get(name, ()))
        # bool is an int subclass in Python, so a bare isinstance() would let ``truncated: true``
        # satisfy a number and ``truncated: 1`` satisfy a boolean. A bool is acceptable only where
        # the schema actually says boolean.
        if accepted:
            matches = isinstance(value, tuple(accepted))
            if isinstance(value, bool) and "boolean" not in names:
                matches = False
            if not matches:
                errors.append(f"invalid type at {path}: expected {' or '.join(names)}")
                return
    if not isinstance(value, (dict, list)):
        allowed = schema.get("enum")
        if allowed is not None and value not in allowed:
            errors.append(f"invalid value at {path}: {value!r} is not one of {allowed}")
        return
    if isinstance(value, dict):
        for required in schema.get("required", []):
            if required not in value:
                errors.append(f"missing {path}.{required}")
        properties = schema.get("properties", {})
        for member, member_schema in properties.items():
            if member in value:
                _validate_value(
                    value[member], member_schema, f"{path}.{member}", errors
                )
        return
    items = schema.get("items")
    if isinstance(items, dict):
        for index, element in enumerate(value):
            _validate_value(element, items, f"{path}[{index}]", errors)


def validate_record(record: dict[str, Any]) -> list[str]:
    """Check a normalized record against the published schema.

    Takes the record payload itself -- ``record.as_dict()``, or the ``"record"`` member of what
    ``record_to_schema`` returns. The wrapper is not a record: validating one reports all
    eighteen required fields missing, which reads as a broken record rather than a mistake at
    the call site.

    Every declared member is checked, including item types, nested link and notice structures,
    and the enums, so this is what ``registrata doctor`` means by an invalid record.
    """
    errors: list[str] = []
    properties = REGISTRATION_RECORD_SCHEMA["properties"]
    for key in REGISTRATION_RECORD_SCHEMA["required"]:
        if key not in record:
            errors.append(f"missing required field: {key}")
    for key, value in record.items():
        schema = properties.get(key)
        if schema is not None:
            _validate_value(value, schema, key, errors)
    return errors


__all__ = [
    "RECORD_SCHEMA_VERSION",
    "REGISTRATION_RECORD_SCHEMA",
    "RDAP_LINK_ITEM_SCHEMA",
    "RDAP_NOTICE_ITEM_SCHEMA",
    "RDAP_REDACTED_ITEM_SCHEMA",
    "record_to_schema",
    "validate_record",
]
