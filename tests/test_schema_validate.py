"""``validate_object`` -- a public compliance predicate that had no tests and no callers.

It answers "does this object satisfy this class?", which is a claim about RFC 2167 conformance,
so it is worth pinning what it checks and, as importantly, what it deliberately does not. The
cases below marked as limitations are pinned so the leniency is a visible decision rather than
an accident someone has to rediscover.
"""

import pytest

from registrata.errors import RwhoisError, RwhoisParseError
from registrata.protocol import parse_response
from registrata.records import AttributeLine, ObjectRecord
from registrata.schema import (
    AttributeDefinition,
    SchemaClass,
    parse_bool,
    validate_object,
)


def make_schema(*definitions: AttributeDefinition) -> SchemaClass:
    return SchemaClass("domain", description="test", attributes=list(definitions))


def make_object(*pairs: tuple[str, str]) -> ObjectRecord:
    record = ObjectRecord(class_name="domain", attributes=[])
    for name, value in pairs:
        record.attributes.append(AttributeLine(name=name, value=value))
    return record


NAME = AttributeDefinition("Domain-Name", "the name", required=True)
ADMIN = AttributeDefinition("Admin-Name", "contact link", repeatable=True)
NOTES = AttributeDefinition("Notes", "free text", multi_line=True)


def test_a_missing_required_attribute_is_reported() -> None:
    errors = validate_object(make_object(("Class-Name", "domain")), make_schema(NAME))

    assert errors == ["required attribute missing: Domain-Name"]


def test_a_required_attribute_with_no_value_does_not_satisfy_the_schema() -> None:
    """Appendix B defines ``attribute-value = 1*any-char``: one or more characters.

    Counting occurrences alone let ``ID:`` satisfy a required-and-primary attribute, so the
    validator reported an object as conforming when the value the schema asks for is absent.
    """
    errors = validate_object(make_object(("Domain-Name", "")), make_schema(NAME))

    assert errors, "an empty value was accepted as satisfying a required attribute"
    assert "Domain-Name" in errors[0]


def test_a_required_attribute_of_only_spaces_is_reported_too() -> None:
    """Grammar-permissible, schema-useless: spaces are ``any-char``, but carry no value."""
    errors = validate_object(make_object(("Domain-Name", "   ")), make_schema(NAME))

    assert errors, (
        "whitespace-only value was accepted as satisfying a required attribute"
    )


def test_attribute_names_compare_case_insensitively() -> None:
    """RFC 2167 treats attribute names case-insensitively; servers do send them upper-cased."""
    assert (
        validate_object(make_object(("DOMAIN-NAME", "example.com")), make_schema(NAME))
        == []
    )


def test_a_repeatable_attribute_may_appear_more_than_once() -> None:
    record = make_object(
        ("Domain-Name", "example.com"), ("Admin-Name", "a"), ("Admin-Name", "b")
    )

    assert validate_object(record, make_schema(NAME, ADMIN)) == []


def test_repeating_a_non_repeatable_attribute_is_reported() -> None:
    record = make_object(("Domain-Name", "one"), ("Domain-Name", "two"))

    errors = validate_object(record, make_schema(NAME))

    assert errors == ["non-repeatable attribute repeated: Domain-Name"]


def test_attributes_the_class_never_declared_are_outside_what_this_checks() -> None:
    """Pinned limitation: undeclared attributes are not reported.

    Appendix C defines 320 Invalid attribute for exactly this, and the server does not call this
    validator during -register either (docs/compliance.md already records that schema semantics
    for registration remain open), so nothing in the library currently enforces it. Asserting it
    here keeps that gap on the surface instead of reading as coverage.
    """
    record = make_object(("Domain-Name", "example.com"), ("Banana", "y"))

    assert validate_object(record, make_schema(NAME)) == []


def test_multi_line_repetition_is_not_flagged_because_it_cannot_be_told_apart() -> None:
    """Pinned limitation, and it rests on two facts in this codebase.

    ``AttributeDefinition`` rejects multi-line together with repeatable, so this branch can only
    ever apply to an attribute that is NOT repeatable -- and the parser has no continuation-line
    support, so a multi-line value arrives as several attribute lines indistinguishable from
    repetition. Flagging it would invent violations; not flagging it means this validator cannot
    check such an attribute, which is what the docstring now says rather than implies.
    """
    record = make_object(
        ("Domain-Name", "example.com"),
        ("Notes", "first line"),
        ("Notes", "second line"),
    )

    assert validate_object(record, make_schema(NAME, NOTES)) == []


def test_an_absent_option_takes_the_default_while_a_blank_one_is_refused() -> None:
    """The distinction has to be made at the lookup, because both arrive as the same string.

    ``from_schema_group`` answered "key not in group" with an empty string, so a group that never
    mentioned ``required`` looked identical to ``required:`` with no value. Tightening only
    ``parse_bool`` therefore made every group without the option raise -- which two corpus
    fixtures caught, and which this pins so the fix sits where the information actually is.
    """
    absent = AttributeDefinition.from_schema_group(
        {"class": "domain", "attribute": "Notes"}
    )
    assert absent.required is False
    assert absent.indexed is False

    with pytest.raises(RwhoisParseError):
        AttributeDefinition.from_schema_group(
            {"class": "domain", "attribute": "Notes", "required": ""}
        )


def test_an_absent_schema_boolean_uses_the_default() -> None:
    assert parse_bool(None) is False
    assert parse_bool(None, default=True) is True


def test_a_blank_schema_boolean_is_malformed_not_off() -> None:
    """`required:` with nothing after the colon is present-but-empty, which is not ``OFF``.

    It used to return the default, so a schema line outside the grammar read as a deliberate
    "not required" and validate_object then stopped asking for the attribute at all.
    """
    with pytest.raises(RwhoisParseError):
        parse_bool("")


def test_a_blank_schema_option_is_refused_when_the_schema_is_interpreted() -> None:
    """Reading the response keeps the raw lines; interpreting them is where the blank bites.

    That split is the right place for it: one blank option should not make a server's bytes
    unreadable, but a caller asking for typed SchemaClass objects must not get a silently
    invented ``False`` out of the same input.
    """
    response = parse_response(
        ["%schema domain:attribute:Notes", "%schema domain:required:", "%schema", "%ok"]
    )

    with pytest.raises(RwhoisError):
        response.schema_classes
