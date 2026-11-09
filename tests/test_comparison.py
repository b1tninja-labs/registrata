from registrata.comparison import compare_records
from registrata.model import RegistrationRecord
from registrata.record_schema import (
    RECORD_SCHEMA_VERSION,
    record_to_schema,
    validate_record,
)


def test_compare_records_normalizes_case_order_and_dates():
    rdap = RegistrationRecord(
        source="rdap",
        kind="domain",
        identifier="EXAMPLE.COM",
        statuses=["Active", "clientTransferProhibited"],
        nameservers=["NS2.EXAMPLE.COM", "ns1.example.com"],
        events=[{"action": "registration", "date": "2020-01-01T00:00:00+00:00"}],
        contacts=[
            {
                "roles": ["registrant"],
                "emails": ["REG@EXAMPLE.COM"],
                "phones": ["+1 (555) 1234"],
            }
        ],
    )
    whois = RegistrationRecord(
        source="whois",
        kind="domain",
        identifier="example.com.",
        statuses=["CLIENTTRANSFERPROHIBITED", "ACTIVE"],
        nameservers=["ns1.example.com.", "ns2.example.com"],
        events=[{"action": "registration", "date": "2020-01-01T00:00:00Z"}],
        contacts=[
            {
                "roles": ["registrant"],
                "emails": ["reg@example.com"],
                "phones": ["tel:15551234"],
            }
        ],
    )

    report = compare_records(
        [rdap, whois],
        fields=("identifier", "statuses", "nameservers", "events", "contacts"),
    )

    assert report["score"] == 1.0
    assert report["matches"] == [
        "identifier",
        "statuses",
        "nameservers",
        "events",
        "contacts",
    ]
    assert report["differences"] == {}


def test_compare_records_reports_differences_and_missing_fields():
    rdap = RegistrationRecord(
        source="rdap",
        kind="domain",
        identifier="example.com",
        statuses=["active"],
        contacts=[{"roles": ["registrant"], "emails": ["reg@example.com"]}],
    )
    whois = RegistrationRecord(
        source="whois",
        kind="domain",
        identifier="example.net",
        statuses=["clientHold"],
        contacts=[],
    )

    report = compare_records(
        [rdap, whois], fields=("identifier", "statuses", "contacts")
    )

    assert report["matches"] == []
    assert report["differences"]["identifier"] == {
        "rdap": "example.com",
        "whois": "example.net",
    }
    assert report["missing_or_empty"]["contacts"] == ["whois"]
    assert report["score"] == 0.0


def test_compare_records_disambiguates_duplicate_sources():
    first = RegistrationRecord(
        source="rwhois",
        kind="domain",
        identifier="one.example.com",
        statuses=["active"],
    )
    second = RegistrationRecord(
        source="rwhois",
        kind="domain",
        identifier="two.example.com",
        statuses=["active"],
    )

    report = compare_records([first, second], fields=("identifier", "statuses"))

    assert report["sources"] == ["rwhois", "rwhois#2"]
    assert report["matches"] == ["statuses"]
    assert report["differences"]["identifier"] == {
        "rwhois": "one.example.com",
        "rwhois#2": "two.example.com",
    }


# --- what the report must NOT claim -------------------------------------------------
#
# Every test above passes two records, which is the only case where "score 1.0, no differences"
# means anything. The degenerate inputs produce exactly that output today, and it is the most
# misleading thing this module can print: one source is what a lookup returns when the other
# source failed, and a mistyped --fields list compares nothing at all.


def test_one_record_is_not_reported_as_agreeing_with_itself():
    only = RegistrationRecord(
        source="rdap", kind="domain", identifier="example.com", statuses=["active"]
    )

    report = compare_records([only], fields=("identifier", "statuses", "nameservers"))

    assert report["comparable"] is False
    assert report["matches"] == [], (
        "a record agrees with itself by construction, not by evidence"
    )
    assert report["differences"] == {}
    assert report["score"] is None, (
        "a perfect score for no comparison is indistinguishable from health"
    )


def test_no_records_is_not_reported_as_agreeing_either():
    report = compare_records([], fields=("identifier",))

    assert report["comparable"] is False
    assert report["score"] is None
    assert report["matches"] == []


def test_a_typo_in_the_field_list_does_not_produce_a_perfect_score():
    a = RegistrationRecord(source="rdap", kind="domain", identifier="example.com")
    b = RegistrationRecord(source="whois", kind="domain", identifier="example.com")

    # --fields status (rather than statuses) filters down to nothing silently.
    report = compare_records([a, b], fields=("status",))

    assert report["fields"] == []
    assert report["comparable"] is False
    assert report["score"] is None


def test_a_field_empty_in_every_source_is_still_reported_as_empty():
    """Agreement and absence are different facts, and the report promises both.

    Two sources that both have no nameservers do agree, so the field stays a match; suppressing
    the emptiness because they agree hid the one thing an operator needs to know -- that neither
    source said anything about nameservers at all.
    """
    a = RegistrationRecord(
        source="rdap", kind="domain", identifier="example.com", nameservers=[]
    )
    b = RegistrationRecord(
        source="whois", kind="domain", identifier="example.com", nameservers=[]
    )

    report = compare_records([a, b], fields=("identifier", "nameservers"))

    assert report["matches"] == ["identifier", "nameservers"]
    assert report["missing_or_empty"]["nameservers"] == ["rdap", "whois"]


def test_a_real_comparison_reports_itself_comparable():
    a = RegistrationRecord(source="rdap", kind="domain", identifier="example.com")
    b = RegistrationRecord(source="whois", kind="domain", identifier="example.com")

    report = compare_records([a, b], fields=("identifier",))

    assert report["comparable"] is True
    assert report["score"] == 1.0
    assert report["reason"] is None


def test_record_schema_wraps_and_validates_records():
    record = RegistrationRecord(
        source="rdap", kind="domain", identifier="example.com"
    ).as_dict()
    assert validate_record(record) == []
    wrapped = record_to_schema(record)
    assert wrapped["schema_version"] == RECORD_SCHEMA_VERSION
    assert wrapped["record"]["source"] == "rdap"


def test_record_schema_rejects_bad_types():
    record = RegistrationRecord(
        source="rdap", kind="domain", identifier="example.com"
    ).as_dict()
    record["statuses"] = "active"
    errors = validate_record(record)
    assert any("statuses" in error for error in errors)
