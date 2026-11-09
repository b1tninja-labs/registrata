"""Extension-aware RDAP normalization (RFC 9083 section 4/9, RFC 8982, RFC 9537).

These tests pin the contract of ``from_rdap`` for the common data structures that
the normalized model represents explicitly: conformance, language, the status,
nameserver, network and secureDNS members, notices and remarks, links and
referral walking, redacted fields, and subsetting metadata, plus the guarantee
that hostile input never escapes as an exception.
"""

from registrata.model import (
    _iter_rdap_objects,
    RDAP_BASE_CONFORMANCE,
    RDAP_DEFAULT_PATH_LANG,
    RDAP_DEFAULT_REDACTION_METHOD,
    RDAP_LINK_MEMBERS,
    RDAP_LINK_REQUIRED_MEMBERS,
    RDAP_NOTICE_MEMBERS,
    RDAP_REDACTED_CONFORMANCE,
    RDAP_REDACTION_METHODS,
    RDAP_SUBSETTING_CONFORMANCE,
    RDAP_TRUNCATION_TYPES,
    from_rdap,
    from_rwhois_object,
    from_whois_fields,
)
from registrata.record_schema import (
    RDAP_LINK_ITEM_SCHEMA,
    RDAP_NOTICE_ITEM_SCHEMA,
    RECORD_SCHEMA_VERSION,
    REGISTRATION_RECORD_SCHEMA,
    validate_record,
)
from registrata.records import ObjectRecord

TOP_SELF = "https://rdap.example.test/domain/example.com"


def _domain(**members):
    payload = {"objectClassName": "domain", "ldhName": "example.com", "handle": "dom-1"}
    payload.update(members)
    return payload


def _link(**members):
    link = {"value": TOP_SELF, "rel": "related", "href": TOP_SELF}
    link.update(members)
    return link


def _notice(**members):
    notice = {"title": "Terms of Use", "description": ["Status: active"]}
    notice.update(members)
    return notice


def _notice_for(record, scope, context=None):
    matches = [
        notice
        for notice in record.notices
        if notice["scope"] == scope
        and (context is None or notice["context"] == context)
    ]
    assert len(matches) == 1, (scope, context, record.notices)
    return matches[0]


def _link_for(record, scope, rel=None):
    matches = [
        link
        for link in record.links
        if link["scope"] == scope and (rel is None or link["rel"] == rel)
    ]
    assert len(matches) == 1, (scope, rel, record.links)
    return matches[0]


def _notice_scopes(record):
    return {notice["scope"] for notice in record.notices}


def _by_title(notices):
    return {notice["title"]: notice for notice in notices}


def _scopes(payload):
    return [scope for _obj, scope, _lang in _iter_rdap_objects(payload)]


# ---------------------------------------------------------------------------
# rdapConformance (RFC 9083 section 4.1)
# ---------------------------------------------------------------------------


def test_rdap_conformance_feeds_supports_and_the_extension_list():
    record = from_rdap(
        _domain(rdapConformance=["rdap_level_0", "redacted", "subsetting"])
    )
    assert record.conformance == ["rdap_level_0", "redacted", "subsetting"]
    assert record.supports("redacted")
    assert record.supports("  REDACTED  ")
    assert not record.supports("tmn")
    # Every token but the RFC 9083 identifier names an extension, and the base
    # identifier is recognized however the server capitalizes it.
    assert record.context["extensions"] == ["redacted", "subsetting"]
    assert RDAP_BASE_CONFORMANCE not in record.context["extensions"]
    assert from_rdap(_domain(rdapConformance=["RDAP_LEVEL_0", "redacted"])).context[
        "extensions"
    ] == ["redacted"]
    assert from_rdap(_domain()).conformance == []
    assert from_rdap(_domain()).context["extensions"] == []


# ---------------------------------------------------------------------------
# Language (RFC 9083 section 4.4)
# ---------------------------------------------------------------------------


def test_top_level_lang_is_inherited_by_nested_structures():
    record = from_rdap(
        _domain(
            lang="en",
            notices=[_notice()],
            entities=[
                {
                    "handle": "reg-1",
                    "remarks": [
                        _notice(title="Registrar remark", description=["registrar"])
                    ],
                    "links": [
                        _link(rel="self", href="https://rdap.example.test/entity/reg-1")
                    ],
                }
            ],
        )
    )
    assert record.lang == "en"
    assert _notice_for(record, "top")["lang"] == "en"
    assert _notice_for(record, "entity:reg-1")["lang"] == "en"
    assert _link_for(record, "entity:reg-1")["lang"] == "en"


def test_nested_lang_overrides_inherited_lang_for_its_subtree():
    record = from_rdap(
        _domain(
            lang="en",
            notices=[_notice()],
            entities=[
                {
                    "handle": "reg-1",
                    "lang": "de",
                    "remarks": [
                        _notice(title="Registrar remark", description=["registrar"])
                    ],
                    "links": [
                        _link(rel="self", href="https://rdap.example.test/entity/reg-1")
                    ],
                    "entities": [
                        {
                            "handle": "sub-1",
                            "remarks": [
                                _notice(title="Deep remark", description=["deep"])
                            ],
                        }
                    ],
                }
            ],
        )
    )
    assert record.lang == "en"
    assert _notice_for(record, "top")["lang"] == "en"
    assert _notice_for(record, "entity:reg-1")["lang"] == "de"
    assert _link_for(record, "entity:reg-1")["lang"] == "de"
    assert _notice_for(record, "entity:reg-1/entity:sub-1")["lang"] == "de"


# ---------------------------------------------------------------------------
# Status, nameservers, networks and secureDNS (RFC 9083 section 4.6, 4.7, 4.9)
# ---------------------------------------------------------------------------


def test_status_given_as_a_bare_string_is_one_status():
    # RFC 9083 section 4.6 specifies an array of status strings; a server that
    # sends one bare string means one status, not one status per character.
    record = from_rdap(_domain(status="active"))
    assert record.statuses == ["active"]
    assert validate_record(record.as_dict()) == []


def test_status_list_entries_are_coerced_to_text():
    record = from_rdap(_domain(status=["ok", None, 5, {"weird": True}]))
    assert record.statuses == ["ok", "5"]
    assert all(isinstance(status, str) for status in record.statuses)
    # Blank tokens and nested arrays carry no readable status and are dropped.
    assert from_rdap(_domain(status=["active", "", "  ", ["nested"]])).statuses == [
        "active"
    ]


def test_nameservers_accept_strings_and_objects_in_the_order_received():
    # RFC 9083 section 4.7 makes "nameservers" an array of objects, while plenty
    # of servers emit plain strings; both shapes are accepted, in order, and the
    # case of the name as sent is preserved.
    record = from_rdap(
        _domain(nameservers=["ns1.example.com", {"ldhName": "NS2.EXAMPLE.NET"}])
    )
    assert record.nameservers == ["ns1.example.com", "NS2.EXAMPLE.NET"]


def test_nameserver_objects_are_named_by_ldh_name_and_ignore_unrelated_members():
    record = from_rdap(
        _domain(
            nameservers=[
                {"unicodeName": "ns2.example.net", "ldhName": "ns2.example.com"},
                {"ipAddress": ["192.0.2.1"]},
                {"name": "not a nameserver member"},
            ]
        )
    )
    # "ldhName" wins over "unicodeName", and an object that names nothing
    # contributes nothing instead of the repr of the whole object.
    assert record.nameservers == ["ns2.example.com"]


def test_nameservers_collapse_duplicates():
    record = from_rdap(
        _domain(
            nameservers=[
                "ns1.example.com",
                {"ldhName": "ns1.example.com"},
                "NS1.EXAMPLE.COM",
            ]
        )
    )
    # Only the exact name is collapsed; case differences are kept as sent.
    assert record.nameservers == ["ns1.example.com", "NS1.EXAMPLE.COM"]


def test_nameservers_given_a_scalar_or_a_bare_object_instead_of_an_array():
    assert from_rdap(_domain(nameservers={"not": "a list"})).nameservers == []
    assert from_rdap(_domain(nameservers="ns1.example.com")).nameservers == [
        "ns1.example.com"
    ]


def test_networks_given_as_a_bare_string_becomes_one_named_network():
    record = from_rdap(_domain(networks="NET-1"))
    assert record.networks == [{"name": "NET-1"}]
    assert validate_record(record.as_dict()) == []


def test_network_entries_keep_their_object_shape():
    # A network is a dict on the record, so a scalar entry is named rather than
    # flattened, and an entry that already is an object keeps every member it has.
    record = from_rdap(_domain(networks=[None, "NET-A", {"handle": "N"}]))
    assert record.networks == [{"name": "NET-A"}, {"handle": "N"}]
    assert validate_record(record.as_dict()) == []


def test_secure_dns_with_a_non_mapping_value_is_kept_as_raw():
    # The record schema only allows a mapping for "dnssec", so a server that sends
    # a bare value has that value kept under "raw" instead of breaking the record.
    record = from_rdap(_domain(secureDNS=True))
    assert record.dnssec == {"raw": True}
    assert validate_record(record.as_dict()) == []
    assert from_rdap(_domain(secureDNS="unsigned")).dnssec == {"raw": "unsigned"}
    assert from_rdap(_domain(secureDNS=[{"delegationSigned": True}])).dnssec == {
        "raw": [{"delegationSigned": True}]
    }


def test_secure_dns_mapping_is_preserved_verbatim():
    record = from_rdap(_domain(secureDNS={"delegationSigned": True, "maxSigLife": 300}))
    assert record.dnssec == {"delegationSigned": True, "maxSigLife": 300}
    assert from_rdap(_domain()).dnssec is None


# ---------------------------------------------------------------------------
# Notices and remarks: context and scope (RFC 9083 section 4.3)
# ---------------------------------------------------------------------------


def test_top_level_notices_and_remarks_are_scoped_to_top():
    record = from_rdap(
        _domain(
            notices=[_notice()],
            remarks=[_notice(title="Server remark", description=["registrar data"])],
        )
    )
    assert {notice["context"] for notice in record.notices} == {"notice", "remark"}
    assert _notice_for(record, "top", context="notice")["title"] == "Terms of Use"
    assert _notice_for(record, "top", context="remark")["title"] == "Server remark"


def test_entity_remarks_are_scoped_by_handle_chain():
    record = from_rdap(
        _domain(
            entities=[
                {
                    "handle": "reg-1",
                    "remarks": [
                        _notice(title="Registrar remark", description=["registrar"])
                    ],
                },
                {
                    "handle": "con-1",
                    "roles": ["registrant"],
                    "entities": [
                        {
                            "handle": "abuse-1",
                            "remarks": [
                                _notice(title="Abuse remark", description=["abuse"])
                            ],
                        }
                    ],
                },
            ]
        )
    )
    assert _notice_for(record, "entity:reg-1")["context"] == "remark"
    assert _notice_for(record, "entity:con-1/entity:abuse-1")["title"] == "Abuse remark"
    assert _notice_scopes(record) == {"entity:reg-1", "entity:con-1/entity:abuse-1"}


def test_nameserver_network_and_variant_remarks_are_scoped_by_name():
    record = from_rdap(
        _domain(
            nameservers=[
                {
                    "ldhName": "ns1.example.com",
                    "remarks": [_notice(title="ns remark", description=["hidden"])],
                }
            ],
            networks=[
                {
                    "name": "NET-1",
                    "remarks": [_notice(title="net remark", description=["hidden"])],
                }
            ],
            variants=[
                {
                    "ldhName": "variant.example",
                    "remarks": [
                        _notice(title="variant remark", description=["hidden"])
                    ],
                }
            ],
        )
    )
    assert _notice_for(record, "nameserver:ns1.example.com")["title"] == "ns remark"
    assert _notice_for(record, "network:NET-1")["title"] == "net remark"
    assert _notice_for(record, "variant:variant.example")["title"] == "variant remark"
    # An object without a scalar name still gets a stable positional scope.
    positional = from_rdap(
        _domain(
            variants=[
                {
                    "variantName": {"ldhName": "variant.example"},
                    "remarks": [
                        _notice(title="positional remark", description=["hidden"])
                    ],
                }
            ]
        )
    )
    assert _notice_for(positional, "variant#0")["title"] == "positional remark"


def test_variant_scope_reads_the_names_of_the_variant_itself():
    # RFC 9083 section 5.3: a variant object identifies itself through its own
    # "variantNames" member, so the scope label uses that name.
    assert _scopes({"variants": [{"variantNames": [{"ldhName": "V.EXAMPLE"}]}]}) == [
        "variant:V.EXAMPLE"
    ]
    scoped = from_rdap(
        _domain(
            variants=[
                {
                    "variantNames": [{"unicodeName": "v.example"}],
                    "remarks": [
                        _notice(title="variant remark", description=["hidden"])
                    ],
                }
            ]
        )
    )
    assert _notice_for(scoped, "variant:v.example")["title"] == "variant remark"
    # A variant whose names carry no text still falls back to the positional label.
    assert _scopes({"variants": [{"variantNames": [{"ldhName": ""}]}]}) == ["variant#0"]


def test_search_result_objects_are_walked_with_a_search_scope():
    record = from_rdap(
        {
            "rdapConformance": ["rdap_level_0"],
            "domainSearchResults": [
                {
                    "handle": "dom-9",
                    "remarks": [_notice(title="with handle", description=["r"])],
                    "entities": [
                        {
                            "handle": "reg-9",
                            "remarks": [
                                _notice(title="nested entity", description=["r"])
                            ],
                        }
                    ],
                },
                {
                    "ldhName": "ten.example",
                    "remarks": [_notice(title="without handle", description=["r"])],
                },
            ],
        }
    )
    assert _notice_for(record, "search:dom-9")["title"] == "with handle"
    assert _notice_for(record, "search:ten.example")["title"] == "without handle"
    assert _notice_for(record, "search:dom-9/entity:reg-9")["title"] == "nested entity"


# ---------------------------------------------------------------------------
# Notice shape, coercion and completeness
# ---------------------------------------------------------------------------


def test_notice_carries_every_documented_member():
    record = from_rdap(
        _domain(
            lang="en",
            notices=[
                _notice(
                    type="result set truncated due to authorization",
                    links=[_link(rel="alternate", href="https://example.test/status")],
                )
            ],
        )
    )
    notice = record.notices[0]
    assert set(notice) == {
        "context",
        "scope",
        "title",
        "type",
        "description",
        "links",
        "lang",
        "truncation",
        "complete",
        "coerced",
    }
    assert set(RDAP_NOTICE_MEMBERS) <= set(notice)
    assert notice["context"] == "notice"
    assert notice["scope"] == "top"
    assert notice["title"] == "Terms of Use"
    assert notice["type"] == "result set truncated due to authorization"
    assert notice["description"] == ["Status: active"]
    assert notice["lang"] == "en"
    assert notice["truncation"] == "result set"
    assert notice["links"][0]["scope"] == "top/notice:Terms of Use"


def test_notice_completeness_and_coercion_flags():
    record = from_rdap(
        _domain(notices=[_notice(), "bare string notice", {"title": "No description"}])
    )
    by_title = _by_title(record.notices)
    assert by_title["Terms of Use"]["complete"] is True
    assert by_title["Terms of Use"]["coerced"] is False
    # A bare string still carries its text, but it is not the structure §4.3 specifies.
    bare = by_title[None]
    assert bare["description"] == ["bare string notice"]
    assert bare["coerced"] is True
    assert bare["complete"] is False
    assert bare["context"] == "notice"
    assert bare["scope"] == "top"
    missing = by_title["No description"]
    assert missing["description"] == []
    assert missing["complete"] is False
    assert missing["coerced"] is False


def test_notice_description_coercions():
    record = from_rdap(
        _domain(
            notices=[
                {"title": "wrapped in value", "description": {"value": "wrapped text"}},
                {"title": "wrapped in text", "description": {"text": "text member"}},
                {
                    "title": "mixed",
                    "description": ["keep", None, ["nested"], {"no_text": 1}, "  "],
                },
            ]
        )
    )
    by_title = _by_title(record.notices)
    assert by_title["wrapped in value"]["description"] == ["wrapped text"]
    assert by_title["wrapped in value"]["complete"] is False
    assert by_title["wrapped in text"]["description"] == ["text member"]
    assert by_title["mixed"]["description"] == ["keep"]
    assert len(record.notices) == 3


def test_notice_unknown_members_are_preserved_in_extra():
    record = from_rdap(_domain(notices=[_notice(hreflang="en", injected={"a": 1})]))
    notice = record.notices[0]
    assert notice["extra"] == {"hreflang": "en", "injected": {"a": 1}}
    assert "hreflang" not in notice
    assert from_rdap(_domain(notices=[_notice()])).notices[0].get("extra") is None


# ---------------------------------------------------------------------------
# Truncation (RFC 9083 section 9 and section 10.2.1)
# ---------------------------------------------------------------------------


def test_every_registered_truncation_type_is_classified():
    assert len(RDAP_TRUNCATION_TYPES) == 6
    seen = set()
    for truncation_type in RDAP_TRUNCATION_TYPES:
        expected = (
            "result set" if truncation_type.startswith("result set") else "object"
        )
        record = from_rdap(
            _domain(remarks=[{"type": truncation_type, "description": ["partial"]}])
        )
        assert record.truncated is True
        assert record.truncation[0]["type"] == truncation_type
        assert record.truncation[0]["truncation"] == expected
        assert record.truncation[0]["context"] == "remark"
        seen.add(expected)
    assert seen == {"result set", "object"}


def test_truncation_entry_projects_the_notice_fields():
    record = from_rdap(
        _domain(
            notices=[
                {
                    "title": "Truncated",
                    "type": "result set truncated due to excessive load",
                    "description": ["only 5 of 100 records"],
                    "links": [
                        _link(
                            rel="related", href="https://rdap.example.test/domain/other"
                        )
                    ],
                }
            ]
        )
    )
    entry = record.truncation[0]
    assert set(entry) == {
        "scope",
        "context",
        "type",
        "truncation",
        "title",
        "description",
        "links",
    }
    assert entry["scope"] == "top"
    assert entry["context"] == "notice"
    assert entry["truncation"] == "result set"
    assert entry["title"] == "Truncated"
    assert entry["description"] == ["only 5 of 100 records"]
    assert entry["links"][0]["scope"] == "top/notice:Truncated"
    assert record.incomplete is True


def test_singular_truncation_variant_is_still_detected():
    remarks = [
        {"type": "object truncated due to unexplainable reason", "description": ["x"]}
    ]
    singular = from_rdap(_domain(remarks=remarks))
    assert singular.truncated is True
    assert singular.truncation[0]["truncation"] == "object"
    remarks = [
        {
            "type": "result set truncated due to unexplainable reason",
            "description": ["x"],
        }
    ]
    plural = from_rdap(_domain(remarks=remarks))
    assert plural.truncation[0]["truncation"] == "result set"


def test_notice_type_that_is_not_a_truncation_leaves_truncation_empty():
    record = from_rdap(_domain(notices=[_notice(type="terms of use")]))
    assert record.truncated is False
    assert record.truncation == []
    assert record.notices[0]["truncation"] is None


# ---------------------------------------------------------------------------
# Links (RFC 9083 section 4.2)
# ---------------------------------------------------------------------------


def test_link_carries_every_documented_member():
    record = from_rdap(
        _domain(
            lang="en",
            links=[
                _link(
                    rel="self",
                    href=TOP_SELF,
                    type="application/rdap+json",
                    media="screen",
                    title="This domain",
                    hreflang=["en", "fr"],
                )
            ],
        )
    )
    link = record.links[0]
    assert set(link) == {
        "value",
        "rel",
        "href",
        "type",
        "media",
        "title",
        "hreflang",
        "scope",
        "lang",
        "complete",
        "self_duplicate",
    }
    assert set(RDAP_LINK_MEMBERS) <= set(link)
    assert link["value"] == TOP_SELF
    assert link["rel"] == "self"
    assert link["href"] == TOP_SELF
    assert link["type"] == "application/rdap+json"
    assert link["media"] == "screen"
    assert link["title"] == "This domain"
    assert link["hreflang"] == ["en", "fr"]
    assert link["scope"] == "top"
    assert link["lang"] == "en"
    assert link["complete"] is True
    assert link["self_duplicate"] is False


def test_hreflang_given_as_a_string_is_split_into_language_tags():
    split = from_rdap(_domain(links=[_link(hreflang="en, fr")]))
    assert split.links[0]["hreflang"] == ["en", "fr"]
    array = from_rdap(_domain(links=[_link(hreflang=["de"])]))
    assert array.links[0]["hreflang"] == ["de"]
    absent = from_rdap(_domain(links=[_link()]))
    assert absent.links[0]["hreflang"] == []


def test_link_missing_a_required_member_is_incomplete():
    record = from_rdap(
        _domain(
            links=[
                {"rel": "related", "href": "https://rdap.example.test/domain/other"},
                {
                    "value": TOP_SELF,
                    "href": "https://rdap.example.test/domain/value-only",
                },
                _link(rel="related", href="https://rdap.example.test/domain/complete"),
            ]
        )
    )
    assert set(RDAP_LINK_REQUIRED_MEMBERS) == {"value", "rel", "href"}
    by_href = {link["href"]: link for link in record.links}
    assert len(record.links) == 3
    assert by_href["https://rdap.example.test/domain/other"]["complete"] is False
    assert by_href["https://rdap.example.test/domain/value-only"]["complete"] is False
    assert by_href["https://rdap.example.test/domain/value-only"]["rel"] is None
    assert by_href["https://rdap.example.test/domain/complete"]["complete"] is True


def test_link_unknown_members_are_preserved_and_non_dict_entries_are_dropped():
    record = from_rdap(
        _domain(
            links=[
                "junk",
                None,
                42,
                _link(
                    rel="related",
                    href="https://rdap.example.test/domain/other",
                    injected=[1, 2],
                ),
            ]
        )
    )
    assert len(record.links) == 1
    link = record.links[0]
    assert link["extra"] == {"injected": [1, 2]}
    assert link["hreflang"] == []


def test_nested_entity_links_are_collected_with_their_scope():
    record = from_rdap(
        _domain(
            links=[_link(rel="self", href=TOP_SELF)],
            entities=[
                {
                    "handle": "reg-1",
                    "links": [
                        _link(rel="self", href="https://rdap.example.test/entity/reg-1")
                    ],
                }
            ],
            nameservers=[
                {
                    "ldhName": "ns1.example.com",
                    "links": [
                        _link(
                            rel="related",
                            href="https://rdap.example.test/domain/ns1.example.com",
                        )
                    ],
                }
            ],
        )
    )
    assert {link["scope"] for link in record.links} == {
        "top",
        "entity:reg-1",
        "nameserver:ns1.example.com",
    }
    assert (
        _link_for(record, "entity:reg-1")["href"]
        == "https://rdap.example.test/entity/reg-1"
    )


def test_notice_links_stay_out_of_the_record_link_set_unless_requested():
    record = from_rdap(
        _domain(
            links=[_link(rel="related", href="https://rdap.example.test/domain/other")],
            notices=[
                _notice(
                    links=[
                        {
                            "value": "https://example.test/tos",
                            "rel": "Terms-of-Use",
                            "href": "https://example.test/tos",
                        }
                    ]
                )
            ],
        )
    )
    assert [link["rel"] for link in record.links] == ["related"]
    assert record.links_for("terms-of-use") == []
    on_demand = record.links_for("TERMS-OF-USE", include_notice_links=True)
    assert len(on_demand) == 1
    assert on_demand[0]["href"] == "https://example.test/tos"
    assert on_demand[0]["scope"] == "top/notice:Terms of Use"
    # Matching ignores case, and the record's own link set is returned untouched.
    assert record.links_for("RELATED") == record.links


# ---------------------------------------------------------------------------
# Referral loop protection (RFC 9083 section 4.2, RFC 9537 figures)
# ---------------------------------------------------------------------------


def test_related_link_repeating_a_self_href_is_flagged_and_not_followed():
    other = "https://rdap.example.test/domain/other"
    record = from_rdap(
        _domain(
            links=[
                _link(rel="self", href=TOP_SELF),
                _link(rel="related", href=TOP_SELF),
                _link(rel="related", href=other),
                {
                    "rel": "related",
                    "href": "https://rdap.example.test/domain/incomplete",
                },
            ]
        )
    )
    related = [link for link in record.links if link["rel"] == "related"]
    duplicated = [link for link in related if link["href"] == TOP_SELF]
    assert len(duplicated) == 1
    assert duplicated[0]["self_duplicate"] is True
    assert _link_for(record, "top", rel="self")["self_duplicate"] is False
    assert {link["href"] for link in record.referrals()} == {other}
    assert {
        link["href"] for link in record.referrals(include_self_duplicates=True)
    } == {TOP_SELF, other}


def test_self_duplicate_is_false_when_no_self_href_is_present():
    record = from_rdap(
        _domain(
            links=[_link(rel="related", href="https://rdap.example.test/domain/other")],
            notices=[
                _notice(
                    links=[
                        _link(
                            rel="related",
                            href="https://rdap.example.test/domain/in-notice",
                        )
                    ]
                )
            ],
        )
    )
    assert all(link["self_duplicate"] is False for link in record.links)
    assert len(record.referrals()) == 1
    assert len(record.links_for("related", include_notice_links=True)) == 2


# ---------------------------------------------------------------------------
# Redacted response fields (RFC 9537 section 4.2)
# ---------------------------------------------------------------------------


def test_redacted_defaults_and_registered_name():
    record = from_rdap(
        _domain(
            redacted=[
                {
                    "name": {"type": "Registrant Name"},
                    "prePath": "$.entities[0].vcardArray",
                }
            ],
        )
    )
    entry = record.redacted[0]
    assert entry["scope"] == "top"
    assert entry["lang"] is None
    assert entry["name_type"] == "Registrant Name"
    assert entry["name_description"] is None
    assert entry["pre_path"] == "$.entities[0].vcardArray"
    assert entry["post_path"] is None
    assert entry["replacement_path"] is None
    # An absent "method" means removal and an absent "pathLang" means jsonpath.
    assert entry["method"] == RDAP_DEFAULT_REDACTION_METHOD == "removal"
    assert entry["path_lang"] == RDAP_DEFAULT_PATH_LANG == "jsonpath"
    assert entry["unknown_method"] is None
    assert entry["path_conflict"] is False
    assert entry["complete"] is True
    assert record.incomplete is True


def test_redacted_unregistered_name_and_reason():
    record = from_rdap(
        _domain(
            lang="en",
            redacted=[
                {
                    "name": "Registry Data",
                    "reason": {"type": "policy", "description": "server policy"},
                    "replacementPath": "***",
                }
            ],
        )
    )
    entry = record.redacted[0]
    assert entry["name_description"] == "Registry Data"
    assert entry["name_type"] is None
    assert entry["reason_type"] == "policy"
    assert entry["reason_description"] == "server policy"
    assert entry["replacement_path"] == "***"
    assert entry["lang"] == "en"


def test_redacted_path_conflict_and_unknown_method():
    record = from_rdap(
        _domain(
            redacted=[
                {
                    "name": {"type": "Registrant Name", "description": "hidden name"},
                    "prePath": "$.entities[0].vcardArray",
                    "postPath": "$.handle",
                    "method": "bogusValue",
                    "pathLang": "custompath",
                    "injected": True,
                }
            ]
        )
    )
    entry = record.redacted[0]
    # prePath and postPath are mutually exclusive: the entry is flagged, not dropped.
    assert entry["path_conflict"] is True
    assert entry["method"] == "removal"
    assert entry["unknown_method"] == "bogusValue"
    assert entry["path_lang"] == "custompath"
    assert entry["name_type"] == "Registrant Name"
    assert entry["name_description"] == "hidden name"
    assert entry["extra"] == {"injected": True}


def test_redacted_entries_without_name_or_of_the_wrong_type():
    record = from_rdap(_domain(redacted=["junk", None, 7, {"prePath": "$.handle"}]))
    assert len(record.redacted) == 1
    entry = record.redacted[0]
    assert entry["name_type"] is None
    assert entry["name_description"] is None
    assert entry["complete"] is False
    assert from_rdap(_domain()).redacted == []


def test_redacted_inside_search_results_keeps_its_scope():
    record = from_rdap(
        {
            "redacted": [{"name": {"type": "Registry Data"}}],
            "domainSearchResults": [
                {
                    "handle": "dom-9",
                    "redacted": [{"name": "Registrant Name", "lang": "de"}],
                }
            ],
        }
    )
    by_scope = {entry["scope"]: entry for entry in record.redacted}
    assert set(by_scope) == {"top", "search:dom-9"}
    assert by_scope["top"]["name_type"] == "Registry Data"
    assert by_scope["search:dom-9"]["name_description"] == "Registrant Name"
    assert by_scope["search:dom-9"]["lang"] == "de"


def test_rdap_extension_constants_match_the_registrations():
    assert RDAP_REDACTION_METHODS == frozenset(
        {"removal", "emptyValue", "partialValue", "replacementValue"}
    )
    assert RDAP_DEFAULT_REDACTION_METHOD in RDAP_REDACTION_METHODS
    assert RDAP_DEFAULT_PATH_LANG == "jsonpath"
    assert RDAP_BASE_CONFORMANCE == "rdap_level_0"
    assert RDAP_REDACTED_CONFORMANCE == "redacted"
    assert RDAP_SUBSETTING_CONFORMANCE == "subsetting"
    assert RDAP_LINK_REQUIRED_MEMBERS == ("value", "rel", "href")
    assert RDAP_LINK_MEMBERS == (
        "value",
        "rel",
        "href",
        "type",
        "media",
        "title",
        "hreflang",
    )
    assert RDAP_NOTICE_MEMBERS == ("title", "type", "description", "links", "lang")


# ---------------------------------------------------------------------------
# Subsetting metadata (RFC 8982 section 2.1)
# ---------------------------------------------------------------------------


def test_subsetting_metadata_normalizes_the_field_sets():
    assert from_rdap(_domain()).subsetting is None
    record = from_rdap(
        _domain(
            subsetting_metadata={
                "currentFieldSet": "brief",
                "availableFieldSets": [
                    {"name": "brief", "default": True, "description": "minimal"},
                    {"name": "full", "default": False},
                    "junk",
                    {"description": "no name"},
                ],
                "odd": 1,
            }
        )
    )
    subsetting = record.subsetting
    assert set(subsetting) == {
        "current_field_set",
        "available_field_sets",
        "default_field_sets",
        "complete",
        "extra",
    }
    assert subsetting["current_field_set"] == "brief"
    assert subsetting["complete"] is True
    assert subsetting["default_field_sets"] == ["brief"]
    assert subsetting["extra"] == {"odd": 1}
    # The bare string entry is dropped rather than raising; a nameless entry survives.
    assert [field_set["name"] for field_set in subsetting["available_field_sets"]] == [
        "brief",
        "full",
        None,
    ]
    assert set(subsetting["available_field_sets"][0]) == {
        "name",
        "default",
        "description",
        "links",
    }
    assert subsetting["available_field_sets"][0]["description"] == "minimal"
    assert subsetting["available_field_sets"][1]["default"] is False
    assert subsetting["available_field_sets"][1]["links"] == []
    partial = from_rdap(
        _domain(
            subsetting_metadata={
                "availableFieldSets": [{"name": "full", "default": True}]
            }
        )
    )
    assert partial.subsetting["current_field_set"] is None
    assert partial.subsetting["complete"] is False
    assert partial.subsetting["default_field_sets"] == ["full"]
    assert "extra" not in partial.subsetting


def test_subsetting_field_set_links_are_scoped_by_field_set():
    record = from_rdap(
        _domain(
            subsetting_metadata={
                "currentFieldSet": "brief",
                "availableFieldSets": [
                    {
                        "name": "brief",
                        "default": True,
                        "links": [
                            _link(rel="alternate", href=TOP_SELF + "?fieldSet=brief")
                        ],
                    },
                    {
                        "links": [
                            _link(rel="alternate", href=TOP_SELF + "?fieldSet=unnamed")
                        ]
                    },
                ],
            }
        )
    )
    field_sets = record.subsetting["available_field_sets"]
    assert field_sets[0]["links"][0]["scope"] == "subsetting:brief"
    assert field_sets[0]["links"][0]["complete"] is True
    assert field_sets[1]["links"][0]["scope"] == "subsetting:fieldSet"
    # Field set links describe how to ask again; they are not links of the object.
    assert record.links == []


# ---------------------------------------------------------------------------
# Incompleteness
# ---------------------------------------------------------------------------


def test_subsetting_metadata_alone_does_not_mark_the_record_incomplete():
    # RFC 8982 section 2.1 metadata names the field set that was applied; it does
    # not assert that anything was withheld, so only truncation and redaction set
    # the flag.
    record = from_rdap(_domain(subsetting_metadata={"currentFieldSet": "brief"}))
    assert record.subsetting["current_field_set"] == "brief"
    assert record.incomplete is False
    assert record.truncated is False
    combined = from_rdap(
        _domain(
            subsetting_metadata={"currentFieldSet": "brief"},
            remarks=[
                {"type": "object truncated due to authorization", "description": ["x"]}
            ],
        )
    )
    assert combined.incomplete is True


def test_incomplete_flag_tracks_truncation_and_redaction():
    assert from_rdap(_domain(notices=[_notice()])).incomplete is False
    truncated = from_rdap(
        _domain(
            remarks=[
                {"type": "object truncated due to excessive load", "description": ["x"]}
            ]
        )
    )
    assert truncated.incomplete is True
    assert truncated.redacted == []
    redacted = from_rdap(_domain(redacted=[{"name": {"type": "Registrant Name"}}]))
    assert redacted.incomplete is True
    assert redacted.truncated is False


# ---------------------------------------------------------------------------
# Robustness: hostile input never raises and always stays schema-valid
# ---------------------------------------------------------------------------


def test_hostile_top_level_payloads_keep_their_raw_and_stay_schema_valid():
    for hostile in (None, [], "string", 42):
        record = from_rdap(hostile)
        payload = record.as_dict()
        assert record.source == "rdap"
        assert payload["raw"] == hostile
        assert type(record.raw) is type(hostile)
        assert record.conformance == []
        assert record.lang is None
        assert record.notices == []
        assert record.links == []
        assert record.redacted == []
        assert record.subsetting is None
        assert record.truncated is False
        assert record.incomplete is False
        assert record.context == {"extensions": [], "unmodelled_members": []}
        assert validate_record(payload) == []


def test_extension_members_given_the_wrong_shape_never_raise():
    record = from_rdap(
        _domain(
            notices="Status: active",
            links=7,
            redacted={"name": {"type": "Registrant Name"}},
            subsetting_metadata=[{"name": "brief"}],
            rdapConformance="rdap_level_0",
        )
    )
    assert record.conformance == ["rdap_level_0"]
    assert len(record.notices) == 1
    assert record.notices[0]["description"] == ["Status: active"]
    assert record.notices[0]["complete"] is False
    assert record.links == []
    assert len(record.redacted) == 1
    assert record.redacted[0]["name_type"] == "Registrant Name"
    # Subsetting metadata that is not an object describes nothing.
    assert record.subsetting is None
    assert validate_record(record.as_dict()) == []
    for payload in (
        {"notices": [None, [], 5]},
        {"links": {"rel": "self"}},
        {"redacted": [[{"name": 1}]]},
        {"subsetting_metadata": "text"},
        {"subsetting_metadata": {"availableFieldSets": "text"}},
    ):
        weird = from_rdap(_domain(**payload))
        assert validate_record(weird.as_dict()) == []


def test_every_core_member_given_the_wrong_shape_at_once_stays_schema_valid():
    record = from_rdap(
        _domain(
            status="active",
            nameservers={"not": "a list"},
            networks=[None, "NET-A", {"handle": "N"}],
            secureDNS=True,
            entities="reg-1",
            redacted={"name": "single object"},
            subsetting_metadata=["brief"],
        )
    )
    assert validate_record(record.as_dict()) == []
    assert record.statuses == ["active"]
    assert record.nameservers == []
    assert record.networks == [{"name": "NET-A"}, {"handle": "N"}]
    assert record.dnssec == {"raw": True}
    # A bare object in "entities" names no contact, and subsetting metadata that is
    # not an object describes nothing.
    assert record.contacts == []
    assert record.subsetting is None
    # The bare object in "redacted" is still one entry, with an unregistered name.
    assert len(record.redacted) == 1
    assert record.redacted[0]["name_description"] == "single object"
    assert record.redacted[0]["scope"] == "top"
    assert record.truncated is False
    assert record.incomplete is True


def test_self_referencing_entities_return_promptly():
    entity = {
        "handle": "loop-1",
        "remarks": [_notice(title="Loop", description=["again"])],
        "links": [_link(rel="self", href="https://rdap.example.test/entity/loop-1")],
    }
    entity["entities"] = [entity]
    record = from_rdap(_domain(entities=[entity], notices=[_notice()]))
    assert len(record.notices) == 2
    assert len(record.links) == 1
    assert _notice_scopes(record) == {"top", "entity:loop-1"}
    top_cycle = {"handle": "TOP"}
    top_cycle["entities"] = [top_cycle]
    assert from_rdap(top_cycle).notices == []


def test_deeply_nested_entities_are_not_walked():
    fourth = {
        "handle": "e4",
        "remarks": [_notice(title="fourth level", description=["d"])],
    }
    third = {
        "handle": "e3",
        "remarks": [_notice(title="third level", description=["d"])],
        "entities": [fourth],
    }
    second = {
        "handle": "e2",
        "remarks": [_notice(title="second level", description=["d"])],
        "entities": [third],
    }
    first = {
        "handle": "e1",
        "remarks": [_notice(title="first level", description=["d"])],
        "entities": [second],
    }
    record = from_rdap(_domain(entities=[first]))
    assert "entity:e1/entity:e2/entity:e3" in _notice_scopes(record)
    assert "entity:e1/entity:e2/entity:e3/entity:e4" not in _notice_scopes(record)
    assert len(record.notices) == 3


def test_unicode_and_long_description_text_survive():
    long_text = "x" * 5000
    record = from_rdap(
        _domain(
            lang="fr-CA",
            entities=[
                {
                    "handle": "rég-1",
                    "remarks": [
                        _notice(
                            title="Ünïcödé", description=["Grüße, Herr Doe", long_text]
                        )
                    ],
                }
            ],
        )
    )
    notice = _notice_for(record, "entity:rég-1")
    assert notice["title"] == "Ünïcödé"
    assert notice["description"] == ["Grüße, Herr Doe", long_text]
    assert notice["lang"] == "fr-CA"
    assert record.lang == "fr-CA"
    assert validate_record(record.as_dict()) == []


# ---------------------------------------------------------------------------
# Schema (registrata.record_schema)
# ---------------------------------------------------------------------------


def _full_payload():
    return _domain(
        lang="en",
        rdapConformance=["rdap_level_0", "redacted", "subsetting"],
        status=["active"],
        notices=[
            _notice(links=[_link(rel="Terms-of-Use", href="https://example.test/tos")])
        ],
        remarks=[
            _notice(title="Server remark", description=["registrar data"]),
            "bare remark",
        ],
        links=[
            _link(rel="self", href=TOP_SELF),
            _link(rel="related", href=TOP_SELF),
            _link(
                rel="related",
                href="https://rdap.example.test/domain/other",
                hreflang="en, fr",
            ),
        ],
        entities=[
            {
                "handle": "reg-1",
                "roles": ["registrar"],
                "lang": "de",
                "remarks": [
                    {
                        "type": "object truncated due to authorization",
                        "description": ["hidden"],
                    }
                ],
                "links": [
                    _link(rel="self", href="https://rdap.example.test/entity/reg-1")
                ],
                "redacted": [
                    {
                        "name": "Registrant Name",
                        "reason": {"type": "policy", "description": "privacy"},
                    }
                ],
                "entities": [
                    {
                        "handle": "sub-1",
                        "notices": [_notice(title="Nested", description=["nested"])],
                    }
                ],
            }
        ],
        nameservers=[
            {
                "ldhName": "ns1.example.com",
                "remarks": [_notice(title="ns remark", description=["hidden"])],
            }
        ],
        networks=[
            {
                "name": "NET-1",
                "remarks": [_notice(title="net remark", description=["hidden"])],
            }
        ],
        variants=[
            {
                "ldhName": "variant.example",
                "remarks": [_notice(title="variant remark", description=["hidden"])],
            }
        ],
        redacted=[
            {
                "name": {"type": "Registrant Name"},
                "prePath": "$.entities[0].vcardArray",
                "postPath": "$.handle",
                "method": "bogusValue",
            }
        ],
        subsetting_metadata={
            "currentFieldSet": "brief",
            "availableFieldSets": [
                {
                    "name": "brief",
                    "default": True,
                    "description": "minimal",
                    "links": [
                        _link(rel="alternate", href=TOP_SELF + "?fieldSet=brief")
                    ],
                },
                "junk",
            ],
            "odd": 1,
        },
        secureDNS={"delegationSigned": True},
        totallyNewExtensionMember={"x": 1},
    )


def test_full_rdap_payload_produces_a_schema_valid_record():
    record = from_rdap(_full_payload())
    payload = record.as_dict()
    assert validate_record(payload) == []
    assert record.conformance == ["rdap_level_0", "redacted", "subsetting"]
    assert record.context["extensions"] == ["redacted", "subsetting"]
    assert record.context["unmodelled_members"] == ["totallyNewExtensionMember"]
    assert record.truncated is True
    assert record.truncation[0]["scope"] == "entity:reg-1"
    assert record.incomplete is True
    assert len(record.redacted) == 2
    assert record.subsetting["default_field_sets"] == ["brief"]
    assert {link["self_duplicate"] for link in record.links} == {True, False}
    assert [link["href"] for link in record.referrals()] == [
        "https://rdap.example.test/domain/other"
    ]


def test_record_schema_version_and_required_extension_keys():
    assert RECORD_SCHEMA_VERSION == "0.2"
    required = REGISTRATION_RECORD_SCHEMA["required"]
    for key in (
        "conformance",
        "lang",
        "truncated",
        "truncation",
        "redacted",
        "subsetting",
        "context",
        "raw",
    ):
        assert key in required
    assert (
        REGISTRATION_RECORD_SCHEMA["properties"]["notices"]["items"]
        is RDAP_NOTICE_ITEM_SCHEMA
    )
    assert (
        REGISTRATION_RECORD_SCHEMA["properties"]["links"]["items"]
        is RDAP_LINK_ITEM_SCHEMA
    )
    assert (
        RDAP_NOTICE_ITEM_SCHEMA["properties"]["links"]["items"] is RDAP_LINK_ITEM_SCHEMA
    )


# ---------------------------------------------------------------------------
# The other two sources keep empty extension defaults
# ---------------------------------------------------------------------------


def _assert_empty_extension_defaults(record):
    assert record.conformance == []
    assert record.lang is None
    assert record.truncated is False
    assert record.truncation == []
    assert record.redacted == []
    assert record.subsetting is None
    assert record.context == {}
    assert record.incomplete is False
    assert not record.supports(RDAP_REDACTED_CONFORMANCE)
    assert record.referrals() == []
    assert record.links_for("related") == []
    assert validate_record(record.as_dict()) == []


def test_whois_fields_record_keeps_empty_extension_defaults():
    record = from_whois_fields(
        {
            "Domain Name": ["EXAMPLE.COM"],
            "Name Server": ["NS1.EXAMPLE.COM"],
            "Registrar": ["Example Registrar"],
        },
        resource="example.com",
        kind="domain",
    )
    _assert_empty_extension_defaults(record)


def test_rwhois_object_record_keeps_empty_extension_defaults():
    obj = ObjectRecord("domain")
    obj.add("Class-Name", "domain")
    obj.add("ID", "dom-1.example.com")
    obj.add("Server", "hst-1.example.com", type="I")
    _assert_empty_extension_defaults(from_rwhois_object(obj))
