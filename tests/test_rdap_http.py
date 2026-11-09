"""Tests for the experimental RDAP transport layer (RFC 9083 §6, RFC 8288, RFC 8982).

Every test injects ``opener=``; nothing here touches the network.
"""

from __future__ import annotations

import json
import threading
from typing import Any

import pytest

from registrata.experimental import rdap
from registrata.record_schema import validate_record


@pytest.fixture(autouse=True)
def rdap_feature_enabled(monkeypatch):
    # query_rdap/lookup_rdap are gated by the RDAP experimental flag.
    monkeypatch.setenv("REGISTRATA_ENABLE_EXPERIMENTAL_RDAP", "1")


# RFC 9083 §6: errorCode (number), title (string), description (array of strings),
# plus the optional rdapConformance/notices/lang members of §4.
SECTION_6_BODY = {
    "rdapConformance": ["rdap_level_0", "icann_rdap_response_profile_0"],
    "lang": "en",
    "errorCode": 404,
    "title": "Not Found",
    "description": ["The domain you requested was not found.", "Check the spelling."],
    "notices": [
        {
            "title": "Terms of Use",
            "description": ["Usage terms apply to this response."],
            "links": [
                {
                    "value": "https://rdap.example.com/domain/example.com",
                    "rel": "terms-of-use",
                    "href": "https://rdap.example.com/terms",
                    "type": "text/html",
                }
            ],
        }
    ],
    "links": [
        {
            "value": "https://rdap.example.com/domain/example.com",
            "rel": "related",
            "href": "https://rdap.example.com/help",
            "type": "application/rdap+json",
        }
    ],
}


def _json_response(*, payload: bytes = b"{}", status: int = 200, headers: Any = None):
    class Resp:
        def __init__(self) -> None:
            self.status = status
            self.headers = (
                headers
                if headers is not None
                else {"Content-Type": "application/rdap+json"}
            )

        def read(self):
            return payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    return Resp()


class Recorder:
    """Fake opener: records the request and replays canned responses in order."""

    def __init__(self, *responses):
        self.urls: list[str] = []
        self._responses = list(responses)

    def __call__(self, req, timeout):
        self.urls.append(req.full_url)
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


def test_error_details_reads_full_section_6_body():
    details = rdap.rdap_error_details(SECTION_6_BODY)

    assert details is not None
    assert details["error_code"] == 404
    assert details["error_code_raw"] is None
    assert details["title"] == "Not Found"
    assert details["description"] == [
        "The domain you requested was not found.",
        "Check the spelling.",
    ]
    assert details["lang"] == "en"
    assert details["conformance"] == ["rdap_level_0", "icann_rdap_response_profile_0"]
    assert details["notices"][0]["context"] == "notice"
    assert details["notices"][0]["title"] == "Terms of Use"
    assert details["notices"][0]["links"][0]["rel"] == "terms-of-use"
    assert details["links"][0]["rel"] == "related"
    assert details["links"][0]["complete"] is True


def test_error_details_none_without_section_6_members():
    assert rdap.rdap_error_details({}) is None
    assert (
        rdap.rdap_error_details({"objectClassName": "domain", "ldhName": "example.com"})
        is None
    )


def test_error_details_keeps_non_integer_error_code_as_raw_text():
    details = rdap.rdap_error_details({"errorCode": "404", "title": "Not Found"})

    assert details is not None
    assert details["error_code"] is None
    assert details["error_code_raw"] == "404"
    assert details["title"] == "Not Found"
    # Repeated calls keep the raw text rather than coercing it away.
    assert rdap.rdap_error_details({"errorCode": "404"})["error_code_raw"] == "404"


def test_error_details_title_or_description_alone_counts_as_section_6():
    assert rdap.rdap_error_details({"title": "Not Found"})["error_code"] is None
    assert rdap.rdap_error_details({"description": "Plain string description"})[
        "description"
    ] == ["Plain string description"]


@pytest.mark.parametrize("junk", [None, [], "not json", 404, True, ("a",)])
def test_error_details_never_raises_on_non_object_body(junk):
    assert rdap.rdap_error_details(junk) is None


def test_error_details_survives_body_that_breaks_the_normalizer():
    # "status" as a number makes model.from_rdap fail; the §6 members are read
    # directly instead so the caller still gets the errorCode.
    details = rdap.rdap_error_details(
        {
            "errorCode": 429,
            "status": 5,
            "lang": "fr",
            "rdapConformance": ["rdap_level_0"],
        }
    )

    assert details["error_code"] == 429
    assert details["lang"] == "fr"
    assert details["conformance"] == ["rdap_level_0"]
    assert details["notices"] == []
    assert details["links"] == []


def test_rdap_result_error_details_exposes_body_members():
    result = rdap.RdapResult(
        url="https://rdap.example.com/domain/example.com",
        status=404,
        data=dict(SECTION_6_BODY),
    )

    assert not result.ok
    assert result.error is None
    assert result.error_details()["error_code"] == 404
    assert (
        rdap.RdapResult(
            url="https://rdap.example.com/domain/x", status=200
        ).error_details()
        is None
    )


# --- RFC 9110 §5.2 repeated field combination and RFC 8288 §3 Link parsing ---


def test_collect_headers_joins_repeated_fields():
    collected = rdap._collect_headers(
        [
            ("Link", '<https://rdap.example.com/a>; rel="self"'),
            ("Link", '<https://rdap.example.com/b>; rel="related"'),
        ]
    )

    assert collected == {
        "Link": '<https://rdap.example.com/a>; rel="self", <https://rdap.example.com/b>; rel="related"'
    }


def test_collect_headers_merges_case_insensitively_without_duplication():
    collected = rdap._collect_headers(
        [
            ("ETag", 'W/"v1"'),
            ("etag", "strong-v1"),
            ("Content-Type", "application/rdap+json"),
        ]
    )

    # The first-seen spelling is kept, values are combined (RFC 9110 §5.2).
    assert list(collected) == ["ETag", "Content-Type"]
    assert collected["ETag"] == 'W/"v1", strong-v1'


def test_collect_headers_accepts_a_mapping():
    assert rdap._collect_headers({"Content-Type": "application/rdap+json"}) == {
        "Content-Type": "application/rdap+json"
    }
    assert rdap._collect_headers(None) == {}


def test_parse_link_header_two_targets_in_one_value():
    parsed = rdap.parse_link_header(
        '<https://rdap.example.com/domain/example.com>; rel="self", '
        "<https://rdap.example.com/domain/other>; rel=related; type=application/rdap+json"
    )

    assert parsed == [
        {"href": "https://rdap.example.com/domain/example.com", "rel": "self"},
        {
            "href": "https://rdap.example.com/domain/other",
            "rel": "related",
            "type": "application/rdap+json",
        },
    ]


def test_parse_link_header_keeps_quoted_commas_inside_one_entry():
    parsed = rdap.parse_link_header(
        '<https://rdap.example.com/terms>; rel="terms-of-use"; title="Terms, in brief"'
    )

    assert parsed == [
        {
            "href": "https://rdap.example.com/terms",
            "rel": "terms-of-use",
            "title": "Terms, in brief",
        }
    ]


def test_parse_link_header_keeps_commas_inside_the_target():
    parsed = rdap.parse_link_header(
        '<https://rdap.example.com/ip/192.0.2.0,192.0.2.1>; rel="related"'
    )

    assert parsed == [
        {"href": "https://rdap.example.com/ip/192.0.2.0,192.0.2.1", "rel": "related"}
    ]


def test_parse_link_header_lowercases_parameter_names_and_keeps_hreflang_raw():
    parsed = rdap.parse_link_header(
        '<https://rdap.example.com/x>; HREFLANG="en, fr"; REL="self"'
    )

    assert parsed[0]["hreflang"] == "en, fr"
    assert parsed[0]["rel"] == "self"
    assert "HREFLANG" not in parsed[0]


@pytest.mark.parametrize(
    "junk",
    [
        None,
        "",
        "   ",
        "not a link header",
        "<<<<>, , <>; rel=, broken",
        "garbage; rel=self",
        "<https://a.example",
        "<https://a.example>; rel=",
    ],
)
def test_parse_link_header_never_raises_on_junk(junk):
    parsed = rdap.parse_link_header(junk)

    assert isinstance(parsed, list)
    # Only usable link-values survive: an entry is never emitted without a target.
    assert all(entry.get("href") for entry in parsed)


def test_parse_link_header_drops_only_the_broken_entries():
    assert rdap.parse_link_header("<<<<>, , <>; rel=, broken") == []
    assert rdap.parse_link_header(
        ', <>; rel=self, <https://rdap.example.com/ok>; rel="self"'
    ) == [{"href": "https://rdap.example.com/ok", "rel": "self"}]


def test_rdap_header_links_normalizes_through_the_model_shape():
    headers = {
        "Link": '<https://rdap.example.com/help>; rel="help"; type="text/html"; hreflang="en, fr"; title="Help"'
    }
    links = rdap.rdap_header_links(
        headers, base_url="https://rdap.example.com/domain/example.com", lang="en"
    )

    assert len(links) == 1
    link = links[0]
    assert link["scope"] == "http:link"
    assert link["value"] == "https://rdap.example.com/domain/example.com"
    assert link["href"] == "https://rdap.example.com/help"
    assert link["rel"] == "help"
    assert link["type"] == "text/html"
    assert link["title"] == "Help"
    assert link["hreflang"] == ["en", "fr"]
    assert link["lang"] == "en"
    assert link["complete"] is True
    assert link["self_duplicate"] is False


def test_rdap_header_links_handles_missing_and_malformed_headers():
    assert rdap.rdap_header_links(None) == []
    assert rdap.rdap_header_links({}) == []
    assert rdap.rdap_header_links({"Content-Type": "application/rdap+json"}) == []
    assert rdap.rdap_header_links({"Link": "junk, , <>"}) == []
    # Without a base URL the required context member is absent, so the link is
    # kept but marked incomplete (RFC 9083 §4.2).
    partial = rdap.rdap_header_links(
        {"Link": '<https://rdap.example.com/help>; rel="help"'}
    )
    assert partial[0]["value"] is None
    assert partial[0]["complete"] is False


def test_rdap_header_links_repeated_link_fields_are_all_kept():
    headers = rdap._collect_headers(
        [
            ("Link", '<https://rdap.example.com/self>; rel="self"'),
            ("Link", '<https://rdap.example.com/related>; rel="related"'),
        ]
    )
    links = rdap.rdap_header_links(
        headers, base_url="https://rdap.example.com/domain/example.com"
    )

    assert [link["rel"] for link in links] == ["self", "related"]


def test_rdap_header_links_keeps_unknown_parameters_in_extra():
    # RFC 8288 registers parameters RFC 9083 §4.2 has no member for; they must not
    # vanish on the way into the normalized link shape.
    headers = {
        "Link": '<https://rdap.example.com/doc>; rel="alternate"; anchor="one two"; oc="AAA"; sort="2"'
    }
    links = rdap.rdap_header_links(headers, base_url=URL)

    assert links[0]["rel"] == "alternate"
    assert links[0]["extra"] == {"anchor": "one two", "oc": "AAA", "sort": "2"}


def test_http_get_json_combines_repeated_link_headers_on_success():
    class Resp:
        status = 200

        def __init__(self):
            self.headers = [
                ("Content-Type", "application/rdap+json"),
                ("Link", '<https://rdap.example.com/self>; rel="self"'),
                ("Link", '<https://rdap.example.com/related>; rel="related"'),
            ]

        def read(self):
            return b'{"objectClassName":"domain","ldhName":"example.com"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    result = rdap.http_get_json(
        "https://rdap.example.com/domain/example.com",
        opener=lambda req, timeout: Resp(),
    )

    assert result.ok
    assert rdap.parse_link_header(result.headers["Link"]) == [
        {"href": "https://rdap.example.com/self", "rel": "self"},
        {"href": "https://rdap.example.com/related", "rel": "related"},
    ]


def test_http_get_json_combines_repeated_link_headers_on_http_error():
    import io
    from urllib import error as urllib_error

    body = json.dumps({"errorCode": 404, "title": "Not Found"}).encode("utf-8")
    headers = [
        ("Content-Type", "application/rdap+json"),
        ("Link", '<https://rdap.example.com/help>; rel="help"'),
        ("link", '<https://rdap.example.com/terms>; rel="terms-of-use"'),
    ]

    def opener(req, timeout):
        raise urllib_error.HTTPError(
            req.full_url, 404, "Not Found", headers, io.BytesIO(body)
        )

    result = rdap.http_get_json(
        "https://rdap.example.com/domain/gone.example", opener=opener
    )

    assert result.status == 404
    assert result.error is None
    assert [link["rel"] for link in rdap.rdap_header_links(result.headers)] == [
        "help",
        "terms-of-use",
    ]
    assert result.error_details()["title"] == "Not Found"


# --- normalize_rdap with HTTP context ---

BODY_WITH_SELF = {
    "objectClassName": "domain",
    "ldhName": "example.com",
    "handle": "2",
    "links": [
        {
            "value": "https://rdap.example.com/domain/example.com",
            "rel": "self",
            "href": "https://rdap.example.com/domain/example.com",
        }
    ],
}

URL = "https://rdap.example.com/domain/example.com"


def test_normalize_rdap_one_argument_is_unchanged():
    from registrata.model import from_rdap

    assert (
        rdap.normalize_rdap(BODY_WITH_SELF).as_dict()
        == from_rdap(BODY_WITH_SELF).as_dict()
    )
    # No transport arguments means no "http" context at all.
    assert "http" not in rdap.normalize_rdap(BODY_WITH_SELF).context


def test_normalize_rdap_records_http_context_and_header_link():
    headers = {
        "Content-Type": "application/rdap+json",
        "Content-Language": "de",
        "Notice": "11100 - Service partial",
        "Link": '<https://rdap.example.com/terms>; rel="terms-of-use"; type="text/html"',
    }
    record = rdap.normalize_rdap(BODY_WITH_SELF, headers=headers, url=URL, status=200)

    assert record.context["http"] == {
        "url": URL,
        "status": 200,
        "content_type": "application/rdap+json",
        "content_language": "de",
        "notice": "11100 - Service partial",
        "link_header_targets": ["https://rdap.example.com/terms"],
    }
    body_links, header_link = record.links
    assert body_links["scope"] == "top"
    assert header_link["scope"] == "http:link"
    assert header_link["value"] == URL
    assert header_link["rel"] == "terms-of-use"


def test_normalize_rdap_status_only_context():
    record = rdap.normalize_rdap(BODY_WITH_SELF, status=404)

    assert record.context["http"] == {"status": 404}
    # The body's own links are untouched when no header links exist.
    assert [link["rel"] for link in record.links] == ["self"]


def test_normalize_rdap_header_related_link_repeating_self_href_is_flagged():
    headers = {"Link": f'<{URL}>; rel="related"'}
    record = rdap.normalize_rdap(BODY_WITH_SELF, headers=headers, url=URL)

    header_link = record.links[-1]
    assert header_link["scope"] == "http:link"
    assert header_link["rel"] == "related"
    assert header_link["self_duplicate"] is True
    assert record.referrals() == []
    assert record.referrals(include_self_duplicates=True) == [header_link]


def test_normalize_rdap_never_takes_lang_from_content_language():
    # RFC 7480 §9.3: Content-Language is advisory; only the body's "lang" is record.lang.
    record = rdap.normalize_rdap(
        {"objectClassName": "domain", "ldhName": "example.com"},
        headers={"Content-Language": "de"},
        url=URL,
    )

    assert record.lang is None
    assert record.context["http"]["content_language"] == "de"


def test_normalize_rdap_body_lang_wins_and_labels_header_links():
    record = rdap.normalize_rdap(
        {"objectClassName": "domain", "ldhName": "example.com", "lang": "fr"},
        headers={
            "Content-Language": "de",
            "Link": '<https://rdap.example.com/help>; rel="help"',
        },
        url=URL,
    )

    assert record.lang == "fr"
    assert record.links[-1]["lang"] == "fr"


def test_normalize_rdap_hostile_headers_stay_valid_and_opaque():
    hostile = {
        "Content-Type": "",
        "Content-Language": ";; q=",
        "Notice": ",,,, <<<<, \x00partial",
        "Link": '<<<<>, , <>; rel=, broken, <https://rdap.example.com/x>; rel="related"; title="evil, " ; hreflang="en, fr"',
        "X-Junk": None,
    }
    record = rdap.normalize_rdap(BODY_WITH_SELF, headers=hostile, url=URL, status=500)

    assert validate_record(record.as_dict()) == []
    assert record.context["http"]["notice"] == ",,,, <<<<, \x00partial"
    assert "content_type" not in record.context["http"]
    assert record.context["http"]["link_header_targets"] == [
        "https://rdap.example.com/x"
    ]
    assert record.links[-1]["hreflang"] == ["en", "fr"]
    # The surviving header link is a legitimate, complete "related" link.
    assert [link["href"] for link in record.referrals()] == [
        "https://rdap.example.com/x"
    ]


# --- RFC 8982 §2 fieldSet query parameter ---

ANSWER = json.dumps({"objectClassName": "domain", "ldhName": "example.com"})


def _answer_response(status: int = 200):
    return _json_response(payload=ANSWER.encode("utf-8"), status=status)


def test_query_rdap_field_set_appends_the_rfc8982_parameter():
    recorder = Recorder(_answer_response(), _answer_response())
    rdap.query_rdap(
        "https://rdap.example.com/",
        "/domain/example.com",
        opener=recorder,
        field_set="brief",
    )
    rdap.query_rdap("https://rdap.example.com/", "/domain/example.com", opener=recorder)

    assert recorder.urls == [
        "https://rdap.example.com/domain/example.com?fieldSet=brief",
        "https://rdap.example.com/domain/example.com",
    ]


def test_query_rdap_field_set_uses_ampersand_when_a_query_is_present():
    recorder = Recorder(_answer_response(), _answer_response())
    rdap.query_rdap(
        "https://rdap.example.com/",
        "/domain/example.com?apiKey=XYZ",
        opener=recorder,
        field_set="brief",
    )
    rdap.query_rdap(
        "https://rdap.example.com/", "/domain/example.com?apiKey=XYZ", opener=recorder
    )

    assert recorder.urls == [
        "https://rdap.example.com/domain/example.com?apiKey=XYZ&fieldSet=brief",
        "https://rdap.example.com/domain/example.com?apiKey=XYZ",
    ]


@pytest.mark.parametrize("blank", [None, "", "   ", "\t"])
def test_query_rdap_blank_field_set_sends_no_parameter(blank):
    recorder = Recorder(_answer_response())
    rdap.query_rdap(
        "https://rdap.example.com/",
        "/domain/example.com",
        opener=recorder,
        field_set=blank,
    )

    assert recorder.urls == ["https://rdap.example.com/domain/example.com"]


def test_query_rdap_percent_encodes_the_field_set_name():
    recorder = Recorder(_answer_response())
    rdap.query_rdap(
        "https://rdap.example.com/",
        "/domain/example.com",
        opener=recorder,
        field_set="public brief",
    )

    assert recorder.urls == [
        "https://rdap.example.com/domain/example.com?fieldSet=public%20brief"
    ]


def test_query_rdap_field_sets_cache_independently_of_the_full_response():
    from registrata.cache import TTLCache

    recorder = Recorder(_answer_response(), _answer_response())
    cache = TTLCache(default_ttl=60)
    full = rdap.query_rdap(
        "https://rdap.example.com/", "/domain/example.com", opener=recorder, cache=cache
    )
    brief = rdap.query_rdap(
        "https://rdap.example.com/",
        "/domain/example.com",
        opener=recorder,
        cache=cache,
        field_set="brief",
    )

    assert full.cache_mode == "miss"
    assert brief.cache_mode == "miss"
    assert len(recorder.urls) == 2


def test_lookup_rdap_threads_field_set_to_the_base_url_query():
    recorder = Recorder(_answer_response(), _answer_response())
    rdap.lookup_rdap(
        "example.com",
        base_url="https://rdap.example.com/",
        opener=recorder,
        field_set="brief",
    )
    rdap.lookup_rdap(
        "example.com", base_url="https://rdap.example.com/", opener=recorder
    )

    assert recorder.urls == [
        "https://rdap.example.com/domain/example.com?fieldSet=brief",
        "https://rdap.example.com/domain/example.com",
    ]


def test_append_field_set_helper():
    assert (
        rdap._append_field_set("https://e.test/domain/x", None)
        == "https://e.test/domain/x"
    )
    assert (
        rdap._append_field_set("https://e.test/domain/x?a=1", "brief")
        == "https://e.test/domain/x?a=1&fieldSet=brief"
    )
    assert (
        rdap._append_field_set("https://e.test/domain/x", "a/b?c")
        == "https://e.test/domain/x?fieldSet=a%2Fb%3Fc"
    )


def test_transport_response_feeds_normalize_rdap_end_to_end():
    response = _json_response(
        payload=json.dumps(BODY_WITH_SELF).encode("utf-8"),
        status=200,
        headers=[
            ("Content-Type", "application/rdap+json"),
            ("Notice", "11100 - Service partial"),
            ("Link", f'<{URL}>; rel="related"'),
        ],
    )
    result = rdap.query_rdap(
        "https://rdap.example.com/",
        "/domain/example.com",
        opener=lambda req, timeout: response,
    )
    record = rdap.normalize_rdap(
        result.data, headers=result.headers, url=result.url, status=result.status
    )

    assert result.ok
    # Header spelling is preserved by _collect_headers, and the raw Notice header is
    # kept as opaque context: RFC 9083 §9 puts truncation in the body, not here.
    assert list(result.headers) == ["Content-Type", "Notice", "Link"]
    assert record.context["http"] == {
        "url": URL,
        "status": 200,
        "content_type": "application/rdap+json",
        "notice": "11100 - Service partial",
        "link_header_targets": [URL],
    }
    assert record.truncated is False
    assert record.links[-1]["scope"] == "http:link"
    assert record.links[-1]["self_duplicate"] is True
    assert record.referrals() == []


# --- bootstrap cache: single-flight loading and atomic replacement ---

BOOTSTRAP_URL = "https://bootstrap.invalid/dns.json"
BOOTSTRAP_SERVICES = {"services": [[["com"], ["https://rdap.example/"]]]}
BOOTSTRAP_THREADS = 6
# Every wait/join in this section is bounded, so a regression hangs nothing.
BOUND = 5.0


def _bootstrap_response(payload: dict[str, Any], *, etag: str):
    return _json_response(
        payload=json.dumps(payload).encode("utf-8"),
        status=200,
        headers={"Content-Type": "application/json", "ETag": etag},
    )


def _large_bootstrap_payload(
    *, marker: str, pad_bytes: int = 262_144
) -> dict[str, Any]:
    """A body big enough that a truncate-then-write would be caught mid-flight."""
    return {
        "services": [[["com", marker], ["https://rdap.example/", marker]]],
        "padding": "x" * pad_bytes,
    }


class GatedOpener:
    """Fake opener that parks inside the fetch until the test opens the gate.

    Each invocation is recorded, so letting more than one thread through to HTTP
    shows up as more than one call.
    """

    def __init__(self, response: Any):
        self.response = response
        self.calls: list[str] = []
        self.inside = threading.Event()
        self.gate = threading.Event()

    def __call__(self, req, timeout):
        self.calls.append(req.full_url)
        self.inside.set()
        self.gate.wait(timeout=BOUND)
        return self.response


def _stampede_bootstrap_cache(cache_dir, opener, **arguments):
    """Fire ``BOOTSTRAP_THREADS`` concurrent ``load_bootstrap`` calls at one cache dir."""
    barrier = threading.Barrier(BOOTSTRAP_THREADS, timeout=BOUND)
    results: list[Any] = [None] * BOOTSTRAP_THREADS
    errors: list[BaseException] = []
    errors_guard = threading.Lock()

    def worker(index: int) -> None:
        try:
            barrier.wait()
            results[index] = rdap.load_bootstrap(
                "domain",
                cache_dir=cache_dir,
                url=BOOTSTRAP_URL,
                opener=opener,
                **arguments,
            )
        except BaseException as exc:
            with errors_guard:
                errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(index,), daemon=True)
        for index in range(BOOTSTRAP_THREADS)
    ]
    for thread in threads:
        thread.start()
    try:
        # The first writer is inside the fetch; the rest are queued behind it.
        assert opener.inside.wait(timeout=BOUND), "no thread ever reached the fetch"
    finally:
        opener.gate.set()
        for thread in threads:
            thread.join(timeout=BOUND)
    assert [thread.name for thread in threads if thread.is_alive()] == []
    return results, errors


def test_bootstrap_stampede_of_threads_fetches_the_document_once(tmp_path):
    opener = GatedOpener(_bootstrap_response(BOOTSTRAP_SERVICES, etag='"stamp"'))

    results, errors = _stampede_bootstrap_cache(tmp_path, opener, max_age_seconds=3600)

    assert errors == []
    # One download per process: the writers that arrive while the fetch is in
    # progress block on the per-file lock and then find the fresh cache.
    assert opener.calls == [BOOTSTRAP_URL]
    assert results == [BOOTSTRAP_SERVICES] * BOOTSTRAP_THREADS
    assert rdap.bootstrap_cache_path(tmp_path, "domain").exists()


def test_bootstrap_cache_replacement_is_atomic(tmp_path):
    cache_file = rdap.bootstrap_cache_path(tmp_path, "domain")
    opener = GatedOpener(_bootstrap_response(BOOTSTRAP_SERVICES, etag='"stamp"'))

    results, errors = _stampede_bootstrap_cache(tmp_path, opener, max_age_seconds=3600)

    assert errors == []
    assert results == [BOOTSTRAP_SERVICES] * BOOTSTRAP_THREADS
    assert [path.name for path in tmp_path.iterdir()] == [cache_file.name]
    stored = json.loads(cache_file.read_text(encoding="utf-8"))
    assert stored["services"] == BOOTSTRAP_SERVICES
    assert stored["_etag"] == '"stamp"'
    assert isinstance(stored["_cached_at"], float)

    refreshed = _large_bootstrap_payload(marker="refreshed")
    big_opener = Recorder(_bootstrap_response(refreshed, etag='"refreshed"'))
    services = rdap.load_bootstrap(
        "domain",
        cache_dir=tmp_path,
        url=BOOTSTRAP_URL,
        opener=big_opener,
        force_refresh=True,
    )

    assert services == refreshed
    assert big_opener.urls == [BOOTSTRAP_URL]
    # A private temp renamed into place: no leftover, and the file is a complete
    # document rather than the half of it a truncating writer would leave behind.
    assert list(tmp_path.glob("*.tmp")) == []
    assert [path.name for path in tmp_path.iterdir()] == [cache_file.name]
    assert json.loads(cache_file.read_text(encoding="utf-8"))["services"] == refreshed


def test_bootstrap_warm_cache_costs_no_fetch(tmp_path):
    recorder = Recorder(_bootstrap_response(BOOTSTRAP_SERVICES, etag='"warm"'))

    first = rdap.load_bootstrap(
        "domain",
        cache_dir=tmp_path,
        url=BOOTSTRAP_URL,
        opener=recorder,
        max_age_seconds=3600,
    )

    assert first == BOOTSTRAP_SERVICES
    assert recorder.urls == [BOOTSTRAP_URL]

    warmer = Recorder(
        _bootstrap_response(_large_bootstrap_payload(marker="newer"), etag='"newer"')
    )
    second = rdap.load_bootstrap(
        "domain",
        cache_dir=tmp_path,
        url=BOOTSTRAP_URL,
        opener=warmer,
        max_age_seconds=3600,
    )

    assert warmer.urls == []
    assert second == BOOTSTRAP_SERVICES
