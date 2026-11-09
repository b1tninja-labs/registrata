"""RFC 2167 transcript corpus: structure, round-trips, and the failure contract.

Fixtures live in ``tests/fixtures/rwhois/`` as CRLF-terminated latin-1 transcripts
(RFC 2167 section 3.1.9 defines an 8-bit protocol over crlf-terminated lines) and
``manifest.json`` holds one entry per transcript with the expectations asserted here.

Cases are synthesized from the RFC grammar and several lines are quoted verbatim from
RFC 2167 examples. They are not live captures: every manifest entry carries
``"recorded": false`` so real server recordings can be added later alongside them.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from registrata.banner import parse_banner, serialize_banner
from registrata.capabilities import (
    Capability,
    decode_capability_id,
    encode_capability_id,
)
from registrata.errors import (
    RwhoisError,
    RwhoisParseError,
    RwhoisProtocolError,
    error_from_code,
    format_error_line,
    parse_error_line,
)
from registrata.protocol import (
    _PREFIXES,
    parse_directive_response,
    parse_query_result,
    parse_response,
)
from registrata.records import (
    AttributeLine,
    ObjectRecord,
    Referral,
    parse_referral_line,
)
from registrata.wire import LINE_ENCODING, LineReader

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures" / "rwhois"
MANIFEST = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
CASES: dict[str, dict] = {case["id"]: case for case in MANIFEST["cases"]}

VALID_IDS = sorted(cid for cid, c in CASES.items() if c["kind"] == "valid")
MALFORMED_IDS = sorted(cid for cid, c in CASES.items() if c["kind"] == "malformed")
WIRE_IDS = sorted(cid for cid, c in CASES.items() if c["kind"] == "wire")
ROUNTRIP_IDS = sorted(cid for cid, c in CASES.items() if c.get("roundtrip"))

EXCEPTIONS = {
    "RwhoisParseError": RwhoisParseError,
    "RwhoisProtocolError": RwhoisProtocolError,
}
PARSERS = {
    "query": parse_query_result,
    "response": parse_response,
    "directive": parse_directive_response,
}

KNOWN_KEYS = {
    "attributes",
    "attribute_count",
    "attribute_types",
    "auth_area",
    "banner_best_version",
    "banner_capabilities",
    "banner_host",
    "banner_implementation",
    "banner_versions",
    "banners",
    "class_descriptions",
    "class_names",
    "class_versions",
    "decoded_exact",
    "decoded_prefix",
    "directive_groups",
    "directive_names",
    "display_groups",
    "domain_names",
    "error_class",
    "error_code",
    "error_text",
    "info_messages",
    "max_line_bytes",
    "object_class",
    "objects",
    "other_lines",
    "ok",
    "raises",
    "reason",
    "record_id",
    "referral_keys",
    "referrals",
    "register_pairs",
    "schema_attributes",
    "schema_classes",
    "schema_groups",
    "soa_fields",
    "soa_records",
    "status",
    "xfer_objects",
}


def raw(case: dict) -> bytes:
    return (FIXTURE_DIR / case["file"]).read_bytes()


def transcript(case: dict) -> list[str]:
    """Fixture bytes -> wire lines, exactly as a socket would deliver them."""
    text = raw(case).decode(LINE_ENCODING)
    assert text.endswith("\r\n"), f"{case['id']}: transcript must end with crlf"
    return text[:-2].split("\r\n")


def loose_lines(case: dict) -> list[str]:
    """Fixture lines without the crlf contract check.

    Wire fixtures deliberately hold non-crlf and oversized payloads to exercise the
    reader, so they cannot be asserted to be well-formed transcripts.
    """
    return raw(case).decode(LINE_ENCODING).splitlines()


def parse_case(case: dict):
    return PARSERS[case["parser"]](transcript(case))


def first_object(result):
    return (result.objects or result.xfer_objects)[0]


class _FakeSocket:
    """Minimal recv() source so wire limits can be exercised without a real socket."""

    def __init__(self, payload: bytes, chunk: int = 4096) -> None:
        self._payload = payload
        self._chunk = chunk

    def recv(self, size: int) -> bytes:
        take = min(size, self._chunk)
        chunk, self._payload = self._payload[:take], self._payload[take:]
        return chunk

    def close(self) -> None:
        self._payload = b""


def _check_structure(case_id: str, result, expect: dict) -> None:
    def eq(label: str, actual, wanted) -> None:
        assert actual == wanted, (
            f"{case_id}: {label} == {actual!r}, expected {wanted!r}"
        )

    if "ok" in expect:
        eq("ok", result.ok, expect["ok"])
    if "objects" in expect:
        eq("object count", len(result.objects), expect["objects"])
    if "xfer_objects" in expect:
        eq("xfer object count", len(result.xfer_objects), expect["xfer_objects"])
    if "referrals" in expect:
        eq("referral count", len(result.referrals), expect["referrals"])
    if "referral_keys" in expect:
        eq(
            "referral keys",
            [list(ref.key) for ref in result.referrals],
            expect["referral_keys"],
        )
    if "banners" in expect:
        eq("banner count", len(result.banners), expect["banners"])
    if "other_lines" in expect:
        eq("unmatched lines", len(result.other_lines), expect["other_lines"])
    if "display_groups" in expect:
        eq("display groups", len(result.display_groups), expect["display_groups"])
    if "register_pairs" in expect:
        eq("register pairs", dict(result.register), expect["register_pairs"])
    if "status" in expect:
        for key, value in expect["status"].items():
            eq(f"status[{key}]", result.status_dict.get(key), value)
    if "info_messages" in expect:
        eq("info messages", result.info_messages, expect["info_messages"])
    if "error_code" in expect:
        eq("error code", result.error_code, expect["error_code"])
    if "error_text" in expect:
        eq("error text", result.error_text, expect["error_text"])
    if "error_class" in expect:
        eq(
            "mapped error",
            type(error_from_code(result.error_code)).__name__,
            expect["error_class"],
        )
        with pytest.raises(RwhoisError) as excinfo:
            result.raise_for_error()
        eq("raised error", type(excinfo.value).__name__, expect["error_class"])
        eq("raised code", excinfo.value.code, result.error_code)
    if "soa_records" in expect:
        eq("soa records", len(result.soa), expect["soa_records"])
    if "soa_fields" in expect:
        record = result.soa[0]
        for key, value in expect["soa_fields"].items():
            eq(f"soa[{key}]", str(getattr(record, key.replace("-", "_"))), value)
    if "schema_groups" in expect:
        eq("schema groups", len(result.schema_groups), expect["schema_groups"])
    if "schema_classes" in expect:
        eq(
            "schema classes",
            [cls.class_name for cls in result.schema_classes],
            expect["schema_classes"],
        )
    if "schema_attributes" in expect:
        names = [attr.name for cls in result.schema_classes for attr in cls.attributes]
        eq("schema attributes", names, expect["schema_attributes"])
    if "class_names" in expect:
        eq(
            "class names",
            [cls.class_name for cls in result.class_classes],
            expect["class_names"],
        )
    if "class_descriptions" in expect:
        described = {cls.class_name: cls.description for cls in result.class_classes}
        for key, value in expect["class_descriptions"].items():
            eq(f"class[{key}].description", described.get(key), value)
    if "class_versions" in expect:
        versions = {cls.class_name: cls.version for cls in result.class_classes}
        for key, value in expect["class_versions"].items():
            eq(f"class[{key}].version", versions.get(key), value)
    if "directive_groups" in expect:
        eq("directive groups", len(result.directive_groups), expect["directive_groups"])
    if "directive_names" in expect:
        eq(
            "directive names",
            [group.get("directive") for group in result.directive_groups],
            expect["directive_names"],
        )

    object_keys = (
        "object_class",
        "attribute_count",
        "attributes",
        "attribute_types",
        "record_id",
        "auth_area",
    )
    if any(key in expect for key in object_keys):
        obj = first_object(result)
        if "object_class" in expect:
            eq("object class", obj.class_name, expect["object_class"])
        if "attribute_count" in expect:
            eq("attribute count", len(obj.attributes), expect["attribute_count"])
        if "attributes" in expect:
            for name, values in expect["attributes"].items():
                eq(f"attribute[{name}]", obj.getall(name), values)
        if "attribute_types" in expect:
            seen: dict[str, str] = {}
            for attr in obj.attributes:
                seen.setdefault(attr.name, attr.type)
            for name, type_char in expect["attribute_types"].items():
                eq(f"attribute type[{name}]", seen.get(name), type_char)
        if "record_id" in expect:
            eq("ID attribute", obj.get("ID"), expect["record_id"])
        if "auth_area" in expect:
            eq("Auth-Area attribute", obj.get("Auth-Area"), expect["auth_area"])

    if "domain_names" in expect:
        eq(
            "Domain-Name list",
            [obj.get("Domain-Name") for obj in result.objects],
            expect["domain_names"],
        )

    if result.banners:
        banner = result.banners[0]
        if "banner_host" in expect:
            eq("banner host", banner.host, expect["banner_host"])
        if "banner_versions" in expect:
            eq(
                "banner versions",
                list(banner.version_numbers),
                expect["banner_versions"],
            )
        if "banner_best_version" in expect:
            eq(
                "banner best version",
                banner.best_version().name,
                expect["banner_best_version"],
            )
        if "banner_implementation" in expect:
            eq(
                "banner implementation",
                banner.implementation,
                expect["banner_implementation"],
            )
        if "banner_capabilities" in expect:
            for name in expect["banner_capabilities"]:
                assert Capability[name] in banner.capabilities, (
                    f"{case_id}: capability {name} not advertised; "
                    f"got {sorted(str(cap) for cap in banner.capabilities)}"
                )


def test_manifest_is_self_consistent() -> None:
    for case in MANIFEST["cases"]:
        assert (FIXTURE_DIR / case["file"]).is_file(), (
            f"{case['id']}: missing transcript {case['file']}"
        )
    referenced = {case["file"] for case in MANIFEST["cases"]}
    on_disk = {
        p.relative_to(FIXTURE_DIR).as_posix() for p in FIXTURE_DIR.rglob("*.txt")
    }
    assert on_disk == referenced, (
        f"orphan transcripts: {sorted(on_disk - referenced)}; "
        f"manifest entries without files: {sorted(referenced - on_disk)}"
    )


def test_manifest_uses_only_supported_expectation_keys() -> None:
    for case in MANIFEST["cases"]:
        unknown = set(case["expect"]) - KNOWN_KEYS
        assert not unknown, (
            f"{case['id']}: unsupported expectation keys {sorted(unknown)}"
        )


def test_corpus_exercises_every_recognised_line_prefix() -> None:
    """Guard: teaching the parser a new line prefix must come with a fixture."""
    covered: set[str] = set()
    for case in MANIFEST["cases"]:
        for line in loose_lines(case):
            covered.update(prefix for prefix in _PREFIXES if line.startswith(prefix))
    assert covered == set(_PREFIXES), (
        f"corpus never exercises {sorted(set(_PREFIXES) - covered)}"
    )


def test_corpus_has_both_valid_and_malformed_populations() -> None:
    assert len(VALID_IDS) >= 10, VALID_IDS
    assert len(MALFORMED_IDS) >= 15, MALFORMED_IDS
    assert len(WIRE_IDS) >= 3, WIRE_IDS


@pytest.mark.parametrize("case_id", VALID_IDS)
def test_valid_transcript_structure(case_id: str) -> None:
    case = CASES[case_id]
    _check_structure(case_id, parse_case(case), case["expect"])


def _roundtrip(case_id: str, kind: str) -> None:
    case = CASES[case_id]
    source = transcript(case)

    if kind == "banner":
        for line in [item for item in source if item.startswith("%rwhois")]:
            banner = parse_banner(line)
            rendered = serialize_banner(
                banner.versions, banner.host, implementation=banner.implementation
            )
            assert rendered == line, (
                f"{case_id}: banner round-trip {rendered!r} != {line!r}"
            )
        return

    if kind == "objects":
        result = parse_case(case)
        for obj in result.objects:
            again = ObjectRecord.from_lines(obj.to_wire_lines())
            before = [(attr.name, attr.value, attr.type) for attr in obj.attributes]
            after = [(attr.name, attr.value, attr.type) for attr in again.attributes]
            assert after == before, (
                f"{case_id}: attribute round-trip {after} != {before}"
            )
            assert again.class_name == obj.class_name, (
                f"{case_id}: object class round-trip"
            )
        return

    if kind == "referrals":
        result = parse_case(case)
        original = [line for line in source if line.startswith("%referral")]
        assert [ref.to_wire() for ref in result.referrals] == original, (
            f"{case_id}: referral round-trip"
        )
        for ref in result.referrals:
            assert parse_referral_line(ref.to_wire()) == ref, (
                f"{case_id}: referral line reparse"
            )
            assert Referral.parse_url(ref.url) == ref, (
                f"{case_id}: referral url reparse"
            )
        return

    if kind == "error_line":
        line = next(item for item in source if item.startswith("%error"))
        code, text = parse_error_line(line)
        assert format_error_line(code, text) == line, (
            f"{case_id}: error line round-trip"
        )
        return

    if kind == "status":
        result = parse_case(case)
        original = [line for line in source if line.startswith("%status")]
        rendered = [f"%status {key}:{value}" for key, value in result.status]
        assert rendered == original, (
            f"{case_id}: status round-trip {rendered} != {original}"
        )
        return

    pytest.fail(f"{case_id}: unsupported roundtrip kind {kind!r}")


@pytest.mark.parametrize(
    "case_id,kind",
    [(cid, kind) for cid in ROUNTRIP_IDS for kind in CASES[cid]["roundtrip"]],
)
def test_transcript_roundtrip(case_id: str, kind: str) -> None:
    _roundtrip(case_id, kind)


@pytest.mark.parametrize(
    "capability_id", ["00ffff:00", "003fff:00", "000100:00", "ffffff:ff"]
)
def test_capability_id_roundtrip(capability_id: str) -> None:
    assert encode_capability_id(decode_capability_id(capability_id)) == capability_id


@pytest.mark.parametrize("case_id", MALFORMED_IDS)
def test_malformed_transcript_raises_documented_error(case_id: str) -> None:
    case = CASES[case_id]
    expected = EXCEPTIONS[case["expect"]["raises"]]
    with pytest.raises(expected) as excinfo:
        parse_case(case)
    assert case["expect"]["reason"] in str(excinfo.value), (
        f"{case_id}: message {str(excinfo.value)!r} lacks {case['expect']['reason']!r}"
    )


@pytest.mark.parametrize("case_id", MALFORMED_IDS)
def test_malformed_transcript_never_leaks_builtin_errors(case_id: str) -> None:
    """RwhoisError is the documented contract a hostile server may never escape.

    A builtin TypeError/ValueError would surface as HTTP 500 through the gateway and
    crash library callers that correctly catch only RwhoisError.
    """
    try:
        parse_case(CASES[case_id])
    except RwhoisError:
        return
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{case_id}: leaked builtin {type(exc).__name__}: {exc}")
    pytest.fail(f"{case_id}: accepted a transcript that must be rejected")


@pytest.mark.parametrize("case_id", WIRE_IDS)
def test_wire_transcripts(case_id: str) -> None:
    case = CASES[case_id]
    expect = case["expect"]
    reader = LineReader(
        _FakeSocket(raw(case)),
        buffer_size=4096,
        max_line_bytes=int(expect.get("max_line_bytes", 1_048_576)),
    )
    try:
        if "raises" in expect:
            with pytest.raises(EXCEPTIONS[expect["raises"]]) as excinfo:
                reader.readline()
            assert expect["reason"] in str(excinfo.value), (
                f"{case_id}: {excinfo.value!r}"
            )
            return
        line = reader.readline()
        if "decoded_exact" in expect:
            assert line == expect["decoded_exact"], f"{case_id}: {line!r}"
        if "decoded_prefix" in expect:
            assert line == expect["decoded_prefix"], f"{case_id}: {line!r}"
    finally:
        reader.close()


def test_explicit_text_type_normalizes_to_the_bare_wire_form() -> None:
    """``;T`` is RFC 2167's default attribute type, so it is not re-emitted.

    ``person:First-Name;T:Jane`` and ``person:First-Name:Jane`` are the same attribute,
    which is why the object round-trip compares re-parsed semantics rather than bytes.
    ``;I`` and ``;S`` have no default and must survive byte-for-byte.
    """
    assert (
        AttributeLine("First-Name", "Jane", "T").to_wire("person")
        == "person:First-Name:Jane"
    )
    assert (
        AttributeLine("Numeric-Id", "42", "I").to_wire("person")
        == "person:Numeric-Id;I:42"
    )
    assert (
        AttributeLine("Tag-List", "a,b", "S").to_wire("person")
        == "person:Tag-List;S:a,b"
    )
    assert AttributeLine.parse("person:First-Name;T:Jane")[1] == AttributeLine(
        "First-Name", "Jane", "T"
    )
    assert AttributeLine.parse("person:First-Name:Jane")[1] == AttributeLine(
        "First-Name", "Jane", "T"
    )
