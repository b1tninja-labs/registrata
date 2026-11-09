"""RFC 2167 Appendix B conformance gate over the transcript corpus.

Three claims are checked here, and the third is the reason this file exists.

1. **The transcription is faithful.** ``rwhois_abnf_match.selfcheck()`` pins every
   pattern against values copied out of the RFC (and against the near-misses a looser
   pattern would swallow), and every leaf production is asserted to have a pattern, so a
   production cannot be added to the inventory and quietly never matched.
2. **Grammar-valid is accepted; grammar-invalid escapes only as ``RwhoisError``.**
   Validity is checked against values the grammar itself supplies, and invalidity is
   generated mechanically from grammar-valid transcripts (drop a required space, strip a
   leading ``%``, double a separator, truncate at each line boundary, inject CR/LF/NUL,
   overflow a numeric bound, substitute a non-dns character) rather than hand-written, so
   the negative half grows with the fixtures instead of drifting from them.
3. **Every production has a test.** Each production in ``rwhois_grammar.PRODUCTIONS``
   must be named by at least one corpus case. This is what turns "all ABNF constructs
   have tests" from a sentence in a document into a gate that fails by naming the
   constructs that lost their test.

Coverage is read from exactly one place: the ``"abnf"`` key on a manifest case. It is
never inferred from text that happens to occur in a transcript, because a fixture that
mentions ``%soa`` anywhere would then be able to claim ``soa-dir``. The gate function is
pure and takes the case list as an argument precisely so that this discipline is itself
tested (see ``test_coverage_comes_from_case_claims_and_never_from_transcript_text``).

Outcome model for a grammar-invalid mutation, per docs/compliance.md:

- raises an ``RwhoisError`` subclass -> strict, asserted as such;
- accepted -> leniency. Not automatically a defect, so it is pinned exactly as observed
  in ``DOCUMENTED_LENICIENCY`` with a one-line reason, which keeps it from changing
  silently and hands the keep-or-tighten call to the compliance doc;
- raises a builtin -> always a failure, asserted everywhere.

Deterministic throughout: no sockets, no sleeps, no clock reads. Where a hang had to be
made testable it is bounded by an executed-line budget, which is a step count rather than
a timeout (see ``_run_within_line_budget``).
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Callable

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# The tools/ modules are standalone scripts, not an installed package, so they are located
# by path the same way tests locate the fixture directory.
import rwhois_abnf_match  # noqa: E402
import rwhois_grammar  # noqa: E402

from registrata.banner import Version, parse_banner, serialize_banner  # noqa: E402
from registrata.capabilities import decode_capability_id, encode_capability_id  # noqa: E402
from registrata.errors import (  # noqa: E402
    InvalidQuerySyntax,
    RwhoisError,
    RwhoisParseError,
    parse_error_line,
)
from registrata.protocol import (  # noqa: E402
    _PREFIXES,
    _parse_grouped_simple,
    _parse_grouped_two_level,
    _parse_xfer_group,
    parse_directive_response,
    parse_query_result,
    parse_response,
)
from registrata.query import parse_query, search_values  # noqa: E402
from registrata.records import (  # noqa: E402
    AttributeLine,
    ObjectRecord,
    Referral,
    parse_referral_line,
)
from registrata.soa import format_timestamp, parse_timestamp  # noqa: E402
from registrata.wire import LINE_ENCODING, LineReader, encode_line  # noqa: E402

FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "rwhois"
MANIFEST = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
CASES: dict[str, dict] = {case["id"]: case for case in MANIFEST["cases"]}
VALID_IDS = sorted(cid for cid, case in CASES.items() if case["kind"] == "valid")

PRODUCTIONS = rwhois_grammar.PRODUCTIONS
PATTERNS = rwhois_abnf_match.PATTERNS
PARSERS: dict[str, Callable[[list[str]], object]] = {
    "query": parse_query_result,
    "response": parse_response,
    "directive": parse_directive_response,
}

# ``parse_response`` advances its cursor by the number of lines a grouped-line handler
# reports consuming (protocol.py: ``i += j``). For these five prefixes a line that starts
# with the prefix but carries no space after it comes back as "0 lines consumed", so the
# cursor never moves. Those mutants are routed to the loop-freedom tests rather than the
# transcript battery: feeding one to ``parse_response`` today does not raise, it never
# returns, and a hanging suite is worse than a failing one.
GROUPED_PREFIXES = ("%class", "%directive", "%display", "%schema", "%xfer")
_GROUPED_HANDLERS: dict[str, Callable[[list[str], str], tuple[object, int]]] = {
    "%class": _parse_grouped_two_level,
    "%schema": _parse_grouped_two_level,
    "%directive": _parse_grouped_simple,
    "%display": _parse_grouped_simple,
    "%xfer": lambda lines, _prefix: _parse_xfer_group(lines),
}


def transcript_lines(case: dict) -> list[str]:
    """Fixture bytes -> wire lines, matching the corpus test's crlf contract."""
    text = (FIXTURE_DIR / case["file"]).read_bytes().decode(LINE_ENCODING)
    assert text.endswith("\r\n"), f"{case['id']}: transcript must end with crlf"
    return text[:-2].split("\r\n")


def _lines(case_id: str) -> list[str]:
    return transcript_lines(CASES[case_id])


def is_query_line(line: str) -> bool:
    """True when ``line`` is one instance of ``query-line`` as registrata reads it.

    The doubled-separator mutation is defined on ``query-line`` only, so the membership
    test is the parser's own: a line the parser accepts as an attribute line is a line the
    mutation can meaningfully corrupt.
    """
    if not line or line.startswith("%"):
        return False
    try:
        AttributeLine.parse(line)
    except RwhoisError:
        return False
    return True


def _drop_space_after_keyword(line: str) -> str:
    """Delete the single space a ``%keyword`` line requires after its keyword."""
    return line.replace(" ", "", 1)


def _is_hang_prone(line: str) -> bool:
    """True when ``line`` would make a grouped handler report zero lines consumed."""
    return any(
        line.startswith(prefix) and line != prefix and not line.startswith(prefix + " ")
        for prefix in GROUPED_PREFIXES
    )


# A mutant is (case_id, mutated line index, parser name, mutated lines). For truncation
# mutants the index is the cut point, so the id still names what changed.
Mutant = tuple[str, int, str, list[str]]


def _truncate_mutants() -> list[Mutant]:
    out: list[Mutant] = []
    for case_id in VALID_IDS:
        lines = _lines(case_id)
        for cut in range(len(lines)):
            out.append((case_id, cut, CASES[case_id]["parser"], lines[:cut]))
    return out


def _line_mutants(
    transform: Callable[[str], str], *, selector: Callable[[str], bool]
) -> list[Mutant]:
    """Apply ``transform`` to every line the selector accepts, one mutant per line."""
    out: list[Mutant] = []
    for case_id in VALID_IDS:
        lines = _lines(case_id)
        for index, line in enumerate(lines):
            if not selector(line):
                continue
            mutated = transform(line)
            if mutated == line:
                continue
            replacement = list(lines)
            replacement[index] = mutated
            out.append((case_id, index, CASES[case_id]["parser"], replacement))
    return out


def _append_to_value(suffix: str) -> Callable[[str], str]:
    """Append ``suffix`` to an attribute line, which lands inside attribute-value.

    Appending rather than splicing is deliberate: in ``class:name[:;type]:value`` the value
    is everything after the attribute-name separator, so anything appended ends up inside
    ``attribute-value`` by construction rather than by inspection, even for a value that
    itself contains colons such as ``domain:Statistic:Source:ARIN``.
    """
    return lambda line: line + suffix


TRUNCATE_MUTANTS = _truncate_mutants()
STRIP_PERCENT_MUTANTS = _line_mutants(
    lambda line: line[1:], selector=lambda line: line.startswith("%")
)
DOUBLE_CLASS_COLON_MUTANTS = _line_mutants(
    lambda line: line.replace(":", "::", 1), selector=is_query_line
)
CR_IN_VALUE_MUTANTS = _line_mutants(_append_to_value("\rE"), selector=is_query_line)
LF_IN_VALUE_MUTANTS = _line_mutants(_append_to_value("\nE"), selector=is_query_line)
NUL_IN_VALUE_MUTANTS = _line_mutants(_append_to_value("\x00E"), selector=is_query_line)

# Dropping the required space is the one family that must be partitioned before it can be
# run: five prefixes hang the driver instead of raising (see GROUPED_PREFIXES). The
# hang-prone half is still enumerated, and the loop-freedom tests below are the assertion
# that covers each of those mutants by prefix.
DROP_SPACE_MUTANTS = _line_mutants(
    _drop_space_after_keyword,
    selector=lambda line: (
        line.startswith("%")
        and " " in line
        and not _is_hang_prone(_drop_space_after_keyword(line))
    ),
)
DROP_SPACE_HANG_PRONE: list[tuple[str, int, str]] = [
    (case_id, index, _drop_space_after_keyword(line))
    for case_id in VALID_IDS
    for index, line in enumerate(_lines(case_id))
    if line.startswith("%")
    and " " in line
    and _is_hang_prone(_drop_space_after_keyword(line))
]

ALL_MUTANTS: list[Mutant] = [
    *TRUNCATE_MUTANTS,
    *STRIP_PERCENT_MUTANTS,
    *DOUBLE_CLASS_COLON_MUTANTS,
    *DROP_SPACE_MUTANTS,
    *CR_IN_VALUE_MUTANTS,
    *LF_IN_VALUE_MUTANTS,
    *NUL_IN_VALUE_MUTANTS,
]


def mutant_id(mutant: Mutant) -> str:
    case_id, index, _, _ = mutant
    return f"{case_id}@{index}"


def accepts(callable_: Callable[[], object]) -> bool:
    """True when calling ``callable_`` does not raise; used to pin leniency."""
    try:
        callable_()
    except RwhoisError:
        return False
    return True


def soa_record(lines: list[str]):
    """The single SOA record in ``lines``, for leniency assertions."""
    return parse_response([*lines, "%ok"]).soa[0]


class MemorySocket:
    """Stand-in for a socket so the wire reader can be exercised without a connection."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def recv(self, _size: int) -> bytes:
        chunk, self._payload = self._payload[:64], self._payload[64:]
        return chunk

    def close(self) -> None:
        self._payload = b""


def reader_first_line(payload: bytes) -> str:
    reader = LineReader(MemorySocket(payload))
    try:
        return reader.readline()
    finally:
        reader.close()


# Inputs the ABNF excludes which registrata accepts. Each entry pairs the grammar's own
# verdict with the library's, so an entry fails if either side moves: the grammar claim
# cannot rot into "we never checked", and a silent tightening has to update this list
# rather than change behaviour unnoticed. ``reason`` is the one line the compliance doc
# needs in order to keep or drop the tolerance.
LENIENT_BEHAVIOURS: list[tuple[str, Callable[[], bool], str]] = [
    (
        "info-block-terminator-mutated",
        lambda: (
            (result := parse_response(["%info on", "a notice", "%infooff", "%ok"])).ok
            and "%infooff" in result.info_messages
        ),
        "info-response's body is *(*any-char crlf), so a line reading '%infooff' is legal "
        "text rather than a malformed keyword; the block simply never closes and the parser "
        "ends it at the response terminator, keeping what it gathered. The asymmetry with "
        "the strict '%info on' start is real: the start is a keyword line, the terminator "
        "position is inside free text.",
    ),
    (
        "nul-in-attribute-value",
        lambda: (
            not rwhois_abnf_match.matches("any-char", "\x00")
            and accepts(lambda: AttributeLine("Domain-Name", "A\x00B"))
        ),
        "any-char is octets 1..255, so NUL is outside the alphabet entirely; "
        "records.validate_no_line_break guards CR and LF only, so a NUL survives into the "
        "object and back out to the wire.",
    ),
    (
        "underscore-in-host-name",
        lambda: (
            not rwhois_abnf_match.matches("host-name", "bad_host.example.net")
            and Referral.parse_url(
                "rwhois://bad_host.example.net:4321/auth-area=example.net"
            ).host
            == "bad_host.example.net"
        ),
        "host-name is built from dns-char, which has no underscore. Tolerance is "
        "deliberate: refusing a slightly odd referral URL would break resolution "
        "(docs/compliance.md, 'non-dns characters in host names').",
    ),
    (
        "soa-primary-port-beyond-host-port-bound",
        lambda: (
            not rwhois_abnf_match.matches("host-port", "h.example.net:432100")
            and soa_record(
                [
                    "%soa authority:example.net",
                    "%soa primary:h.example.net:432100",
                    "%soa",
                ]
            ).primary
            == "h.example.net:432100"
        ),
        "host-port is 1*5digit. SOARecord keeps primary verbatim and does not claim "
        "host-port validation, so a 6-digit port passes; the referral path does validate.",
    ),
    (
        "soa-serial-beyond-time-stamp-width",
        lambda: (
            not rwhois_abnf_match.matches("time-stamp", "199611201234550000")
            and soa_record(
                ["%soa authority:example.net", "%soa serial:199611201234550000", "%soa"]
            ).serial
            == "199611201234550000"
        ),
        "time-stamp is exactly 17 digits, but the %soa serial path stores the string, so "
        "only soa.parse_timestamp enforces the width.",
    ),
    (
        "soa-group-absorbs-a-stripped-field-line",
        lambda: (
            '"%soa"' in PRODUCTIONS["soa-line"].abnf
            and (
                soa_record(
                    ["%soa authority:example.net", "soa serial:20240102030405000"]
                ).serial
                == "19700101000000000"
            )
            and parse_response(
                [
                    "%soa authority:example.net",
                    "soa serial:20240102030405000",
                    "%soa",
                    "%ok",
                ]
            ).other_lines
            == []
        ),
        "SOARecord.from_lines skips every line that does not start with %soa, so a "
        "corrupted field line inside a record is defaulted away instead of reported; the "
        "record still claims to be complete.",
    ),
    (
        "space-after-percent-keyword-is-stripped-not-required",
        lambda: (
            accepts(lambda: parse_response(["%statuslimit:20", "%ok"]))
            and accepts(
                lambda: parse_response(["%soaauthority:example.net", "%soa", "%ok"])
            )
            and accepts(lambda: parse_response(["%registerExample-Handle:ON", "%ok"]))
            and accepts(lambda: parse_banner("%rwhoisV-1.5:00ffff:00 host.example.net"))
        ),
        "each of these productions writes `space` into the rule; _split_prefix and "
        "parse_banner strip whitespace after the prefix rather than requiring exactly one.",
    ),
    (
        "double-space-after-referral-keyword",
        lambda: (
            parse_referral_line(
                "%referral  rwhois://h.example.net:4321/auth-area=com"
            ).host
            == "h.example.net"
        ),
        "referral-line is `%referral` space referral-url with one space; the reader "
        "accepts [ \\t]+, which real servers do send.",
    ),
    (
        "uppercase-keyword-literals",
        lambda: (
            parse_query("a.example.net AND b.example.net").to_wire()
            == "a.example.net and b.example.net"
            and parse_response(["%status holdconnect:OFF", "%ok"]).status
            == [("holdconnect", "OFF")]
        ),
        "bin-boolean and on-off are printed lowercase in the ABNF and RFC 2234 2.3 makes "
        "quoted literals case-insensitive, so this is in-grammar; serialize() normalises.",
    ),
    (
        "truncated-transcript-yields-an-incomplete-response",
        lambda: (
            "%ok" not in transcript_lines(CASES["query-domain-object"])[:-1]
            and PRODUCTIONS["rwhois-query-result"].abnf.rstrip().endswith("response")
            and parse_query_result(
                transcript_lines(CASES["query-domain-object"])[:-1]
            ).ok
            is False
        ),
        "every server production ends in `response`, so a transcript cut before its "
        "terminator is not a complete message; the parser returns what arrived with ok "
        "False instead of raising, because incompleteness is signalled by ok.",
    ),
    (
        "stripped-percent-line-becomes-unstructured-text",
        lambda: (
            '"%status"' in PRODUCTIONS["status-line"].abnf
            and parse_response(["status limit:20", "%ok"]).status == []
            and parse_response(["status limit:20", "%ok"]).other_lines
            == ["status limit:20"]
        ),
        "removing the leading % leaves an ordinary text line, which x-response admits "
        "before a terminator; parse_response files it in other_lines instead of raising, "
        "which is how %notify and free-form server chatter already travel.",
    ),
    (
        "bare-lf-ends-a-line-though-the-grammar-defines-crlf",
        lambda: (
            not rwhois_abnf_match.matches("crlf", "\n")
            and rwhois_abnf_match.matches("lf", "\n")
            and reader_first_line(b"%ok\n") == "%ok"
        ),
        "crlf is cr followed by lf, so a lone LF is not a line ending by the grammar; the "
        "reader ends the line there anyway because servers send it and a client waiting for "
        "CR would stall on live data.",
    ),
]

#: Which recorded entry explains the acceptance of each mutation family. An empty tuple is
#: a claim that the family is strict: every mutant must raise.
LENIENT_FAMILIES: dict[str, tuple[str, ...]] = {
    "cr-in-value": (),
    "double-class-colon": (),
    "drop-space": ("space-after-percent-keyword-is-stripped-not-required",),
    "lf-in-value": (),
    "nul-in-value": ("nul-in-attribute-value",),
    "strip-percent": (
        "stripped-percent-line-becomes-unstructured-text",
        "soa-group-absorbs-a-stripped-field-line",
    ),
    "truncate": ("truncated-transcript-yields-an-incomplete-response",),
}

# ---------------------------------------------------------------- grammar inventory --

# The group counts the release gate quotes. Pinning them here means "130 productions" is
# a checked number rather than folklore: a production added to the inventory without a
# test, or dropped from it, changes one of these counts and fails.
EXPECTED_GROUP_COUNTS = {
    "banner": 8,
    "class": 6,
    "directive": 5,
    "display": 5,
    "general": 18,
    "holdconnect": 2,
    "lexical": 12,
    "limit": 2,
    "notify": 3,
    "protocol": 5,
    "query": 7,
    "query-result": 7,
    "quit": 2,
    "register": 10,
    "required": 2,
    "response": 6,
    "schema": 4,
    "security": 9,
    "soa": 4,
    "status": 3,
    "x": 4,
    "xfer": 6,
}

#: Productions whose group is spelled out in characters rather than in other
#: productions, so a recognizer for them is transcribable and its absence is a defect.
LEAF_GROUPS = ("lexical", "general")
LEAF_NAMES = sorted(
    name for name, production in PRODUCTIONS.items() if production.group in LEAF_GROUPS
)


def test_grammar_inventory_has_the_documented_shape() -> None:
    assert len(PRODUCTIONS) == 130, f"inventory holds {len(PRODUCTIONS)} productions"
    counts: dict[str, int] = {}
    for production in PRODUCTIONS.values():
        counts[production.group] = counts.get(production.group, 0) + 1
    assert counts == EXPECTED_GROUP_COUNTS, f"per-group counts changed: {counts}"


def test_every_production_carries_its_abnf_text_and_a_source() -> None:
    for name, production in sorted(PRODUCTIONS.items()):
        assert production.name == name, (
            f"{name}: inventory key and Production.name disagree"
        )
        assert production.abnf.strip(), f"{name}: production has no ABNF text to check"
        assert production.abnf.startswith(f"{name} ="), (
            f"{name}: text {production.abnf!r} is not its own rule"
        )
        assert production.refs, (
            f"{name}: production records no part of the RFC as its source"
        )


def test_abnf_match_selfcheck_is_clean() -> None:
    """The transcription of the grammar cannot rot silently.

    ``selfcheck()`` walks the RFC's own example values plus the near-misses a looser
    pattern would swallow, so an empty list is the statement that the patterns still say
    what the RFC says.
    """
    assert rwhois_abnf_match.selfcheck() == []


@pytest.mark.parametrize("name", LEAF_NAMES)
def test_leaf_production_has_a_pattern(name: str) -> None:
    """A leaf production with no pattern is a production nothing can ever check."""
    assert name in PATTERNS, (
        f"{name} is a {PRODUCTIONS[name].group} production ({PRODUCTIONS[name].abnf!r}) "
        f"but rwhois_abnf_match.PATTERNS has no recognizer for it"
    )


def test_unpatterned_productions_are_all_composites() -> None:
    """Only rules built out of other rules may lack a pattern, and by name.

    ``key-id`` is in this list because RFC 2167 never defines it, which is the one case
    where "no pattern" is not a gap in the transcription.
    """
    unpatterned = set(rwhois_abnf_match.unpatterned_productions())
    leaf_unpatterned = sorted(
        name for name in unpatterned if PRODUCTIONS[name].group in LEAF_GROUPS
    )
    assert not leaf_unpatterned, (
        f"leaf productions without a pattern: {leaf_unpatterned}"
    )
    assert "key-id" in unpatterned, (
        "key-id must stay unpatterned: the RFC gives no syntax for it"
    )


def test_no_pattern_names_something_the_rfc_does_not_define() -> None:
    """A pattern keyed on a name outside the inventory would fabricate coverage."""
    orphans = sorted(set(PATTERNS) - set(PRODUCTIONS))
    assert not orphans, f"patterns for productions that do not exist: {orphans}"


def test_undefined_references_are_recorded_rather_than_invented() -> None:
    assert rwhois_grammar.UNDEFINED_REFERENCES == ("key-id", "email-char")
    assert "not defined" in PRODUCTIONS["key-id"].abnf, PRODUCTIONS["key-id"].abnf
    assert "RFC 822" in PRODUCTIONS["email-char"].abnf, PRODUCTIONS["email-char"].abnf


def test_email_char_is_exercisable_even_though_the_rfc_borrows_its_definition() -> None:
    """``email-char`` is defined by reference, but that reference is transcribable.

    RFC 2167 defers it to RFC 822 and the matcher spells out RFC 822's ``atext`` set, so
    a real address exercises the production. It is therefore expected to be *covered* by
    the corpus rather than exempted from the gate alongside ``key-id``.
    """
    address = "autoreg@internic.net"
    local, _, domain = address.partition("@")
    assert all(rwhois_abnf_match.matches("email-char", char) for char in local), local
    assert rwhois_abnf_match.matches("email", address)
    assert not rwhois_abnf_match.matches("email-char", "@"), (
        "@ is the separator, not an email-char"
    )


def test_any_char_excludes_nul_and_includes_the_rest_of_the_octet_range() -> None:
    """The 1..255 bound is what makes this an 8-bit protocol.

    Octet 0 is outside the range, so NUL is not a value with an inconvenient meaning, it
    is not a value at all. Octets 0x80-0xff are inside it and must survive the library.
    """
    for char in ("\x01", "\x7f", "\xe9", "\xff"):
        assert rwhois_abnf_match.matches("any-char", char), (
            f"{char!r} should be an any-char"
        )
    for char in ("\x00", "\r", "\n"):
        assert not rwhois_abnf_match.matches("any-char", char), (
            f"{char!r} is outside 1..255 minus CR/LF"
        )
    assert AttributeLine("Domain-Name", "Caf\xe9 Example").value == "Caf\xe9 Example"


def test_high_octets_survive_the_wire_encoding() -> None:
    """Fixtures are latin-1 because RFC 2167 3.1.9 makes the protocol 8-bit."""
    assert encode_line("domain:Register-Name:Caf\xe9, Inc.") == (
        "domain:Register-Name:Caf\xe9, Inc.".encode(LINE_ENCODING) + b"\r\n"
    )


# ------------------------------------------------- grammar-valid implies acceptance --


# Each entry maps a production to the registrata function that consumes it, so an ABNF
# value straight from the RFC is put through the parser rather than merely through the
# matcher. ``preserves`` means the function hands the value back unchanged, which is the
# strongest form of "accepted": the parser did not swallow, normalise, or truncate it.
#
# ``direction`` deliberately has no entry. RFC 2167 uses it only inside ``security-dir``,
# and registrata emits security directives rather than parsing them, so no function here
# could accept it. That is a coverage fact the gate is meant to surface, not something to
# paper over with a synthetic call.
def _host_port_of(referral: Referral) -> str:
    """Rebuild the ``host-port`` a Referral was parsed from, for identity assertions."""
    return f"{referral.host}:{referral.port}"


VALIDATORS: dict[str, tuple[str, Callable[[str], object], bool]] = {
    "any-char": (
        "registrata.records.AttributeLine",
        lambda v: AttributeLine("Domain-Name", f"x{v}y").value[1:-1],
        True,
    ),
    "attribute-name": (
        "registrata.records.AttributeLine",
        lambda v: AttributeLine(v, "value").name,
        True,
    ),
    "attribute-value": (
        "registrata.records.AttributeLine",
        lambda v: AttributeLine("Domain-Name", v).value,
        True,
    ),
    "authority-area": (
        "registrata.records.Referral",
        lambda v: Referral("rwhois.example.net", 4321, v).auth_area,
        True,
    ),
    "bin-boolean": (
        "registrata.query.parse_query",
        lambda v: parse_query(f"a.example.net {v} b.example.net").expression.operation,
        True,
    ),
    "capability-id": (
        "registrata.capabilities",
        lambda v: encode_capability_id(decode_capability_id(v)),
        True,
    ),
    "class-name": (
        "registrata.records.ObjectRecord",
        lambda v: ObjectRecord(v).class_name,
        True,
    ),
    "dns-char": (
        "registrata.records.Referral",
        lambda v: Referral(f"h{v}.example.net", 4321, "com").host[1],
        True,
    ),
    "email": (
        "registrata.soa.SOARecord",
        lambda v: (
            soa_record(
                ["%soa authority:example.net", f"%soa admin-contact:{v}"]
            ).admin_contact
        ),
        True,
    ),
    "error-code": (
        "registrata.errors.parse_error_line",
        lambda v: parse_error_line(f"%error {v} Diagnostic")[0],
        False,
    ),
    "error-response": (
        "registrata.errors.parse_error_line",
        lambda v: parse_error_line(v),
        False,
    ),
    "extra-id": (
        "registrata.capabilities.decode_capability_id",
        lambda v: decode_capability_id(f"00ffff:{v}"),
        False,
    ),
    # encode_capability_id normalises to lowercase hex, which is still a capability-id
    # (capability-id admits A-F per its own rule and RFC 2167 3.1.9 examples print the
    # response-id in lowercase), so this entry claims acceptance, not byte identity.
    "hex-digit": (
        "registrata.capabilities",
        lambda v: encode_capability_id(decode_capability_id(f"0000{v}0:00")),
        False,
    ),
    "host-name": (
        "registrata.records.Referral",
        lambda v: Referral(v, 4321, "example.net").host,
        True,
    ),
    "host-port": (
        "registrata.records.Referral",
        lambda v: _host_port_of(
            Referral.parse_url(f"rwhois://{v}/auth-area=example.net")
        ),
        True,
    ),
    "id-char": (
        "registrata.records.AttributeLine",
        lambda v: AttributeLine(v, "value").name,
        True,
    ),
    "ip-address": (
        "registrata.records.Referral",
        lambda v: Referral(v, 4321, "example.net").host,
        True,
    ),
    "object-id": (
        "registrata.protocol.parse_response",
        lambda v: dict(parse_response([f"%register ID:{v}", "%ok"]).register)["ID"],
        True,
    ),
    "ok-response": (
        "registrata.protocol.parse_response",
        lambda v: parse_response([v]).ok,
        False,
    ),
    "on-off": (
        "registrata.protocol.parse_response",
        lambda v: parse_response([f"%status holdconnect:{v}", "%ok"]).status,
        False,
    ),
    "query-char": (
        "registrata.query.parse_query",
        lambda v: parse_query(f"domain={v}").search_values[0],
        True,
    ),
    "response-id": (
        "registrata.capabilities.decode_capability_id",
        lambda v: decode_capability_id(f"{v}:00"),
        False,
    ),
    "serial-number": (
        "registrata.soa.format_timestamp",
        lambda v: format_timestamp(parse_timestamp(v)),
        True,
    ),
    "time-stamp": (
        "registrata.soa.format_timestamp",
        lambda v: format_timestamp(parse_timestamp(v)),
        True,
    ),
    "type-char": (
        "registrata.records.AttributeLine",
        lambda v: AttributeLine("Numeric-Id", "42", v).type,
        True,
    ),
    "version": ("registrata.banner.Version", lambda v: str(Version.parse(v)), True),
    "version-number": (
        "registrata.banner.Version",
        lambda v: Version.parse(v).name,
        True,
    ),
}

#: Productions the matcher holds RFC values for which no registrata function consumes.
#: Kept as data so the gap is readable instead of expressed by absence.
NOT_CONSUMED_BY_REGISTRATA = ("direction",)


def _validated_examples() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for production, values in sorted(rwhois_abnf_match.RFC_EXAMPLES.items()):
        if production in VALIDATORS:
            out.extend((production, value) for value in values)
    return out


@pytest.mark.parametrize(
    "production,value",
    _validated_examples(),
    ids=[f"{p}={v!r}" for p, v in _validated_examples()],
)
def test_abnf_value_from_the_rfc_is_accepted_by_the_library(
    production: str, value: str
) -> None:
    """The RFC's own examples must be accepted by the parser that owns them.

    This is the direction a generator-written corpus cannot check by itself: the value
    comes from the specification text recorded in ``tools/``, not from the code that wrote
    the fixtures, so a generator drifting from the RFC still fails here.
    """
    label, validate, preserves = VALIDATORS[production]
    assert rwhois_abnf_match.matches(production, value), (
        f"{production}: RFC value {value!r} is not an instance of the transcribed pattern, "
        "so the library check below would prove nothing"
    )
    try:
        observed = validate(value)
    except RwhoisError as exc:
        pytest.fail(
            f"{label} rejects the {production} value {value!r} that the ABNF permits: "
            f"{type(exc).__name__}: {exc}"
        )
    if preserves:
        assert observed == value, (
            f"{label} altered the {production} value {value!r} into {observed!r}"
        )


def test_every_rfc_example_is_either_validated_or_accounted_for() -> None:
    """No RFC example may sit in the matcher untested on the library side."""
    unaccounted = sorted(
        set(rwhois_abnf_match.RFC_EXAMPLES)
        - set(VALIDATORS)
        - set(NOT_CONSUMED_BY_REGISTRATA)
    )
    assert not unaccounted, (
        f"RFC examples exist for {unaccounted} but no validator is registered"
    )


def test_validator_table_names_real_productions() -> None:
    stale = sorted(set(VALIDATORS) - set(PRODUCTIONS))
    assert not stale, (
        f"validators registered for productions that do not exist: {stale}"
    )


@pytest.mark.parametrize(
    ("version_list", "host", "implementation"),
    [
        ("V-1.5:00ffff:00", "master.rwhois.net", ""),
        ("V-1.5:00ffff:00", "master.rwhois.net", "Network Solutions V-1.5"),
        (
            "V-1.0:003f00:00,V-1.5:00ffff:00",
            "rwhois.example.net",
            "Example RWhoisd 2.1.4",
        ),
        ("V-1.0", "192.0.2.1", ""),
    ],
)
def test_library_serialised_banner_is_a_rwhois_banner_and_reparses(
    version_list: str, host: str, implementation: str
) -> None:
    """What the library writes must be what the grammar reads, in both directions.

    ``rwhois-banner`` is ``"%rwhois" space version-list space host-name [space
    implementation]``, so the pieces the library emits are asserted against the productions
    that describe them, not merely against the parser that happens to accept them.
    """
    versions = tuple(Version.parse(token) for token in version_list.split(","))
    for token in version_list.split(","):
        assert rwhois_abnf_match.matches("version", token), (
            f"{token!r} is not a version"
        )
    assert rwhois_abnf_match.matches("host-name", host), f"{host!r} is not a host-name"
    if implementation:
        assert rwhois_abnf_match.matches("implementation", implementation)

    line = serialize_banner(versions, host, implementation=implementation)
    assert line.startswith("%rwhois ")
    banner = parse_banner(line)
    assert [str(version) for version in banner.versions] == version_list.split(",")
    assert banner.host == host
    assert banner.implementation == implementation
    assert (
        serialize_banner(
            banner.versions, banner.host, implementation=banner.implementation
        )
        == line
    )


@pytest.mark.parametrize("case_id", VALID_IDS)
def test_grammar_valid_transcript_reaches_a_response(case_id: str) -> None:
    """A valid transcript is accepted by its parser and ends in a response.

    ``response`` is a required tail of every server-side production, so reaching ``%ok``
    or an ``%error`` line is the acceptance claim; a parse that stopped earlier would let a
    client treat a half-message as complete.
    """
    case = CASES[case_id]
    result = PARSERS[case["parser"]](transcript_lines(case))
    assert result.ok or result.error_code is not None, (
        f"{case_id}: parser {case['parser']} never reached the response the ABNF requires"
    )


# --------------------------------------- grammar-invalid implies a documented error --


def parse_mutant(mutant: Mutant) -> object:
    case_id, index, parser_name, lines = mutant
    return PARSERS[parser_name](lines)


def mutant_lines(mutants: list[Mutant]) -> list[str]:
    return [mutant_id(mutant) for mutant in mutants]


@pytest.mark.parametrize("mutant", ALL_MUTANTS, ids=mutant_lines(ALL_MUTANTS))
def test_mutation_never_leaks_a_builtin_exception(mutant: Mutant) -> None:
    """Nothing a hostile server can type may surface as a TypeError or a ValueError.

    Callers, and the HTTP gateway, are written to catch ``RwhoisError``. A builtin escaping
    here is an unhandled crash on attacker-chosen input, whatever else the parser decides to
    do with it, so this assertion runs over every mutant in every family.
    """
    case_id, index, parser_name, lines = mutant
    mutated = lines[index] if index < len(lines) else "<truncated away>"
    try:
        parse_mutant(mutant)
    except RwhoisError:
        return
    except Exception as exc:  # noqa: BLE001 - the whole point is to catch and report it
        pytest.fail(
            f"{case_id} line {index} parsed with {parser_name}: mutated line {mutated!r} "
            f"leaked builtin {type(exc).__name__}: {exc}"
        )


@pytest.mark.parametrize(
    "name,check,reason",
    LENIENT_BEHAVIOURS,
    ids=[entry[0] for entry in LENIENT_BEHAVIOURS],
)
def test_documented_leniency_is_still_the_observed_behaviour(
    name: str, check: Callable[[], bool], reason: str
) -> None:
    """Behaviour that is lenient relative to the ABNF, pinned so it cannot drift quietly.

    Each check asserts the grammar's verdict and the library's verdict together, so a
    failing entry means either the tolerance changed or the claim about the grammar did. The
    entry is a decision to record in docs/compliance.md, not a defect to route around.
    """
    assert check(), f"{name}: leniency no longer behaves as recorded.\n  {reason}"


def test_leniency_names_are_unique_and_every_one_has_a_reason() -> None:
    names = [name for name, _check, _reason in LENIENT_BEHAVIOURS]
    assert len(names) == len(set(names)), f"duplicate leniency entries: {names}"
    for name, _check, reason in LENIENT_BEHAVIOURS:
        assert len(reason) > 40, f"{name}: the recorded reason is too thin to decide on"


def test_leniency_list_covers_every_accepting_mutation_family() -> None:
    """A family whose mutants are accepted must point at an entry that explains why.

    Acceptance is sometimes correct rather than lenient (a line whose ``%`` was stripped is
    unstructured text, which ``x-response`` admits), and sometimes a tolerance the project
    has chosen to keep. Either way it has to be written down next to the family it belongs
    to, so leniency cannot creep in through a new fixture without someone looking at it. A
    family with no accepted mutants must map to nothing, which is what catches a strict
    family quietly going soft.
    """
    families: dict[str, list[Mutant]] = {
        "truncate": TRUNCATE_MUTANTS,
        "strip-percent": STRIP_PERCENT_MUTANTS,
        "double-class-colon": DOUBLE_CLASS_COLON_MUTANTS,
        "drop-space": DROP_SPACE_MUTANTS,
        "cr-in-value": CR_IN_VALUE_MUTANTS,
        "lf-in-value": LF_IN_VALUE_MUTANTS,
        "nul-in-value": NUL_IN_VALUE_MUTANTS,
    }
    recorded = {name for name, _check, _reason in LENIENT_BEHAVIOURS}
    problems: list[str] = []
    for family, mutants in sorted(families.items()):
        accepted = [
            mutant for mutant in mutants if accepts(lambda m=mutant: parse_mutant(m))
        ]
        entries = LENIENT_FAMILIES[family]
        unknown = sorted(set(entries) - recorded)
        if unknown:
            problems.append(f"{family}: names entries that do not exist: {unknown}")
        if accepted and not entries:
            problems.append(
                f"{family}: {len(accepted)} mutants accepted (first: "
                f"{mutant_id(accepted[0])}) but no entry explains the acceptance"
            )
        if not accepted and entries:
            problems.append(f"{family}: no mutant is accepted, so {entries} is stale")
    assert not problems, "\n  ".join(problems)


def _assert_rejected(mutant: Mutant, why: str) -> None:
    case_id, index, parser_name, lines = mutant
    mutated = lines[index] if index < len(lines) else "<truncated away>"
    try:
        parse_mutant(mutant)
    except RwhoisError:
        return
    pytest.fail(
        f"{case_id} line {index} parsed with {parser_name}: {why} for the mutated line "
        f"{mutated!r}, but the parser accepted it"
    )


@pytest.mark.parametrize(
    "mutant", DOUBLE_CLASS_COLON_MUTANTS, ids=mutant_lines(DOUBLE_CLASS_COLON_MUTANTS)
)
def test_doubled_class_separator_is_rejected(mutant: Mutant) -> None:
    """``query-line`` is ``class-name ":" attribute-name ...``, so ``::`` is an empty name.

    Only the separator between class and attribute is doubled, deliberately. Doubling the
    colon before the value instead would leave ``attribute-value`` starting with ``:``,
    which is an ordinary ``any-char``, so that mutation is not invalid at all and asserting
    a rejection there would be asserting a bug.
    """
    _assert_rejected(mutant, "an empty attribute-name is not 1*id-char")


def test_doubled_value_colon_is_grammar_valid_and_so_is_accepted() -> None:
    """The counter-example to the test above, pinned so the distinction survives.

    ``domain:Handle::x`` has attribute-value ``:x``. That is valid, and treating it as
    malformed would be a regression dressed up as strictness.
    """
    assert AttributeLine.parse("domain:Handle::x")[1].value == ":x"
    assert rwhois_abnf_match.matches("attribute-value", ":x")


# A grammar-valid instance of each bounded numeric production plus the values that grow or
# shrink the digit run past the bound the ABNF states, so each input is one keystroke away
# from something a real server sends: error-code to 4 digits and down to 2, host-port up to
# 6, time-stamp to 18 and down to 16. Only fixed-width productions get the shortening case,
# since ``1*5digit`` genuinely does accept 4 digits and asserting otherwise would be wrong.
NUMERIC_BOUNDS: list[tuple[str, str, str, str | None, str, Callable[[str], object]]] = [
    (
        "error-code",
        "230",
        "2301",
        "23",
        "error-code = 3digit",
        lambda value: parse_error_line(f"%error {value} Diagnostic"),
    ),
    (
        "host-port",
        "master.rwhois.net:4321",
        "master.rwhois.net:432100",
        None,
        'host-port = (host-name / ip-address) ":" 1*5digit',
        lambda value: Referral.parse_url(f"rwhois://{value}/auth-area=example.net"),
    ),
    (
        "time-stamp",
        "19961120123455000",
        "199611201234550000",
        "1996112012345500",
        "time-stamp = year month day hour minute second milli-second",
        lambda value: parse_timestamp(value),
    ),
]

_NUMERIC_IDS = [entry[0] for entry in NUMERIC_BOUNDS]


@pytest.mark.parametrize(
    "production,base,overflow,underflow,abnf,consume", NUMERIC_BOUNDS, ids=_NUMERIC_IDS
)
def test_numeric_field_grown_past_its_bound_is_rejected(
    production: str,
    base: str,
    overflow: str,
    underflow: str | None,
    abnf: str,
    consume: Callable[[str], object],
) -> None:
    """One digit past a numeric bound is not a bigger number, it is a different production.

    Both sides are asserted: the grammar stops matching, and the function that reads the
    field says so rather than parsing 432100 as a port or an 18-digit serial as a date.
    Silent acceptance here is how a wrong-looking value becomes a wrong-looking record.
    """
    assert PRODUCTIONS[production].abnf.replace(" ", "") == abnf.replace(" ", ""), (
        f"{production}: the bound asserted here no longer matches the inventory: "
        f"{PRODUCTIONS[production].abnf!r}"
    )
    assert rwhois_abnf_match.matches(production, base), (
        f"{base!r} should be a {production}"
    )

    assert not rwhois_abnf_match.matches(production, overflow), (
        f"{production}: the pattern accepts {overflow!r}, which exceeds its own bound"
    )
    with pytest.raises(RwhoisError):
        consume(overflow)

    if underflow is not None:
        assert not rwhois_abnf_match.matches(production, underflow)
        with pytest.raises(RwhoisError):
            consume(underflow)


def test_non_dns_underscore_in_a_host_name_is_rejected_by_the_grammar_only() -> None:
    """The underscore case, stated as the split it actually is.

    ``dns-char`` has no underscore, so ``under_score.net`` is not a host-name and no
    referral-url built from one is grammar-valid. registrata accepts it on purpose (see
    ``LENIENT_BEHAVIOURS``), so what this pins is that the grammar's verdict stays "invalid"
    while the library's stays "tolerate": an underscore must never be *promoted* to valid by
    the matcher, because that is how a tolerance becomes invisible.
    """
    assert not rwhois_abnf_match.matches("dns-char", "_")
    assert rwhois_abnf_match.matches("id-char", "_"), (
        "id-char does allow it, which is the contrast"
    )
    assert not rwhois_abnf_match.matches("host-name", "under_score.example.net")
    assert accepts(
        lambda: Referral.parse_url(
            "rwhois://under_score.example.net:4321/auth-area=com"
        )
    )


@pytest.mark.parametrize(
    "mutant", CR_IN_VALUE_MUTANTS, ids=mutant_lines(CR_IN_VALUE_MUTANTS)
)
def test_cr_in_attribute_value_is_rejected(mutant: Mutant) -> None:
    """CR ends a line, so it cannot occur inside ``attribute-value = 1*any-char``."""
    _assert_rejected(mutant, "CR is excluded from any-char")


@pytest.mark.parametrize(
    "mutant", LF_IN_VALUE_MUTANTS, ids=mutant_lines(LF_IN_VALUE_MUTANTS)
)
def test_lf_in_attribute_value_is_rejected(mutant: Mutant) -> None:
    """LF ends a line, exactly like CR."""
    _assert_rejected(mutant, "LF is excluded from any-char")


@pytest.mark.parametrize(
    "mutant", NUL_IN_VALUE_MUTANTS, ids=mutant_lines(NUL_IN_VALUE_MUTANTS)
)
def test_nul_in_attribute_value_is_accepted_today_and_recorded_as_leniency(
    mutant: Mutant,
) -> None:
    """NUL is outside ``any-char`` (octets 1..255) yet the value parser only guards CR/LF.

    This pins the tolerance rather than pretending it is a rejection. If the guard is ever
    widened, this test fails and the ``nul-in-attribute-value`` entry in
    ``LENIENT_BEHAVIOURS`` has to be deleted, which is the point: the decision gets made
    twice in the open instead of once by accident.
    """
    assert accepts(lambda: parse_mutant(mutant)), (
        f"{mutant_id(mutant)}: NUL is now rejected; remove the recorded leniency entry "
        "nul-in-attribute-value and note the tightening in docs/compliance.md"
    )


#: Keywords whose line parser validates the keyword/argument boundary, so losing the space
#: is a rejection rather than a tolerance. ``%info`` is here because an info block is only
#: opened by the exact ``%info on`` line; ``%class`` and friends are not here because they
#: are the hang-prone group covered by the loop-freedom tests.
STRICT_KEYWORD_SPACES = ("%error", "%referral", "%info")


def keyword_of(line: str) -> str | None:
    """The ``%keyword`` a line claims, matched by prefix because a mutation may have eaten
    the space that used to delimit it. ``_PREFIXES`` is the parser's own vocabulary, so the
    battery cannot drift from what ``parse_response`` actually recognises.
    """
    for prefix in sorted(_PREFIXES, key=len, reverse=True):
        if line.startswith(prefix):
            return prefix
    return None


def _is_info_terminator(mutant: Mutant) -> bool:
    """Whether this mutant ate the space of the ``%info off`` that *closes* a block.

    That position is not a keyword line in disguise. The block body is ``*(*any-char
    crlf)``, so ``%infooff`` is legal body text and the real consequence is a block that
    never closes. ``_parse_info_block`` then stops the block at the response terminator
    and keeps the messages it gathered, which is what makes a truncated ``%info`` block
    from a live server usable instead of fatal. It is recorded as leniency, in
    ``LENIENT_BEHAVIOURS``, rather than demanded as a rejection.
    """
    return _lines(mutant[0])[mutant[1]] == "%info off"


DROP_SPACE_STRICT_MUTANTS = [
    mutant
    for mutant in DROP_SPACE_MUTANTS
    if keyword_of(mutant[3][mutant[1]]) in STRICT_KEYWORD_SPACES
    and not _is_info_terminator(mutant)
]


@pytest.mark.parametrize(
    "mutant", DROP_SPACE_STRICT_MUTANTS, ids=mutant_lines(DROP_SPACE_STRICT_MUTANTS)
)
def test_dropping_the_space_a_strict_keyword_requires_is_rejected(
    mutant: Mutant,
) -> None:
    """``error-response``, ``referral-line`` and the ``%info on`` start name one ``space``.

    The ``%info off`` terminator is excluded by ``_is_info_terminator``; the closing
    literal sits inside block body text, where the grammar permits anything but CR and LF.
    """
    _assert_rejected(mutant, "the production requires a space after the keyword")


def test_drop_space_battery_covers_both_keyword_classes() -> None:
    """The partition into strict and tolerant keywords is exercised, not assumed.

    If fixtures changed so that one side became empty, the assertions above would be
    checking nothing while still reporting green.
    """
    keywords = {keyword_of(mutant[3][mutant[1]]) for mutant in DROP_SPACE_MUTANTS}
    assert keywords & set(STRICT_KEYWORD_SPACES), (
        f"no strict keyword mutated: {sorted(keywords)}"
    )
    assert keywords - set(STRICT_KEYWORD_SPACES), (
        f"only strict keywords mutated: {sorted(keywords)}"
    )
    assert None not in keywords, (
        f"a mutant line lost its keyword: {sorted(map(str, keywords))}"
    )
    assert DROP_SPACE_HANG_PRONE, (
        "the hang-prone partition is empty, which means either the fixtures lost their "
        "grouped directive lines or the partition predicate stopped matching"
    )


# ------------------------------------------------------------ loop freedom (a hang) --


class LineBudgetExceeded(Exception):
    """Raised inside the traced frame once a parse has executed more lines than allowed."""


#: Executed-line ceiling for the two-line inputs the loop-freedom tests use. A legitimate
#: parse of two lines costs a couple of hundred events (asserted in
#: ``test_line_budget_is_generous_for_a_two_line_parse``), so this is orders of magnitude above
#: what a correct parse of those inputs can spend, and an exceedance means the loop ran, not
#: that the machine was slow.
LINE_BUDGET = 20_000


def run_within_line_budget(
    action: Callable[[], object], budget: int = LINE_BUDGET
) -> int:
    """Run ``action``, raising ``LineBudgetExceeded`` if it executes over ``budget`` lines.

    A step bound rather than a timeout: ``parse_response`` walks a list of strings, so the
    number of lines it executes is a property of the code path and not of the machine, which
    keeps this deterministic. The previous tracer is restored either way so the rest of the
    session (coverage, debuggers, other tests) is untouched.
    """
    executed = [0]

    def tracer(frame, event, _arg):
        if event == "line":
            executed[0] += 1
            if executed[0] > budget:
                raise LineBudgetExceeded(f"parse executed more than {budget} lines")
        return tracer

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        action()
    finally:
        sys.settrace(previous)
    return executed[0]


def test_line_budget_is_generous_for_a_two_line_parse() -> None:
    """Control for the budget above: a legitimate two-line parse costs a tiny fraction of it.

    The hang tests hand ``parse_response`` exactly two lines, so the budget only has to be
    large relative to what two lines cost, and measuring that here keeps the control honest.
    Deliberately not measured over the whole corpus: if the budget were tuned against fixture
    size, a future large transcript would trip it and read as a reported hang.
    """
    costs = []
    for prefix in GROUPED_PREFIXES:
        line = f"{prefix} domain:description:x"
        costs.append(
            run_within_line_budget(lambda line=line: parse_response([line, "%ok"]))
        )
    worst = max(costs)
    assert worst < LINE_BUDGET // 4, (
        f"a legitimate two-line parse used {worst} line events, within 4x of the "
        f"{LINE_BUDGET} budget; raise the budget before trusting a budget failure as a hang"
    )


@pytest.mark.parametrize("prefix", GROUPED_PREFIXES)
def test_grouped_line_handler_consumes_input_it_was_handed(prefix: str) -> None:
    """A handler must never silently report zero lines for the line it was handed.

    ``parse_response`` advances with ``i += j``. When a grouped handler returned ``j = 0``
    for the very line it was called on, the cursor never moved and the parse never
    returned, so zero here is not an off-by-one, it is a client that hangs on data a
    server sent. A line that starts with the prefix but carries no space after it is
    reachable from the drop-the-space mutants in ``DROP_SPACE_HANG_PRONE``.

    The src fix answers that shape by rejecting it, and the guarantee is enforced twice on
    purpose: the handler raises for a glued prefix, and ``parse_response`` refuses to
    advance by zero. Either one alone would leave the other free to reintroduce the hang,
    so a refactor has to preserve both. ``test_hang_prone_drop_space_mutants_are_all_
    prefixed_by_a_tested_grouped_keyword`` is what keeps the diverted mutants accounted
    for while they stay out of the sweep.
    """
    line = f"{prefix}domain:description:never matched"
    handler = _GROUPED_HANDLERS[prefix]
    with pytest.raises(RwhoisParseError):
        handler([line, "%ok"], prefix)


@pytest.mark.parametrize("prefix", GROUPED_PREFIXES)
def test_parse_response_terminates_when_a_grouped_line_loses_its_space(
    prefix: str,
) -> None:
    """The consequence of the test above, observed through the public entry point.

    ``-class``-style lines without their space are what a sloppy or hostile server sends,
    and the documented contract is that anything a server sends raises an ``RwhoisError`` at
    worst. Not returning at all is outside every contract: a client waiting on a parser that
    will not finish has no timeout to fall back on, because nothing was raised.
    """
    line = f"{prefix}domain:description:never matched"
    try:
        run_within_line_budget(lambda: parse_response([line, "%ok"]))
    except LineBudgetExceeded as exc:
        pytest.fail(
            f"parse_response([{line!r}, '%ok']) did not terminate: {exc}. Grouped line "
            "handlers return 0 lines consumed for a prefix match without its space, and "
            "parse_response advances by that count, so the loop is infinite. Either the "
            "handler must consume the line or the driver must advance unconditionally."
        )
    except RwhoisError:
        return


def test_hang_prone_drop_space_mutants_are_all_prefixed_by_a_tested_grouped_keyword() -> (
    None
):
    """Nothing is quietly routed away from the battery.

    The drop-the-space mutants that are excluded from the transcript sweep must each belong
    to a prefix the two tests above actually exercise, so the exclusion is a redirection to
    a stronger assertion rather than a gap.
    """
    tested = set(GROUPED_PREFIXES)
    unaccounted = sorted(
        {
            prefix
            for _case_id, _index, line in DROP_SPACE_HANG_PRONE
            for prefix in [keyword_of(line) or "<none>"]
            if prefix not in tested
        }
    )
    assert not unaccounted, (
        f"hang-prone lines outside the grouped prefixes: {unaccounted}"
    )
    prefixes_in_play = {keyword_of(line) for _c, _i, line in DROP_SPACE_HANG_PRONE}
    assert prefixes_in_play <= tested, (
        f"unexpected hang-prone keywords: {sorted(map(str, prefixes_in_play))}"
    )


# -------------------------------------------------------- query round-trip coverage --

# The "query" round-trip kind, kept here rather than in the corpus test so this file owns
# it. ``query-string`` is the one part of the grammar where registrata and Appendix B
# diverge on purpose: section 3.4 admits a leading ``*``, so both wildcard ends are exercised
# instead of only the one the appendix prints.
QUERY_ROUND_TRIPS: list[tuple[str, str]] = [
    ("bare-value", "example"),
    ("trailing-star", "vogon*"),
    ("leading-star", "*vogon"),
    ("both-stars", "*vogon*"),
    ("attribute-query", "domain=EXAMPLE.NET"),
    ("attribute-with-both-stars", "domain=*ns1*.example.net"),
    ("quoted-with-spaces", '"Example, Inc."'),
    ("quoted-with-comma", '"Doe, Jane"'),
    ("boolean-and", "a.example.net and b.example.net"),
    ("boolean-or-attributes", "Last-Name=Doe or First-Name=Jane"),
    ("boolean-chain", "a and b and c"),
    ("class-restricted", "domain *vogon*"),
    ("class-restricted-attribute", "person Last-Name=Doe"),
    ("eight-bit-value", "domain=caf\xe9.example.net"),
    ("ip-authority-area", "192.0.2.1"),
    ("non-ascii-quoted", '"Caf\xe9 Example"'),
]

_ROUND_TRIP_IDS = [label for label, _text in QUERY_ROUND_TRIPS]


@pytest.mark.parametrize("label,text", QUERY_ROUND_TRIPS, ids=_ROUND_TRIP_IDS)
def test_query_round_trips_through_serialize(label: str, text: str) -> None:
    """``parse_query(text).serialize()`` must reparse to an equivalent expression.

    Equivalence, not identity of bytes: a redundant quote and a plain value are the same
    query, so what has to survive is the tree, plus stability of serialising twice, plus the
    re-serialised text being something the parser accepts at all.
    """
    first = parse_query(text)
    serialised = first.to_wire()
    second = parse_query(serialised)
    assert second.expression == first.expression, (
        f"{label}: {serialised!r} reparsed differently"
    )
    assert second.class_name == first.class_name, (
        f"{label}: class restriction lost in {serialised!r}"
    )
    assert second.to_wire() == serialised, (
        f"{label}: serialise is not idempotent ({second.to_wire()!r})"
    )


@pytest.mark.parametrize("label,text", QUERY_ROUND_TRIPS, ids=_ROUND_TRIP_IDS)
def test_query_round_trip_inputs_stay_inside_query_char(label: str, text: str) -> None:
    """The round-trip table is grammar-valid input, or the test above means nothing.

    Values are ``query-char`` plus the ``*`` the production brackets them with; a space may
    appear only inside a quoted string, since space is not a ``query-char``.
    """
    expression = parse_query(text).expression
    # A quoted value may hold space and tab (``quoted-query-char`` adds them); a bare value
    # may not, because those three characters are exactly what ``query-char`` removes from
    # ``any-char``. Whether the value needs quotes is visible in what serialise produced.
    quoted = parse_query(text).to_wire().startswith('"')
    permitted = {" ", "\t"} if quoted else set()
    for value in search_values(expression):
        for char in value.strip("*"):
            assert char != '"', (
                f"{label}: value {value!r} holds a quote, which query-char excludes"
            )
            if char in permitted:
                continue
            assert rwhois_abnf_match.matches("query-char", char), (
                f"{label}: value {value!r} carries {char!r}, which query-char excludes"
            )
    assert not any(char in text for char in "\t\r\n"), (
        f"{label}: tab/CR/LF are not query-chars"
    )


def test_quoted_value_with_spaces_survives_the_round_trip() -> None:
    """The quoting is part of the grammar's meaning, not a presentational choice.

    ``query-string`` has a quoted alternative precisely so a value can contain a space, so
    a value that needs it must come back with the quotes still on.
    """
    quoted = parse_query('"Example, Inc."')
    assert quoted.to_wire() == '"Example, Inc."'
    assert parse_query(quoted.to_wire()).expression == quoted.expression
    assert quoted.search_values == ["Example, Inc."]


def test_unquoted_space_cannot_be_a_single_query_value() -> None:
    """The other side of the same rule: without quotes, a space splits the query.

    Registrata reads the first token as a class name here, which is what the grammar leaves
    it: ``rwhois-query`` is ``[class-name space] query`` and space is not a ``query-char``,
    so there is no reading in which ``Example, Inc.`` is one value.
    """
    parsed = parse_query("Example, Inc.")
    assert parsed.class_name == "Example,"
    with pytest.raises(RwhoisError):
        parsed.to_wire()


def test_double_quote_inside_a_query_value_is_a_documented_deviation() -> None:
    """Registrata refuses a ``"`` inside a query value although ``quoted-query-char`` allows it.

    docs/compliance.md records this as an intentional deviation rather than a bug: a delimiter
    that may occur inside its own body, with no escape mechanism anywhere in the protocol,
    makes the quoted form ambiguous, and refusing it is the only reading that parses to
    exactly one answer. Both halves are asserted so that changing either one has to be a
    decision somebody made: the grammar really does admit the character, and the library
    really does reject it with the documented error class. If the library ever accepts it,
    this test fails and the deviation entry leaves the compliance doc.
    """
    assert '"' in PRODUCTIONS["quoted-query-char"].abnf, PRODUCTIONS[
        "quoted-query-char"
    ].abnf
    assert "quoted-query-char" in rwhois_abnf_match.unpatterned_productions(), (
        "quoted-query-char is a composite over query-char, so the matcher gives it no "
        "pattern; if that changes, assert the character directly instead of via the ABNF text"
    )
    with pytest.raises(InvalidQuerySyntax) as excinfo:
        parse_query('domain="Example, Inc."')
    assert excinfo.value.code == 350, (
        f"expected the documented 350, got {excinfo.value.code}"
    )


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "-soa com",
        "a and",
        "and",
        '"unterminated',
        "domain=",
        "domain=  x",
        "a = b",
        "domain=has\tspace",
        "domain=has\rcr",
        "domain=has\nlf",
    ],
)
def test_malformed_query_raises_only_a_documented_error(text: str) -> None:
    """A bad query from a user or a server is an ``RwhoisError``, never a builtin.

    ``InvalidQuerySyntax`` carries RFC 2167's 350, which is what the gateway turns into a
    client error; a ``ValueError`` escaping here would surface as a 500 instead.
    """
    try:
        parse_query(text)
    except RwhoisError:
        return
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"parse_query({text!r}) leaked builtin {type(exc).__name__}: {exc}")
    pytest.fail(
        f"parse_query({text!r}) accepted input the query grammar does not produce"
    )


# ------------------------------------------------- record separation (RFC 2167 3.4) --


def test_blank_line_separates_records_of_different_classes() -> None:
    """RFC 2167 3.4: a blank line ends one ``query-record`` and starts the next.

    The blank line is the only thing that separates records, so two objects of *different*
    classes side by side must still be two objects rather than one object with a class
    conflict. This is the example the section itself shows.
    """
    result = parse_query_result(
        [
            "domain:Class-Name:domain",
            "domain:Domain-Name:NET-IBM-COM.com",
            "domain:Auth-Area:0.0.0.0/0",
            "",
            "network:Class-Name:network",
            "network:Network-Number:198.41.0.0/16",
            "network:Auth-Area:0.0.0.0/0",
            "%ok",
        ]
    )
    assert [obj.class_name for obj in result.objects] == ["domain", "network"], (
        result.objects
    )
    assert [len(obj.attributes) for obj in result.objects] == [3, 3]
    assert result.objects[1].get("Network-Number") == "198.41.0.0/16"
    assert result.ok


def test_class_change_inside_one_record_is_rejected() -> None:
    """Without the blank line those two lines are one record, and one record has one class.

    ``query-record`` is ``1*query-line crlf`` with no class boundary inside it, so a server
    that changes class mid-record has written something whose attributes belong to nothing.
    """
    with pytest.raises(RwhoisParseError):
        parse_query_result(
            [
                "domain:Domain-Name:NET-IBM-COM.com",
                "network:Network-Number:198.41.0.0/16",
                "%ok",
            ]
        )


def test_truncation_never_reports_a_response_its_own_lines_do_not_contain() -> None:
    """A parse may claim ``ok`` only if a terminator survived in the lines it was given.

    Paired with the truncation sweep: acceptance of a partial transcript is the recorded
    leniency, but a partial transcript must never look *finished*. A client that trusts
    ``ok`` stops reading, so a false ``ok`` is a silently truncated answer.
    """
    for case_id, cut, parser_name, lines in TRUNCATE_MUTANTS:
        parser = PARSERS[parser_name]
        try:
            result = parser(lines)
        except RwhoisError:
            continue
        if result.ok:
            assert "%ok" in lines, (
                f"{case_id} cut at {cut}: ok True with no terminator in range"
            )
        assert result.error_code is None or any(
            line.startswith("%error") for line in lines
        ), f"{case_id} cut at {cut}: error_code {result.error_code} with no %error line"


def test_mutation_families_have_material_to_mutate() -> None:
    """Every family in the battery must have mutants, otherwise its green means nothing.

    This is not a claim that every plain line in a valid transcript is a ``query-line``: prose
    inside an ``%info on`` block, or ahead of a terminator under ``x-response``, is ``*any-char``
    and legitimately unparsable as an attribute. It only asserts that the selectors still find
    what they are supposed to find, and that a prose line is excluded rather than mutated.
    """
    assert TRUNCATE_MUTANTS, "no truncation mutants: no valid transcripts to cut"
    assert STRIP_PERCENT_MUTANTS, "no %-lines to strip a leading %% from"
    assert DROP_SPACE_MUTANTS and DROP_SPACE_HANG_PRONE, (
        "no keyword-space mutants derived"
    )
    assert DOUBLE_CLASS_COLON_MUTANTS, (
        "no query-line available to double a separator on"
    )
    assert (
        len(CR_IN_VALUE_MUTANTS)
        == len(LF_IN_VALUE_MUTANTS)
        == len(NUL_IN_VALUE_MUTANTS)
    ), (
        "the three value-injection families selected different line sets, so a selector drifted"
    )
    assert is_query_line("domain:Domain-Name:EXAMPLE.NET"), (
        "a real query-line stopped being selectable"
    )
    assert not is_query_line("Server maintenance window 02:00-03:00 UTC."), (
        "info-block prose is now parsed as an attribute line, so the injection families would "
        "be mutating text the grammar never constrains that way"
    )
    assert not is_query_line("%class domain:description:x"), (
        "%-lines must not be selected"
    )


# ---------------------------------------------------------------- the coverage gate --

# The only productions the gate lets go unexercised. Each entry has to justify itself
# against ``rwhois_grammar.UNDEFINED_REFERENCES`` (asserted below), and an entry that
# becomes testable has to be deleted, because "no case names this" is excusable only when
# nothing *can* be an instance of it.
#
# key-id: RFC 2167's pgp-data writes ``[space key-id]`` and Appendix B never defines the
#   production, so there is no byte sequence that is a key-id and no transcript that can
#   exercise it. The gap belongs in the compliance doc, which is where UNDEFINED_REFERENCES
#   points.
#
# email-char is deliberately NOT here even though it is also an undefined reference: RFC
# 2167 defers it to RFC 822 and the matcher transcribes RFC 822's atext set, so a real
# address value *is* an instance of it and some case must name it.
COVERAGE_EXEMPT: dict[str, str] = {
    "key-id": (
        "referenced by pgp-data and never defined in RFC 2167, so no input is an instance "
        "of it; recorded in rwhois_grammar.UNDEFINED_REFERENCES and docs/compliance.md"
    ),
}


def coverage_claims(cases: list[dict]) -> dict[str, list[str]]:
    """Map each production name to the case ids that name it.

    Reads the ``"abnf"`` key and nothing else. A hand-written case without the key counts
    toward nothing, which is the honest reading: it may be a perfectly good test, but nobody
    has said which construct it is a test *of*.
    """
    claims: dict[str, list[str]] = {}
    for case in cases:
        for name in case.get("abnf", ()):
            claims.setdefault(name, []).append(str(case["id"]))
    return claims


def covered_productions(cases: list[dict]) -> set[str]:
    return {name for name, claimants in coverage_claims(cases).items() if claimants}


def missing_productions(cases: list[dict]) -> list[str]:
    """Productions no case names, ignoring the exemptions so the raw gap stays visible."""
    covered = covered_productions(cases)
    return sorted(name for name in PRODUCTIONS if name not in covered)


def gate_failures(cases: list[dict]) -> list[str]:
    return sorted(set(missing_productions(cases)) - set(COVERAGE_EXEMPT))


def coverage_report(cases: list[dict]) -> str:
    """Coverage summary in the shape a release gate quotes, reused by failure messages."""
    covered = covered_productions(cases)
    missing = missing_productions(cases)
    by_group: dict[str, list[str]] = {}
    for name in missing:
        by_group.setdefault(PRODUCTIONS[name].group, []).append(name)
    lines = [f"ABNF coverage: {len(covered)}/{len(PRODUCTIONS)} productions exercised."]
    if by_group:
        lines.append(f"{len(missing)} unexercised across {len(by_group)} groups:")
        lines.extend(
            f"  {group} ({len(names)}): {', '.join(names)}"
            for group, names in sorted(by_group.items())
        )
    return "\n".join(lines)


COVERED = covered_productions(MANIFEST["cases"])
GATE_FAILURES = gate_failures(MANIFEST["cases"])


def test_coverage_claims_name_productions_that_exist() -> None:
    """A typo in an ``abnf`` list would claim coverage of a production nobody defines.

    Worse than a fixture nobody reads: the bad name sits in the claims map looking like
    coverage in any report that counts entries, while the production it was meant to name
    keeps looking untested.
    """
    unknown: dict[str, list[str]] = {}
    for case in MANIFEST["cases"]:
        for name in case.get("abnf", ()):
            if name not in PRODUCTIONS:
                unknown.setdefault(str(name), []).append(str(case["id"]))
    assert not unknown, (
        f"cases claim productions that are not in the inventory: {unknown}"
    )


def test_coverage_claims_are_well_formed() -> None:
    """An empty or malformed claim list counts as nothing, so it is rejected here instead."""
    problems: list[str] = []
    for case in MANIFEST["cases"]:
        case_id = str(case["id"])
        if "abnf" not in case:
            # Hand-written cases predate the key. Derived cases must not: being traceable to
            # the construct it was generated from is the only reason an "abnf-" case exists.
            if case_id.startswith("abnf-"):
                problems.append(f"{case_id}: derived case carries no abnf list")
            continue
        claimed = case["abnf"]
        if not isinstance(claimed, list) or not claimed:
            problems.append(
                f'{case_id}: "abnf" must be a non-empty list, got {claimed!r}'
            )
            continue
        if not all(isinstance(name, str) and name for name in claimed):
            problems.append(
                f'{case_id}: "abnf" holds an empty or non-string entry: {claimed!r}'
            )
        if len(set(claimed)) != len(claimed):
            problems.append(f"{case_id}: abnf list repeats a production name")
    assert not problems, "\n  ".join(problems)


def test_coverage_comes_from_case_claims_and_never_from_transcript_text() -> None:
    """The gate's one unforgivable failure mode, tested directly.

    If coverage could be earned from the bytes a fixture happens to contain, a transcript
    that merely mentions ``%soa`` would credit ``soa-dir``, the gate would go green on every
    production whose keyword appears somewhere, and "all ABNF constructs have tests" would be
    hollow while looking checked. So the same file is credited only when the case says so.
    """
    silent = [{"id": "synthetic-mentions-soa", "file": "x.txt", "abnf": []}]
    assert covered_productions(silent) == set(), (
        "coverage was inferred from transcript text"
    )
    claiming = [{"id": "synthetic-names-soa", "file": "x.txt", "abnf": ["soa-dir"]}]
    assert covered_productions(claiming) == {"soa-dir"}
    assert coverage_claims(claiming) == {"soa-dir": ["synthetic-names-soa"]}
    # A case with no key at all is legal and covers nothing, which is what lets the corpus
    # keep growing before every entry has been traced back to the grammar.
    assert covered_productions([{"id": "hand-written", "file": "x.txt"}]) == set()


def test_exemption_list_is_exactly_the_undefinable_production() -> None:
    """An exemption is allowed only where no input can exist, not where one is inconvenient."""
    outside = sorted(set(COVERAGE_EXEMPT) - set(rwhois_grammar.UNDEFINED_REFERENCES))
    assert not outside, (
        f"{outside} is exempted but RFC 2167 defines it, so a case can and must exercise it"
    )
    assert list(COVERAGE_EXEMPT) == ["key-id"], (
        "email-char is an undefined reference too, but the matcher transcribes RFC 822's atext "
        "set, so a real address exercises it; exempting it would hide a coverage gap"
    )
    assert len(COVERAGE_EXEMPT["key-id"]) > 40, (
        "an exemption needs a reason somebody can rule on"
    )
    for name in COVERAGE_EXEMPT:
        assert name in rwhois_abnf_match.unpatterned_productions(), (
            f"{name}: exempted from coverage although the matcher recognises it, which means a "
            "test for it is writable"
        )


@pytest.mark.parametrize("name", sorted(PRODUCTIONS))
def test_production_is_exercised_by_a_corpus_case(name: str) -> None:
    """Every production must be named by some case, or be provably impossible.

    One assertion per production, so a regression reads as "these constructs lost their
    test", named, rather than as a bare count. When this fails the fix is to add the name to
    the ``"abnf"`` list of a case that really does parse it, either because a fixture already
    exercises it and was never traced, or because nothing exercises it and one is missing.
    """
    if name in COVERAGE_EXEMPT:
        # The exemption is not a free pass: a production nobody can define must also be one
        # nobody claims, or someone has found a way to test it and the exemption lies.
        assert name not in COVERED, (
            f"{name} is exempted as undefined, yet "
            f"{coverage_claims(MANIFEST['cases']).get(name)} claims to exercise it; delete the "
            "exemption instead"
        )
        return
    assert name in COVERED, (
        f"{name} ({PRODUCTIONS[name].group} group) is exercised by no corpus case.\n"
        f"  ABNF: {PRODUCTIONS[name].abnf}\n"
        f"  source: {', '.join(PRODUCTIONS[name].refs)}\n"
        f'  fix: add "{name}" to the abnf list of a case that actually parses it'
    )


def test_coverage_gate_is_satisfied_for_the_whole_grammar() -> None:
    """The aggregate claim, failing with the full list instead of one production at a time.

    The per-production test above identifies each gap; this is the number a release gate
    quotes, and it fails on a single missing production too, so the two can never disagree
    about whether the corpus is complete.
    """
    assert not GATE_FAILURES, (
        f"{len(GATE_FAILURES)} of {len(PRODUCTIONS)} productions have no test.\n"
        f"{coverage_report(MANIFEST['cases'])}\n"
        f"exempted as undefinable: {sorted(COVERAGE_EXEMPT)}"
    )


def test_gate_reads_a_corpus_that_exists() -> None:
    """Stops the gate reporting an empty manifest as a coverage finding it understood.

    With no cases the gate would say "0 productions exercised", which reads like a real
    coverage report rather than a broken fixture load, so the population the claims come from
    is asserted separately from the claims themselves.
    """
    assert MANIFEST["cases"], "manifest holds no cases for the gate to read"
    assert len(CASES) == len(MANIFEST["cases"]), (
        "duplicate case ids collapse in the gate index"
    )
    assert VALID_IDS, "no valid transcripts to derive grammar-valid artefacts from"
    assert ALL_MUTANTS, "the mutation battery derived nothing from the corpus"
    assert len(COVERED) + len(missing_productions(MANIFEST["cases"])) == len(
        PRODUCTIONS
    ), "covered and missing do not partition the inventory, so a claim names nothing"


def test_coverage_numbers_partition_the_inventory_by_group() -> None:
    """Per-group coverage, so a half-covered group cannot hide behind a large group.

    ``covered + unexercised == total`` per group is also what proves the inventory has no
    name claimed by a case and absent from the grammar, and no grammar name credited twice
    under two spellings.
    """
    covered = covered_productions(MANIFEST["cases"])
    for group, names in sorted(rwhois_grammar.groups().items()):
        claimed_here = {name for name in names if name in covered}
        assert claimed_here <= set(names), f"{group}: covered names outside the group"
        assert len(names) == len(set(names)), (
            f"{group}: duplicate productions in the inventory"
        )
    assert sum(len(names) for names in rwhois_grammar.groups().values()) == len(
        PRODUCTIONS
    )
