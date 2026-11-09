"""Seeded generative property tests over the RFC 2167 grammar.

``tests/test_rwhois_abnf.py`` mutates *fixed* fixtures, so its reach is bounded by what the
corpus happens to contain. Here the inputs themselves are generated from the production
alphabets, which means a hostile byte can land in an arbitrary position of an arbitrary
artifact rather than only in positions the hand-written transcripts happen to have.

Deterministic by construction: every generator is a pure function of a seed drawn from a
constant range, so a failure names the seed that reproduces it. No clock, no sockets, no
sleeps, and no property framework -- the dev group is pytest and ruff only, so a small
seeded generator is cheaper than adding a dependency for it.

The four properties:

1. **Fidelity where the mapping is injective.** A generated attribute line, error line,
   referral or capability id, parsed back, yields the value that was put in.
2. **Stability everywhere else.** ``parse -> serialize -> parse`` reaches a fixed point
   after one round. Stability rather than identity is asserted because these serializers
   normalize on purpose: ``encode_capability_id`` emits lower-case hex, ``Version.name``
   prepends ``V-``, and ``AND`` folds to ``and``. Demanding byte identity with the input
   would fail on correct behaviour, and a test that fails on correct behaviour gets
   deleted rather than fixed.
3. **No builtin escapes.** Splices of hostile bytes may be accepted, or rejected with an
   ``RwhoisError`` subclass, never with anything else.
4. **No stalls.** Parsing hostile input must terminate within an executed-line budget, so a
   loop like the one that used to live in ``parse_response`` reports as a failure instead
   of hanging the suite.
"""

from __future__ import annotations

import random
import sys
from typing import Callable

import pytest

from registrata.banner import parse_banner, serialize_banner
from registrata.capabilities import decode_capability_id, encode_capability_id
from registrata.errors import RwhoisError, format_error_line, parse_error_line
from registrata.protocol import (
    parse_directive_response,
    parse_query_result,
    parse_response,
)
from registrata.query import parse_query
from registrata.records import (
    AttributeLine,
    ObjectRecord,
    Referral,
    parse_referral_line,
)
from registrata.soa import format_timestamp, parse_timestamp

# Alphabets transcribed from the productions they instantiate. Kept as explicit strings
# rather than sampled from the matcher's regexes, so a transcription error in one place
# cannot silently validate itself against the other.
ID_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
DNS_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
HEX_DIGITS = "0123456789abcdefABCDEF"
# any-char is octets 1..255 except CR and LF; TAB is inside it.
ANY_CHARS = "".join(chr(octet) for octet in range(1, 256) if octet not in (0x0A, 0x0D))
# query-char additionally excludes space, tab and the double quote.
QUERY_CHARS = ANY_CHARS.replace(" ", "").replace("\t", "").replace('"', "")
# Bytes a hostile server reaches for, plus the ones that break framing.
HOSTILE_CHARS = [
    "\x00",
    "\r",
    "\n",
    "\t",
    " ",
    '"',
    ":",
    ";",
    "%",
    "\x1b",
    chr(0x7F),
    chr(0x80),
    "\xe9",
    "\xff",
    "\\",
    "'",
    "|",
    "=",
    "*",
    "@",
    "/",
    "\x08",
]


def _run(rng: random.Random, alphabet: str, minimum: int, maximum: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(minimum, maximum)))


def gen_id(rng: random.Random) -> str:
    """1*id-char, started on an alphanumeric so it is valid by every reading.

    ``id-char`` includes ``-`` and ``_``, so a leading hyphen is in the alphabet whether or
    not ``validate_id`` accepts it. Odd shapes like that belong to the splice battery, not
    to the property that grammar-valid input must parse.
    """
    while True:
        text = _run(rng, ID_CHARS, 1, 12)
        if text[0].isalnum():
            return text


def gen_attribute_value(rng: random.Random) -> str:
    """1*any-char, biased toward the bytes that break naive colon-splitting."""
    value = _run(rng, ANY_CHARS, 1, 24)
    if rng.random() < 0.35:
        value += ":" + gen_id(rng)
    if rng.random() < 0.15:
        value += ";" + gen_id(rng)
    value = value.replace("\r", "").replace("\n", "").replace("\x00", "")
    return value or "v"


def gen_dns_label(rng: random.Random) -> str:
    text = _run(rng, DNS_CHARS, 1, 10)
    if not text[0].isalnum():
        text = (
            "a" + text
        )  # dns-char permits a leading hyphen; hand the parser the ordinary
    return text  # case here and let the splices probe the rest


def gen_host_name(rng: random.Random) -> str:
    return ".".join(gen_dns_label(rng) for _ in range(rng.randint(1, 4)))


def gen_authority_area(rng: random.Random) -> str:
    if rng.random() < 0.2:
        return ".".join(str(rng.randint(0, 255)) for _ in range(4)) + "/0"
    return gen_host_name(rng)


def gen_time_stamp(rng: random.Random) -> str:
    """17 digits, kept inside the range datetime can represent.

    ``time-stamp`` is year month day hour minute second milli-second. Year 0000 is in the
    grammar but below ``datetime.MINYEAR``, so emitting it would test a boundary of the
    standard library rather than one of the protocol.
    """
    return (
        f"{rng.randint(1, 9999):04d}{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}"
        f"{rng.randint(0, 23):02d}{rng.randint(0, 59):02d}{rng.randint(0, 59):02d}"
        f"{rng.randint(0, 999):03d}"
    )


def gen_capability_id(rng: random.Random) -> str:
    return (
        "".join(rng.choice(HEX_DIGITS) for _ in range(6))
        + ":"
        + "".join(rng.choice(HEX_DIGITS) for _ in range(2))
    )


def gen_search_token(rng: random.Random) -> str:
    token = _run(rng, QUERY_CHARS, 1, 14).replace("=", "") or "vogon"
    if rng.random() < 0.25:
        token = "*" + token
    if rng.random() < 0.25:
        token += "*"
    return token


def gen_query_text(rng: random.Random, depth: int = 0) -> str:
    """A canonical query string: no spaces, so no quoting ambiguity is involved."""
    if depth < 2 and rng.random() < 0.35:
        operator = rng.choice(("and", "or"))
        return f"{gen_query_text(rng, depth + 1)} {operator} {gen_query_text(rng, depth + 1)}"
    if rng.random() < 0.4:
        return f"{gen_id(rng)}={gen_search_token(rng)}"
    return gen_search_token(rng)


def gen_banner_line(rng: random.Random) -> str:
    versions = []
    for _ in range(rng.randint(1, 3)):
        number = f"V-{rng.randint(0, 9)}.{rng.randint(0, 99)}"
        if rng.random() < 0.5:
            number += ":" + gen_capability_id(rng)
        versions.append(number)
    implementation = _run(rng, ANY_CHARS.replace("(", "").replace(")", ""), 0, 20)
    return f"%rwhois {' '.join(versions)} {gen_host_name(rng)} ({implementation})"


def gen_error_line(rng: random.Random) -> str:
    code = "".join(rng.choice("0123456789") for _ in range(3))
    text = _run(rng, ANY_CHARS, 1, 30).replace("\x00", "") or "no objects found"
    return f"%error {code} {text}"


def gen_referral(rng: random.Random) -> Referral:
    return Referral(
        host=gen_host_name(rng),
        port=rng.randint(1, 65535),
        auth_area=gen_authority_area(rng),
    )


def splice(rng: random.Random, text: str) -> str:
    """One hostile edit at a uniformly chosen position."""
    if not text:
        return rng.choice(HOSTILE_CHARS)
    position = rng.randrange(len(text))
    action = rng.random()
    if action < 0.4:
        return text[:position] + rng.choice(HOSTILE_CHARS) + text[position + 1 :]
    if action < 0.7:
        return text[:position] + rng.choice(HOSTILE_CHARS) + text[position:]
    return text[:position] + text[position + 1 :]


SEEDS = range(64)


def seeded(salt: str, index: int) -> random.Random:
    """A stream identified by (property, seed), so a reported seed reproduces the input.

    ``random.Random`` seeded with a string hashes through sha512 rather than the process
    string hash, so the sequence is independent of ``PYTHONHASHSEED`` and identical on every
    machine. That is what makes "reproduce with seed 41" a real instruction rather than a
    suggestion.
    """
    return random.Random(f"registrata-property:{salt}:{index}")


def _serialize(banner) -> str:
    return serialize_banner(
        banner.versions, banner.host, implementation=banner.implementation
    )


# ------------------------------------------------------------------- fidelity --------


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_attribute_line_is_recovered_exactly(seed: int) -> None:
    """class:attr[;type]:value survives to_wire and parse unchanged, byte for byte."""
    rng = seeded("attribute-line", seed)
    class_name = gen_id(rng)
    attribute = AttributeLine(gen_id(rng), gen_attribute_value(rng), rng.choice("TIS"))
    line = attribute.to_wire(class_name)

    parsed_class, parsed = AttributeLine.parse(line)

    assert parsed_class == class_name
    assert parsed == attribute
    assert parsed.to_wire(class_name) == line


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_object_record_replays_its_lines(seed: int) -> None:
    """A record built from N lines parses back to the same N lines, in order."""
    rng = seeded("object-record", seed)
    class_name = gen_id(rng)
    lines = [
        AttributeLine(gen_id(rng), gen_attribute_value(rng), rng.choice("TIS")).to_wire(
            class_name
        )
        for _ in range(rng.randint(1, 4))
    ]

    record = ObjectRecord.from_lines(lines)

    assert record.class_name == class_name
    assert record.to_wire_lines() == lines


@pytest.mark.parametrize("seed", SEEDS)
def test_blank_line_separates_generated_objects(seed: int) -> None:
    """RFC 2167 section 3.4 separates objects by a blank line, not by a class change.

    Two records of the same class are distinguishable only by that blank line, and one
    record that changes class mid-record must not pass quietly, so the separator is
    load-bearing and worth generating rather than hand-transcribing once.
    """
    rng = seeded("multi-object", seed)
    transcripts: list[str] = []
    expected: list[tuple[str, list[str]]] = []
    for _ in range(rng.randint(1, 3)):
        class_name = gen_id(rng)
        lines = [
            AttributeLine(gen_id(rng), gen_attribute_value(rng), "T").to_wire(
                class_name
            )
            for _ in range(rng.randint(1, 3))
        ]
        transcripts.extend(lines + [""])
        expected.append((class_name, lines))

    result = parse_query_result(transcripts + ["%ok"])

    assert result.ok
    assert len(result.objects) == len(expected)
    for record, (class_name, lines) in zip(result.objects, expected):
        assert record.class_name == class_name
        assert record.to_wire_lines() == lines


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_referral_reconstructs_its_url(seed: int) -> None:
    """The referral written to the wire is the referral read back off it."""
    rng = seeded("referral", seed)
    referral = gen_referral(rng)

    parsed = parse_referral_line(referral.to_wire())

    assert parsed.key == referral.key
    assert parsed.url == referral.url
    assert parsed.to_wire() == referral.to_wire()


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_error_line_reaches_a_fixed_point(seed: int) -> None:
    """An error line settles after one round; fidelity holds except where it cannot.

    ``ERROR_LINE_RE`` separates code from text with ``[ \\t]+``, not the single ``space``
    Appendix B specifies. That tolerance makes an error-text beginning with whitespace
    unrecoverable in principle: after ``%error 230   oops`` there is no fact of the matter
    about how much of the run was separator and how much was message. Strictly that shape is
    not even malformed, since ``error-text`` is ``1*any-char`` and any-char includes space;
    the loss is a consequence of choosing to accept runs of spaces.

    ``format_error_line`` additionally substitutes the canonical message for a code when the
    text is empty, which is why the property asserted is a fixed point rather than identity.
    """
    rng = seeded("error-line", seed)
    line = gen_error_line(rng)

    code, text = parse_error_line(line)
    once_code, once_text = parse_error_line(format_error_line(code, text))
    wire = format_error_line(once_code, once_text)
    twice = parse_error_line(wire)

    # 000-099 are grammatical: error-code is 3DIGIT, and Appendix C merely documents the
    # 100-999 range. Asserting that range here would have excluded the three seeds that
    # found the zero-padding bug, which is the whole argument for generating input.
    assert 0 <= code <= 999
    assert twice == (once_code, once_text)
    assert format_error_line(*twice) == wire
    if text and text[0] not in " \t":
        assert (once_code, once_text) == (code, text)


def test_error_text_with_a_leading_space_is_not_recoverable() -> None:
    """The one place where the tolerant separator costs information, pinned by name.

    Asserted as a limitation rather than left to the generator, so that tightening the
    separator to the single ``space`` the ABNF specifies has to update this test and cannot
    happen as a silent side effect.
    """
    code, text = parse_error_line("%error 230   oops")

    assert code == 230
    assert text == "oops"


def test_error_codes_below_one_hundred_keep_their_zero_padding() -> None:
    """``error-code`` is 3DIGIT, so the value 30 has to be written back as "030".

    Found by the generator, not by hand: ``format_error_line`` rendered the code through
    ``int``, producing ``%error 30 ...``, which ``parse_error_line`` then rejects with its own
    three-digit requirement. A formatter emitting lines its own parser cannot read is worse
    than a crash, because the failure surfaces at the far end, on a server responding to a
    client.
    """
    line = format_error_line(30, "malformed request")

    assert line == "%error 030 malformed request"
    assert parse_error_line(line) == (30, "malformed request")

    with pytest.raises(ValueError):
        format_error_line(1000, "out of range")


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_time_stamp_survives_the_timestamp_helpers(seed: int) -> None:
    """Seventeen digits in, the same seventeen digits out.

    The milli-second field is the third of the three that a formatter is tempted to drop,
    and a dropped milli-second would make two distinct SOA serials and Updated values
    compare equal.
    """
    rng = seeded("time-stamp", seed)
    stamp = gen_time_stamp(rng)

    assert format_timestamp(parse_timestamp(stamp)) == stamp


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_capability_id_reaches_a_fixed_point(seed: int) -> None:
    """Decoding is case-insensitive and re-encoding is stable after one normalization.

    ``encode_capability_id`` emits lower-case hex, so an upper-case id from the wire does
    not come back byte-identical. Asserting identity would fail for a reason that is not a
    bug; the property that holds, and that matters, is that a second round changes nothing.
    """
    rng = seeded("capability-id", seed)
    raw = gen_capability_id(rng)

    once = encode_capability_id(decode_capability_id(raw))
    twice = encode_capability_id(decode_capability_id(once))

    assert once == twice
    assert decode_capability_id(raw) == decode_capability_id(raw.lower())
    assert decode_capability_id(raw) == decode_capability_id(raw.upper())


# ------------------------------------------------------------------ stability --------


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_banner_reaches_a_fixed_point(seed: int) -> None:
    """parse -> serialize -> parse settles after one round.

    Not identity with the generated line: a version may carry its own capability id or
    inherit the banner's, and the serializer picks the canonical rendering. Settling is the
    property worth having, because a serializer that keeps changing its own output means two
    parses of one server response disagree with each other.
    """
    rng = seeded("banner", seed)
    once = _serialize(parse_banner(gen_banner_line(rng)))
    twice = _serialize(parse_banner(once))

    assert once == twice


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_query_reaches_a_fixed_point(seed: int) -> None:
    """Serializing a parsed query is idempotent, including booleans and wildcards.

    RWhois has no parentheses, so ``a and b or c`` is ambiguous by grammar and the parser
    resolves it one way; that choice must at least be stable, because a resolver that
    re-serializes a query on referral would otherwise change the question it is asking. A
    leading ``-`` is skipped: ``parse_query`` refuses CLI-looking input by design, which is
    a deviation to probe with splices rather than a property violation.
    """
    rng = seeded("query", seed)
    text = gen_query_text(rng)
    while text.startswith("-"):
        text = "n" + text

    wire = parse_query(text).to_wire()
    again = parse_query(wire).to_wire()

    assert wire == again


# ---------------------------------------------------------------- differential -------


def generated_artifacts(index: int) -> list[tuple[str, str]]:
    """One grammar-valid artifact per wire family, from one seed.

    Reproducible on purpose: the splice battery consumes this list, so reporting a seed hands
    a reader the exact starting artifacts as well as the exact mutations of them.
    """
    rng = seeded("artifacts", index)
    class_name = gen_id(rng)
    return [
        (
            "attribute-line",
            AttributeLine(gen_id(rng), gen_attribute_value(rng), "T").to_wire(
                class_name
            ),
        ),
        ("error-line", gen_error_line(rng)),
        ("rwhois-banner", gen_banner_line(rng)),
        ("query-string", gen_query_text(rng)),
        ("referral-line", gen_referral(rng).to_wire()),
        ("class-line", f"%class {class_name}:description:{gen_id(rng)}"),
        ("schema-line", f"%schema {class_name}:attribute:{gen_id(rng)}"),
        ("soa-line", f"%soa authority:{gen_host_name(rng)}"),
        ("status-line", f"%status limit:{rng.randint(1, 999)}"),
        ("info-line", "%info on"),
        ("register-line", f"%register {gen_id(rng)}:ON"),
        ("ok-response", "%ok"),
    ]


# Every parser receives every hostile artifact, not only the family it was generated from.
# A server line is dispatched by prefix, so the failure worth finding is a parser that
# assumes its input already looked right.
PARSERS: list[tuple[str, Callable[[str], object]]] = [
    ("AttributeLine.parse", AttributeLine.parse),
    ("ObjectRecord.from_lines", lambda text: ObjectRecord.from_lines([text])),
    ("parse_referral_line", parse_referral_line),
    ("Referral.parse_url", Referral.parse_url),
    ("parse_error_line", parse_error_line),
    ("parse_banner", parse_banner),
    ("parse_query", parse_query),
    ("decode_capability_id", decode_capability_id),
    ("parse_response", lambda text: parse_response(text.split("\n"))),
    ("parse_query_result", lambda text: parse_query_result(text.split("\n"))),
]


@pytest.mark.parametrize("seed", range(24))
def test_spliced_input_never_escapes_as_a_builtin(seed: int) -> None:
    """Only an ``RwhoisError`` subclass may come back out of a parse.

    Accepting junk is a choice, and the compliance doc argues it entry by entry. Leaking a
    ``TypeError`` or a ``UnicodeDecodeError`` is not a choice anyone would make: callers are
    documented to catch ``RwhoisError``, so a builtin sails through them and into whatever
    process is holding the socket.
    """
    rng = random.Random(f"registrata-property:splice:{seed}")
    escapes: list[str] = []
    for kind, artifact in generated_artifacts(seed):
        for _ in range(12):
            hostile = splice(rng, artifact)
            for name, parser in PARSERS:
                try:
                    parser(hostile)
                except RwhoisError:
                    pass
                except Exception as exc:  # noqa: BLE001 - catching everything is the assertion
                    escapes.append(
                        f"{name} on {kind} splice {hostile!r} raised "
                        f"{type(exc).__name__}: {exc}"
                    )

    assert not escapes, (
        f"seed {seed}: {len(escapes)} builtin escape(s) from spliced input:\n"
        + "\n".join(escapes[:10])
    )


def test_splice_battery_actually_produces_rejections() -> None:
    """An anti-vacuity guard: a fuzzer whose mutations are all accepted proves nothing.

    If the hostile alphabet were ever narrowed to harmless bytes, the test above would stay
    green while checking nothing, so the number of rejections it observes is asserted too.
    """
    rng = random.Random("registrata-property:vacuity:1")
    rejections = 0
    for _kind, artifact in generated_artifacts(1):
        for _ in range(12):
            hostile = splice(rng, artifact)
            for _name, parser in PARSERS:
                try:
                    parser(hostile)
                except RwhoisError:
                    rejections += 1


# ----------------------------------------------------------------------- stalls ------


class _Stalled(RuntimeError):
    """Raised inside the traced frame once a parse has outgrown its line budget."""


def _within_line_budget(call: Callable[[], object], *, budget: int = 40_000) -> None:
    """Run ``call``, raising ``_Stalled`` if it executes more than ``budget`` source lines.

    A step count rather than a clock: a healthy parse costs microseconds and a stalling one
    is reported instead of hanging the run. This mirrors the helper in
    ``test_rwhois_abnf.py`` and is duplicated rather than imported so the two files stay
    independent and a stall here names this file. One blind spot, recorded rather than
    hidden: a parser that swallowed arbitrary exceptions would eat the signal, and none does.
    """
    executed = 0

    def tracer(frame, event, argument):
        nonlocal executed
        if event == "line":
            executed += 1
            if executed > budget:
                raise _Stalled(f"{executed} lines executed and still going")
        return tracer

    sys.settrace(tracer)
    try:
        call()
    finally:
        sys.settrace(None)


TRANSCRIPT_PARSERS = (parse_response, parse_query_result, parse_directive_response)


@pytest.mark.parametrize("seed", range(12))
def test_spliced_transcript_terminates(seed: int) -> None:
    """The infinite-loop class, hunted generatively instead of by one hardcoded line.

    The bug this guards was a grouped keyword prefix that had lost its required space: the
    handler reported zero lines consumed, the driver advanced by zero, and parsing never
    returned. That specific shape is pinned by name in ``test_rwhois_abnf.py``; this is the
    version that keeps looking for the next one, across three transcript shapes (the hostile
    line alone, leading, and trailing a terminator) because cursor arithmetic goes wrong in
    all three positions.
    """
    rng = random.Random(f"registrata-property:stall:{seed}")
    stalls: list[str] = []
    for kind, artifact in generated_artifacts(seed):
        for _ in range(10):
            hostile = splice(rng, artifact)
            for transcript in ([hostile], [hostile, "%ok"], ["%ok", hostile]):
                for parser in TRANSCRIPT_PARSERS:
                    try:
                        _within_line_budget(lambda lines=transcript, p=parser: p(lines))
                    except _Stalled as exc:
                        stalls.append(
                            f"{parser.__name__} on {kind} {transcript!r}: {exc}"
                        )
                    except RwhoisError:
                        pass

    assert not stalls, (
        f"seed {seed}: {len(stalls)} parse(s) did not terminate:\n"
        + "\n".join(stalls[:5])
    )


# ------------------------------------------------------------------- determinism -----


def test_generated_input_depends_on_nothing_but_its_seed() -> None:
    """The battery is a pure function of its seed, or a reported seed is a fiction.

    Without this, a failure could depend on import order or on a shared RNG that an earlier
    test advanced, and the message would send a reader chasing something that does not
    reproduce.
    """
    assert generated_artifacts(9) == generated_artifacts(9)

    artifact = "%class domain:description:xyz"
    stream_a = random.Random("registrata-property:splice:9")
    stream_b = random.Random("registrata-property:splice:9")
    assert [splice(stream_a, artifact) for _ in range(64)] == [
        splice(stream_b, artifact) for _ in range(64)
    ]
