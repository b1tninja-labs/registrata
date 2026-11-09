"""Recognizers for RFC 2167 productions, transcribed from the ABNF in the RFC.

This module exists so the corpus can be checked against the *specification* instead of
against the generator that produced it. If the generator and the checker were the same
code, a wrong generator would emit wrong fixtures and still pass. Each pattern is a
direct translation of one production, keyed by production name so a reviewer can put the
pattern beside the ABNF text in ``rwhois_grammar.py``.

Transcription rules, stated because they are where mistakes hide:

- ``any-char`` is ASCII octets 1..255 except CR and LF. Octet 0 is outside the range, so
  NUL is a violation rather than an unfriendly character, and the 1..255 bound is what
  makes RWhois an 8-bit protocol.
- Composites that are pure alternations of other productions (``response``,
  ``directives``, ``query-record``) get no pattern here. They are exercised through the
  constructs that use them; the coverage gate checks that by reading which cases name
  them rather than pretending to match a protocol-wide alternation.
- ``email-char`` is defined by reference to RFC 822, so its pattern is RFC 822's
  ``<atext>`` set. That is a transcription of a second document, not an invention.
"""

from __future__ import annotations

import re

# any-char: octets 1..255 minus CR (0x0d) and LF (0x0a), and nothing else. TAB is
# inside the class -- the RFC excludes only the two line terminators, and tab is legal
# inside a quoted query and inside a value. The first range therefore ends at 0x09.
ANY_CHAR = r"[\x01-\x09\x0b\x0c\x0e-\xff]"
# RFC 822 atext, the set RFC 2167 points at for email-char.
ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
# dns-char: no underscore, which is what makes host-name narrower than class-name.
DNS_CHAR = r"[A-Za-z0-9-]"
# id-char, spelled out again here because class-name/attribute-name are exactly it.
ID_CHAR = r"[A-Za-z0-9_-]"

# Derived once, reused by every composite below. Repeating the transcription per
# production is how the two copies drift apart.
HOST_NAME = rf"{DNS_CHAR}(?:{DNS_CHAR}|\.)*"
IP_ADDRESS = r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}"
AUTHORITY_AREA = rf"(?:{DNS_CHAR}|\.)(?:{DNS_CHAR}|\.|/)*"
OBJECT_ID = rf"{ID_CHAR}+\.{AUTHORITY_AREA}"
HOST_PORT = rf"(?:{HOST_NAME}|{IP_ADDRESS}):[0-9]{{1,5}}"
EMAIL = rf"{ATEXT}+@{HOST_NAME}"
TIME_STAMP = r"[0-9]{17}"
CAPABILITY_ID = r"[0-9A-Fa-f]{6}:[0-9A-Fa-f]{2}"
VERSION_NUMBER = r"V-[0-9]+\.[0-9]+"
# query-char is any-char except the double quote (0x22), space (0x20) and tab. Skipping
# 0x20 and 0x22 out of the 1..255 set leaves \x01-\x1f, "!", and "#".."\xff"; a single
# contiguous range such as !-\xff would read the excluded quote straight back in.
QUERY_CHAR = r"[\x01-\x08\x0b\x0c\x0e-\x1f!#-\xff]"

PATTERNS: dict[str, str] = {
    # Lexical tokens.
    "alpha": r"[A-Za-z]",
    "digit": r"[0-9]",
    "hex-digit": r"[0-9A-Fa-f]",
    "id-char": ID_CHAR,
    "any-char": ANY_CHAR,
    "dns-char": DNS_CHAR,
    "email-char": ATEXT,
    "space": r" ",
    "tab": r"\t",
    "lf": r"\n",
    "cr": r"\r",
    "crlf": r"\r\n",
    # General definitions.
    "year": r"[0-9]{4}",
    "month": r"[0-9]{2}",
    "day": r"[0-9]{2}",
    "hour": r"[0-9]{2}",
    "minute": r"[0-9]{2}",
    "second": r"[0-9]{2}",
    "milli-second": r"[0-9]{3}",
    "host-name": HOST_NAME,
    "email": EMAIL,
    "authority-area": AUTHORITY_AREA,
    "object-id": OBJECT_ID,
    "ip-address": IP_ADDRESS,
    "host-port": HOST_PORT,
    # class-name and attribute-name are both exactly 1*id-char, which is why the RFC can
    # use the same shape twice. The "+" matters: bare ID_CHAR is one character.
    "class-name": rf"{ID_CHAR}+",
    "attribute-name": rf"{ID_CHAR}+",
    "attribute-value": rf"{ANY_CHAR}+",
    "time-stamp": TIME_STAMP,
    "on-off": r"(?:on|off)",
    # Responses.
    "ok-response": r"%ok",
    "error-code": r"[0-9]{3}",
    "error-text": rf"{ANY_CHAR}+",
    "error-response": rf"%error [0-9]{{3}} {ANY_CHAR}+",
    # Banner.
    "version-number": VERSION_NUMBER,
    "response-id": r"[0-9A-Fa-f]{6}",
    "extra-id": r"[0-9A-Fa-f]{2}",
    "capability-id": CAPABILITY_ID,
    "version": rf"{VERSION_NUMBER}(?::{CAPABILITY_ID})?",
    "implementation": rf"{ANY_CHAR}+",
    # Names the optional directives use. All are 1*id-char.
    "meta-field": rf"{ID_CHAR}+",
    "meta-value": rf"{ANY_CHAR}+",
    "directive-name": rf"{ID_CHAR}+",
    "display-name": rf"{ID_CHAR}+",
    "x-directive": rf"{ID_CHAR}+",
    "x-arguments": rf"{ANY_CHAR}*",
    "direction": r"(?:request|response)",
    "security-method": r"(?:password|pgp|[A-Za-z0-9_-]+)",
    "password-data": rf"{ANY_CHAR}+",
    "serial-number": TIME_STAMP,
    "maintainer-id": EMAIL,
    # Query.
    "query-char": QUERY_CHAR,
    "bin-boolean": r"(?:and|or)",
    "type-char": r"[TIS]",
}

COMPILED = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}


def matches(production: str, value: str) -> bool:
    """True when ``value`` is exactly one instance of the named production."""
    try:
        compiled = COMPILED[production]
    except KeyError as exc:  # pragma: no cover - a typo in a caller
        raise KeyError(f"no pattern transcribed for production {production!r}") from exc
    return compiled.fullmatch(value) is not None


def patterned() -> list[str]:
    return sorted(PATTERNS)


# Values below are copied from RFC 2167's own examples wherever the RFC gives one, so a
# reviewer can grep the number and find it in the text. The paired counter-examples are
# what make the transcription meaningful: they are the near-misses a looser pattern
# would accept.
RFC_EXAMPLES: dict[str, tuple[str, ...]] = {
    # The ABNF permits a trailing dot: host-name is dns-char *(dns-char / "."). Odd in
    # DNS practice, legal on the wire, so it is pinned as accepted rather than rejected.
    "host-name": ("master.rwhois.net", "ardis.com", "ns1234-hst.net", "trailing-dot."),
    "authority-area": ("com", "example.net", "0.0.0.0/0"),
    # object-id is 1*id-char "." authority-area, and id-char includes "-", so a leading
    # hyphen is in the alphabet.
    "object-id": (
        "IBMLIFEPRO-DOM.com",
        "NET-IBMNET-3.0.0.0/0",
        "EXAMPLE-DNS-ORG.example.net",
        "-leading-dot.example.net",
    ),
    "email": ("autoreg@internic.net", "support@example.net"),
    "time-stamp": ("19961120123455000", "19970604120000000"),
    "serial-number": ("19961120123455000",),
    "version-number": ("V-1.5", "V-1.0"),
    "capability-id": ("00ffff:00", "003f00:00"),
    "version": ("V-1.5:00ffff:00", "V-1.0"),
    "ok-response": ("%ok",),
    "error-response": (
        "%error 230 No objects found",
        "%error 330 Exceeded maximum objects limit",
    ),
    "error-code": ("230", "330"),
    "class-name": ("domain", "network", "person"),
    "attribute-name": ("Domain-Name", "Numeric-Id", "Tag_List"),
    "attribute-value": ("Example, Inc.", "Source:ARIN", "Café Example", "tab\tinside"),
    "ip-address": ("192.0.2.1", "0.0.0.0"),
    "host-port": ("192.0.2.1:4321", "master.rwhois.net:4321"),
    "on-off": ("on", "off"),
    "direction": ("request", "response"),
    "bin-boolean": ("and", "or"),
    "type-char": ("T", "I", "S"),
    "id-char": ("a", "9", "_", "-"),
    "dns-char": ("a", "9", "-"),
    "hex-digit": ("f", "A", "9"),
    # TAB is in the alphabet: any-char excludes only CR and LF.
    "any-char": ("A", "\xe9", "\x01", ":", "\t"),
    "query-char": ("v", ".", "*", "="),
}

COUNTER_EXAMPLES: dict[str, tuple[str, ...]] = {
    # host-name is dns-char based, so an underscore is not a host character.
    "host-name": ("under_score.net", ".example.net"),
    # authority-area may not begin with "/", and may not hold a space.
    "authority-area": ("/com", "exa mple", ""),
    "object-id": ("nodot",),
    "ip-address": ("1.2.3", "1234.1.1.1", "1.2.3.4.5"),
    "host-port": ("master.rwhois.net", "master.rwhois.net:432100"),
    # 17 digits exactly: year month day hour minute second milli-second.
    "time-stamp": ("19961120123455", "199611201234550000"),
    "capability-id": ("00ffff", "00zzzz:00"),
    "version-number": ("1.5", "V-1", "V1.5"),
    "email": ("no-at-sign", "@missing.example.net"),
    "error-response": ("%error 23a bad code", "%error 23 missing space"),
    # The ABNF spells these upper case; a lowercase type character is a different token.
    "type-char": ("t", "TT", ""),
    "class-name": ("do main", "class:name"),
    # CR and LF end a line and are outside any-char; NUL is outside 1..255 entirely.
    "any-char": ("\x00", "\r", "\n"),
    "attribute-value": ("line\rwith cr", "line\nwith lf"),
    "query-char": (" ", '"', "\t"),
    "id-char": (".", ":", " "),
    "dns-char": ("_", "."),
    "hex-digit": ("g", "0x1"),
    "on-off": ("ON", "yes"),
}


def selfcheck() -> list[str]:
    """Return a message for every example the transcription gets wrong."""
    problems: list[str] = []
    for production, values in RFC_EXAMPLES.items():
        if production not in COMPILED:
            problems.append(f"{production}: no pattern transcribed but examples exist")
            continue
        for value in values:
            if not matches(production, value):
                problems.append(
                    f"{production}: RFC value {value!r} rejected by {PATTERNS[production]!r}"
                )
    for production, values in COUNTER_EXAMPLES.items():
        if production not in COMPILED:
            problems.append(
                f"{production}: no pattern transcribed but counter-examples exist"
            )
            continue
        for value in values:
            if matches(production, value):
                problems.append(
                    f"{production}: pattern accepts {value!r}, which the ABNF does not"
                )
    return problems


def unpatterned_productions(inventory: dict[str, object] | None = None) -> list[str]:
    """Productions in the RFC inventory with no pattern here.

    Composites over other productions are expected to appear in this list; the test
    suite asserts the list contains only composites, so a leaf production cannot quietly
    lose its coverage.
    """
    from rwhois_grammar import PRODUCTIONS

    source = inventory if inventory is not None else PRODUCTIONS
    return sorted(name for name in source if name not in PATTERNS)


if __name__ == "__main__":
    failures = selfcheck()
    for line in failures:
        print(f"MISMATCH {line}")
    print(f"patterns: {len(PATTERNS)}  mismatches: {len(failures)}")
    raise SystemExit(1 if failures else 0)
