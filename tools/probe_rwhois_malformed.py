"""Development probe: what do the parsers actually do to hostile RWhois input?

The corpus in ``tests/fixtures/rwhois/malformed/`` pins these outcomes; rerun this
script when adding a parser branch to see the raw behaviour first. Exits non-zero if
any input escapes with a builtin exception instead of an ``RwhoisError``.
"""

from __future__ import annotations

import pathlib
import sys

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))

from registrata.banner import Version, parse_banner  # noqa: E402
from registrata.errors import RwhoisError, RwhoisParseError, parse_error_line  # noqa: E402
# A noqa for a multi-line import has to sit on the opening line; on the closing parenthesis ruff
# does not honor it, and E402 fires on the `from` line.
from registrata.protocol import (  # noqa: E402
    parse_directive_response,
    parse_query_result,
    parse_response,
)
from registrata.records import (  # noqa: E402
    AttributeLine,
    ObjectRecord,
    Referral,
    parse_referral_line,
)

CASES: list[tuple[str, object]] = [
    ("bare %info (no 'on')", lambda: parse_response(["%info stray", "%ok"])),
    ("unterminated %info on", lambda: parse_response(["%info on", "hello", "%ok"])),
    ("%info off without on", lambda: parse_response(["%info off", "%ok"])),
    ("attr line w/o value colon", lambda: parse_query_result(["domain:Handle", "%ok"])),
    ("line w/o any colon", lambda: parse_query_result(["garbage", "%ok"])),
    ("bad class name chars", lambda: parse_query_result(["dom ain:Handle:a", "%ok"])),
    ("%status no colon", lambda: parse_response(["%status Auth-Area", "%ok"])),
    ("%class too few parts", lambda: parse_response(["%class domain", "%ok"])),
    ("%register no colon", lambda: parse_response(["%register handle", "%ok"])),
    ("%error no code", lambda: parse_response(["%error", "%ok"])),
    ("%error 4 digits", lambda: parse_error_line("%error 3301 boom")),
    ("%error nonnumeric", lambda: parse_error_line("%error abc boom")),
    ("referral no port", lambda: Referral.parse_url("rwhois://h/auth-area=a")),
    (
        "referral nonnumeric port",
        lambda: Referral.parse_url("rwhois://h:port/auth-area=a"),
    ),
    ("referral port 0", lambda: Referral.parse_url("rwhois://h:0/auth-area=a")),
    ("referral port 99999", lambda: Referral.parse_url("rwhois://h:99999/auth-area=a")),
    ("referral missing area", lambda: Referral.parse_url("rwhois://h:43/auth-area=")),
    ("referral wrong scheme", lambda: Referral.parse_url("whois://h:43/auth-area=a")),
    ("bare %referral line", lambda: parse_referral_line("%referral")),
    ("banner no host", lambda: parse_banner("%rwhois V-1.0/43")),
    ("banner no versions", lambda: parse_banner("%rwhois  host.example.com")),
    ("version garbage", lambda: Version.parse("V-x.y").numeric),
    ("%soa only", lambda: parse_response(["%soa", "%ok"])),
    ("xfer garbage", lambda: parse_response(["%xfer domain:Class-Name"])),
    ("empty query", lambda: parse_query_result([])),
    (
        "directive on object lines",
        lambda: parse_directive_response(["domain:Handle:ex"]),
    ),
    ("CR-only line endings", lambda: parse_query_result(["domain:Handle:ex", "%ok"])),
    ("LF kept in line", lambda: parse_query_result(["domain:Handle:ex\n", "%ok\n"])),
    ("attr with embedded CR", lambda: AttributeLine("Handle", "a\rb")),
    ("query result no objects", lambda: ObjectRecord.from_lines([])),
]

print(f"{'case':<30} {'outcome'}")
bad: list[str] = []
for label, call in CASES:
    try:
        value = call()
        result = f"OK -> {type(value).__name__}"
    except (RwhoisParseError, RwhoisError) as exc:
        result = f"{type(exc).__name__}: {str(exc)[:60]}"
    except Exception as exc:  # noqa: BLE001
        result = f"!! {type(exc).__name__}: {str(exc)[:60]}"
        bad.append(f"{label}: {type(exc).__name__}: {exc}")
    print(f"{label:<30} {result}")

print(f"\nnon-RwhoisError escapes: {len(bad)}")
for item in bad:
    print("  -", item)
raise SystemExit(1 if bad else 0)
