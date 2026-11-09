"""Generate RFC 2167 ABNF-derived corpus cases, one per protocol construct.

``generate_rwhois_corpus.py`` holds the hand-written transcripts. This module adds
cases that are *derived from the grammar* in ``rwhois_grammar.py`` and checked against
the independent recognizers in ``rwhois_abnf_match.py`` before a single byte is
written, so the corpus cannot claim to cover a production whose shape it violates.

Three properties the rest of the corpus relies on:

1. **Self-validation, loudly.** Every artifact passes :func:`require` before it is
   claimed. A leaf production is checked with ``rwhois_abnf_match.matches``; a
   composite (which the recognizer module deliberately leaves unpatterned) is checked
   against the transcription in :func:`_transcriptions`, written straight from the ABNF
   text in ``rwhois_grammar.PRODUCTIONS``. A violation raises
   :class:`AbnfGenerationError` rather than dropping the case, because a corpus that
   silently skips is worse than no corpus: it reads as coverage that never happened.
2. **Witnesses, not assertions.** Each case records, per claimed production, the exact
   string from its own transcript that instantiates it. :func:`validate_case` re-checks
   every witness against the recognizer *and* against the rendered transcript, so a
   claim cannot be decorative ("this case touches ``authority-area``") unless the bytes
   are really there.
3. **Determinism.** Values are drawn from ``random.Random(zlib.crc32(case_id))`` — a
   stable hash, never the builtin ``hash()`` (PYTHONHASHSEED varies), never the clock,
   never dict ordering. Two runs produce byte-identical transcripts and manifest.

Two specification problems are encoded rather than hidden:

* ``query-string``. Section 3.4 is ``["*"] 1*query-char ["*"]`` (wildcard front and/or
  end); Appendix B is ``1*query-char ["*"]`` (end only). ``registrata`` follows section
  3.4, so both ``*vogon`` and ``vogon*`` are generated. The leading-star cases assert
  the contradiction itself — the witness must satisfy the 3.4 reading and must *not*
  satisfy the Appendix B reading — and say so in their ``note``.
* ``quoted-query-char`` includes the double quote, but ``registrata.query`` rejects a
  double quote anywhere in a value with ``InvalidQuerySyntax``, so a value with an inner
  quote cannot exist as a valid case. It is covered with the other two characters the
  production adds — space and tab. See :data:`DOCUMENTED_DEVIATIONS`.
"""

from __future__ import annotations

import functools
import pathlib
import random
import re
import sys
import zlib

CRLF = "\r\n"
_TOOLS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = _TOOLS_DIR.parent

#: Productions that cannot be exercised by a fixture, with the reason the coverage gate
#: should treat them as documented instead of missing. Kept as data so a gap is a
#: statement rather than a silence; :func:`uncovered` refuses to list a production here
#: that some case also claims.
UNCOVERABLE: dict[str, str] = {
    "key-id": (
        "Appendix B references key-id from pgp-data and never defines it, so there is no "
        "language to instantiate and no recognizer to check a value against; the bytes that "
        "follow the pgp method in abnf-directive-security are covered by pgp-data and "
        "security-data, which are defined"
    ),
}

#: Known gaps between the ABNF and the library, kept here so a case cannot quietly
#: claim them. Each value states what the grammar permits and what registrata does.
DOCUMENTED_DEVIATIONS: dict[str, str] = {
    "quoted-query-char": (
        "Appendix B puts the double quote inside quoted-query-char, but "
        "registrata.query rejects a double quote anywhere in a value with "
        "InvalidQuerySyntax, so no valid case can carry an inner quote: the production is "
        "exercised through the space and tab it adds instead."
    ),
    "query-string": (
        "section 3.4 allows a leading '*' and Appendix B does not; registrata follows 3.4, "
        "so the leading-star cases are 3.4-derived and contested, not uncontested wins."
    ),
    "attribute-value": (
        "any-char is octets 1..255, so NUL is outside the alphabet; the generator refuses "
        "NUL and no fixture carries one. registrata does not reject NUL either, so it "
        "could not be pinned as a malformed case without editing src."
    ),
    "key-id": (
        "Appendix B references key-id from pgp-data without defining it, so it is listed in "
        "UNCOVERABLE rather than claimed: no fixture can be an instance of a production that "
        "has no definition, and crediting the hex token to it would be a guess about a "
        "language the RFC never states."
    ),
}

#: Expectation keys ``tests/test_rwhois_corpus.py`` knows how to assert. Mirrors
#: KNOWN_KEYS there; writing a manifest entry the test cannot check would be a lie about
#: the fixture, so the generator refuses to emit one.
KNOWN_EXPECT_KEYS = frozenset(
    {
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
)


class AbnfGenerationError(RuntimeError):
    """Raised when an artifact would violate the production its case claims to cover."""


def _ensure_paths() -> None:
    """Make ``tools/`` and ``src/`` importable however this module was loaded.

    ``tools/rwhois_abnf_match.py`` imports ``rwhois_grammar`` by bare name and the
    library cross-checks import ``registrata`` from ``src``. Doing this in a function
    keeps the module-level import block clean (ruff E402) and lets the generator run
    from any working directory.
    """
    for path in (_TOOLS_DIR, REPO_ROOT / "src"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def _recognizers():
    """Return ``(matches, PATTERNS, PRODUCTIONS)`` from the independent checker."""
    _ensure_paths()
    from rwhois_abnf_match import PATTERNS, matches
    from rwhois_grammar import PRODUCTIONS

    return matches, PATTERNS, PRODUCTIONS


def _library():
    """Return the library callables that prove generated client lines are usable."""
    _ensure_paths()
    from registrata.errors import RwhoisError
    from registrata.query import parse_query
    from registrata.records import Referral

    return parse_query, Referral, RwhoisError


def _fragments() -> dict[str, str]:
    """Building blocks for the transcriptions below, reused so copies cannot drift.

    The primitives come from ``rwhois_abnf_match`` (host-name, authority-area, e-mail,
    time-stamp, capability-id, version-number, host-port, query-char) because a second
    transcription of those is where a checker and a generator would disagree. Only the
    composites the recognizer module deliberately leaves unpatterned are spelled out
    here, straight from the ABNF text in ``rwhois_grammar.PRODUCTIONS``.
    """
    from rwhois_abnf_match import (
        ANY_CHAR,
        AUTHORITY_AREA,
        CAPABILITY_ID,
        EMAIL,
        HOST_NAME,
        HOST_PORT,
        ID_CHAR,
        OBJECT_ID,
        QUERY_CHAR,
        TIME_STAMP,
        VERSION_NUMBER,
    )

    crlf = r"\r\n"
    opt_crlf = rf"(?:{crlf})?"  # terminator, optional because witnesses often omit it
    name = rf"{ID_CHAR}+"  # class-name / attribute-name / meta-field
    val = rf"{ANY_CHAR}+"  # attribute-value / meta-value / error-text
    star = r"\*?"
    digits = r"[0-9]+"
    # quoted-query-char is query-char / space / tab / DQUOTE. The DQUOTE alternative is
    # omitted on purpose: registrata rejects an inner quote, and an unescaped quote inside
    # a quoted string has no non-ambiguous regex. DOCUMENTED_DEVIATIONS says so.
    qq_char = rf"(?:{QUERY_CHAR}| |\t)"
    qs_bare_34 = rf"{star}{QUERY_CHAR}+{star}"  # section 3.4: front and/or end
    qs_bare_b = rf"{QUERY_CHAR}+{star}"  # Appendix B: end only
    qs_quoted_34 = rf'"{star}{qq_char}+{star}"'
    qs_quoted_b = rf'"{QUERY_CHAR}+{star}"'
    version = rf"{VERSION_NUMBER}(?::{CAPABILITY_ID})?"
    ok = r"%ok"
    error_line = rf"%error {digits} {val}"
    info_block = rf"%info on{crlf}(?:{ANY_CHAR}*{crlf})*%info off{crlf}"
    response = rf"(?:{ok}|{error_line}|{info_block}){opt_crlf}"
    query_atom = (
        rf"(?:{name}=(?:{qs_bare_34}|{qs_quoted_34})|(?:{qs_bare_34}|{qs_quoted_34}))"
    )
    # `query -> query bin-boolean query` is left-recursive as written; the grammar's own
    # note reads a boolean chain as nesting, so a flat chain is the transcribed language.
    query = rf"{query_atom}(?: (?:and|or) {query_atom})*"
    referral_url = rf"rwhois://{HOST_PORT}/auth-area={AUTHORITY_AREA}"
    # attribute-def's parts each begin with their own space, and every part is optional,
    # so `*attribute-def` in xfer-dir can loop on the empty string (see the grammar note).
    attribute_def = rf"(?: class={name})?(?: attribute={name})*"
    return {
        "ANY_CHAR": ANY_CHAR,
        "ID_CHAR": ID_CHAR,
        "NAME": name,
        "VAL": val,
        "CRLF": crlf,
        "OPT_CRLF": opt_crlf,
        "DIGITS": digits,
        "EMAIL": EMAIL,
        "HOST_NAME": HOST_NAME,
        "HOST_PORT": HOST_PORT,
        "OBJECT_ID": OBJECT_ID,
        "AUTHORITY_AREA": AUTHORITY_AREA,
        "TIME_STAMP": TIME_STAMP,
        "VERSION_NUMBER": VERSION_NUMBER,
        "VERSION": version,
        "QUERY_CHAR": QUERY_CHAR,
        "QQ_CHAR": qq_char,
        "QS_BARE_34": qs_bare_34,
        "QS_BARE_APPB": qs_bare_b,
        "QS_QUOTED_34": qs_quoted_34,
        "QS_QUOTED_APPB": qs_quoted_b,
        "QUERY": query,
        "QUERY_ATOM": query_atom,
        "OK": ok,
        "ERROR_LINE": error_line,
        "INFO_BLOCK": info_block,
        "RESPONSE": response,
        "REFERRAL_URL": referral_url,
        "RWHOIS_QUERY": rf"(?:{name} )?{query}",
        "RWHOIS_DIR": rf"-rwhois {VERSION_NUMBER}(?: {val})?",
        "CLASS_DIR": rf"-class {AUTHORITY_AREA}(?: {name})*",
        "DIRECTIVE_DIR": rf"-directive(?: {name})*",
        "DISPLAY_DIR": rf"-display(?: {name})?",
        "HOLDCONNECT_DIR": r"-holdconnect (?:on|off)",
        "LIMIT_DIR": rf"-limit {digits}",
        "QUIT_DIR": r"-quit",
        "SCHEMA_DIR": rf"-schema {AUTHORITY_AREA}(?: {name})*",
        "SOA_DIR": rf"-soa(?: {AUTHORITY_AREA})*",
        "STATUS_DIR": r"-status",
        "ATTRIBUTE_DEF": attribute_def,
        "XFER_DIR": rf"-xfer {AUTHORITY_AREA}(?:{attribute_def})*(?: {TIME_STAMP})?",
        # x-dir = "-X-" x-directive [space *[x-arguments]]; since x-arguments is itself
        # *any-char, `*(space *any-char)` and `space? any-char*` describe the same text,
        # and the latter does not make the matcher backtrack across every space.
        "X_DIR": rf"-X-{name}(?: {ANY_CHAR}*)?",
        "SERIAL_NUMBER": TIME_STAMP,
        "REFERRAL_LINE": rf"%referral {referral_url}",
        "QUERY_LINE": rf"{name}:{name}(?:;[TIS])?:{val}",
        "TYPE_CHAR": r"[TIS]",
        "KEY_ID": r"(?:0x)?[0-9A-Fa-f]{8,16}",
    }


@functools.lru_cache(maxsize=1)
def _transcriptions() -> dict[str, str]:
    """One pattern per production that ``rwhois_abnf_match`` deliberately leaves open.

    Those are composites over other productions, so the recognizer module declines to
    transcribe them and the generator must still prove it emitted the shape it claims.
    Where the ABNF ends a production with ``crlf`` the pattern accepts it optionally: a
    witness is usually one wire line stored without its terminator, while a multi-line
    witness (a record, a dialogue) carries its own.
    """
    f = _fragments()
    crlf, opt_crlf = f["CRLF"], f["OPT_CRLF"]
    name, val = f["NAME"], f["VAL"]
    digits, email, area = f["DIGITS"], f["EMAIL"], f["AUTHORITY_AREA"]
    host_port, stamp, obj_id = f["HOST_PORT"], f["TIME_STAMP"], f["OBJECT_ID"]
    any_char, version, response = f["ANY_CHAR"], f["VERSION"], f["RESPONSE"]
    line = rf"(?:{any_char}*{crlf})"  # one arbitrary line, terminator included
    blank = rf"(?:{crlf}{any_char})*"  # records are blank-line separated on the wire

    def repeated(pattern: str) -> str:
        """``1*pattern crlf`` — the shape every record family is built from."""
        return rf"(?:{pattern}{crlf})+"

    tx: dict[str, str] = {}

    # Responses and the banner.
    tx["response"] = response
    tx["info-response"] = rf"%info on{crlf}{line}*%info off{crlf}"
    tx["version-list"] = rf"{version}(?:,{version})*"
    tx["rwhois-banner"] = (
        rf"%rwhois {tx['version-list']} {f['HOST_NAME']}(?: {val})?{opt_crlf}"
    )
    tx["rwhois-response"] = rf"%rwhois {version} {f['HOST_NAME']}(?: {val})?{opt_crlf}"

    # Query results: records of attribute lines, and records of referral lines.
    tx["query-line"] = f["QUERY_LINE"]
    tx["query-record"] = repeated(f["QUERY_LINE"])
    tx["referral-url"] = f["REFERRAL_URL"]
    tx["referral-line"] = f["REFERRAL_LINE"]
    tx["referral-record"] = repeated(f["REFERRAL_LINE"])
    tx["rwhois-query-result"] = (
        rf"(?:(?:{tx['query-record']}|{tx['referral-record']}){blank})*{response}"
    )

    # The optional directive response families: lines, the record they close, and the
    # response group that is zero or more records followed by a response.
    tx["class-line"] = (
        rf"%class {name}:description:{val}|%class {name}:version:{stamp}"
        rf"|%class {name}:{name}:{val}"
    )
    tx["class-record"] = rf"{repeated(tx['class-line'])}?%class{crlf}"
    tx["class-response"] = rf"(?:(?:{tx['class-record']}){blank})*{response}"
    tx["directive-line"] = rf"%directive (?:description:{val}|{name}:{val})"
    tx["directive-record"] = (
        rf"%directive directive:{name}{crlf}(?:{tx['directive-line']}{crlf})*%directive{crlf}"
    )
    tx["directive-response"] = rf"(?:(?:{tx['directive-record']}){blank})*{response}"
    tx["display-line"] = rf"%display {name}:{val}"
    tx["display-record"] = (
        rf"%display name:{name}{crlf}(?:{tx['display-line']}{crlf})*%display{crlf}"
    )
    tx["display-response"] = rf"(?:(?:{tx['display-record']}){blank})*{response}"
    tx["schema-line"] = rf"%schema {name}:{name}:{val}"
    tx["schema-record"] = rf"{repeated(tx['schema-line'])}?%schema{crlf}"
    tx["schema-response"] = rf"(?:(?:{tx['schema-record']}){blank})*{response}"
    tx["soa-line"] = (
        rf"%soa authority:{area}"
        rf"|%soa (?:ttl|refresh|increment|retry):{digits}"
        rf"|%soa serial:{stamp}"
        rf"|%soa (?:tech-contact|admin-contact|hostmaster):{email}"
        rf"|%soa primary:{host_port}"
        rf"|%soa {name}:{val}"
    )
    tx["soa-record"] = rf"{repeated(tx['soa-line'])}?%soa{crlf}"
    tx["soa-response"] = rf"(?:(?:{tx['soa-record']}){blank})*{response}"
    tx["status-line"] = (
        rf"%status (?:limit|authority):{digits}"
        rf"|%status (?:holdconnect|forward):(on|off)"
        rf"|%status display:{val}"
        rf"|%status contact:{email}"
        rf"|%status {name}:{val}"
    )
    tx["status-response"] = rf"{repeated(tx['status-line'])}?{blank}{response}"
    tx["xfer-line"] = rf"%xfer {name}:{name}:{val}"
    tx["xfer-record"] = rf"{repeated(tx['xfer-line'])}?%xfer{crlf}"
    tx["xfer-response"] = rf"(?:(?:{tx['xfer-record']}){blank})*{response}"

    # Registration: the client dialogue and the two shapes of its final response.
    tx["register-line"] = rf"{name}:{val}"
    tx["register-on"] = r"-register on"
    tx["register-off"] = rf"-register off{opt_crlf}"
    added, deleted = repeated(tx["register-line"]), repeated(tx["register-line"])
    tx["register-add"] = added
    tx["register-del"] = deleted
    tx["register-mod"] = rf"{added}_NEW_{crlf}{added}"
    tx["register-dir"] = (
        rf"-register on add {email}{crlf}{added}-register off{crlf}"
        rf"|-register on mod {email}{crlf}{tx['register-mod']}-register off{crlf}"
        rf"|-register on del {email}{crlf}{deleted}-register off{crlf}"
    )
    tx["register-on-response"] = response
    tx["register-off-response"] = (
        rf"%register ID:{obj_id}{crlf}{response}"
        rf"|%register Updated:{stamp}{crlf}{response}"
        rf"|{response}"
    )

    # Security: the directive, its payload, and the response it is answered with.
    tx["key-id"] = f["KEY_ID"]
    tx["pgp-data"] = rf"(?:signed-encrypt|signed|encrypt)(?: {tx['key-id']})?"
    tx["security-data"] = rf"{val}|{tx['pgp-data']}"
    tx["security-payload"] = rf"{line}*"
    tx["security-dir"] = (
        rf"-security on (?:request|response) (?:password|pgp|{name})(?: {tx['security-data']})?"
        rf"{crlf}{tx['security-payload']}(?:-security off{crlf})?"
    )
    tx["security-response"] = response

    # Notify: a referral URL plus the query that triggered it, or a host-port/area pair.
    tx["referral-query"] = rf"{f['REFERRAL_URL']} (?:{name} )?{f['QUERY']}"
    tx["notify-dir"] = (
        rf"-notify (?:badref|recurref) {tx['referral-query']}"
        rf"|-notify (?:update|inssec|delsec) {host_port}:{area}"
    )
    tx["notify-response"] = response

    # Queries, including both readings of query-string (see the module docstring).
    tx["query-string"] = rf"{f['QS_BARE_34']}|{f['QS_QUOTED_34']}"
    tx["quoted-query-char"] = rf"(?:{f['QUERY_CHAR']}| |\t|\")"
    tx["attribute-query"] = rf"{name}=(?:{f['QS_BARE_34']}|{f['QS_QUOTED_34']})"
    tx["query"] = f["QUERY"]
    tx["rwhois-query"] = rf"{f['RWHOIS_QUERY']}{opt_crlf}"
    tx["attribute-def"] = f["ATTRIBUTE_DEF"]

    # Client directives, and the protocol-wide alternations built from them.
    tx["rwhois-dir"] = f["RWHOIS_DIR"]
    tx["class-dir"] = f["CLASS_DIR"]
    tx["directive-dir"] = f["DIRECTIVE_DIR"]
    tx["display-dir"] = f["DISPLAY_DIR"]
    tx["holdconnect-dir"] = f["HOLDCONNECT_DIR"]
    tx["limit-dir"] = f["LIMIT_DIR"]
    tx["quit-dir"] = f["QUIT_DIR"]
    tx["schema-dir"] = f["SCHEMA_DIR"]
    tx["soa-dir"] = f["SOA_DIR"]
    tx["status-dir"] = f["STATUS_DIR"]
    tx["xfer-dir"] = f["XFER_DIR"]
    tx["x-dir"] = f["X_DIR"]
    tx["holdconnect-response"] = response
    tx["limit-response"] = response
    tx["quit-response"] = response
    tx["x-response"] = rf"{line}*{response}"
    tx["directives"] = "|".join(
        tx[key]
        for key in (
            "rwhois-dir",
            "class-dir",
            "directive-dir",
            "display-dir",
            "holdconnect-dir",
            "limit-dir",
            "notify-dir",
            "quit-dir",
            "register-dir",
            "schema-dir",
            "security-dir",
            "soa-dir",
            "status-dir",
            "xfer-dir",
            "x-dir",
        )
    )
    # ``x-response = *(*any-char crlf) response`` accepts any text that ends in a
    # response, so a whole server dialogue is a witness for the alternations above it.
    tx["responses"] = rf"{line}*{response}"
    tx["server-returns"] = rf"(?:{line})*{response}"
    tx["client-sends"] = rf"(?:(?:{tx['directives']}|{f['RWHOIS_QUERY']}){opt_crlf})+"
    tx["rwhois-protocol"] = rf"{tx['client-sends']}|{tx['server-returns']}"
    return tx


def require(production: str, value: str) -> str:
    """Assert ``value`` is exactly one instance of ``production``, then return it.

    Leaf productions are checked by ``rwhois_abnf_match``, which is deliberately not
    this module: if the generator and the checker were the same code, a wrong generator
    would emit wrong fixtures and still pass. Composites are checked against the
    transcription above. Either way a violation raises instead of skipping.
    """
    matches, patterns, productions = _recognizers()
    if production not in productions:
        raise AbnfGenerationError(f"unknown production {production!r}")
    if production in patterns:
        if not matches(production, value):
            raise AbnfGenerationError(
                f"{production}: {value!r} is rejected by the recognizer for "
                f"{patterns[production]!r}"
            )
        return value
    pattern = _transcriptions().get(production)
    if pattern is None:
        raise AbnfGenerationError(f"{production}: nothing to check the value against")
    if re.fullmatch(pattern, value) is None:
        raise AbnfGenerationError(f"{production}: {value!r} does not match the ABNF")
    return value


def query_string_matches(value: str, reading: str) -> bool:
    """True when ``value`` satisfies ``query-string`` under one named reading.

    ``reading`` is ``"3.4"`` (``["*"] 1*query-char ["*"]``, wildcard front and/or end) or
    ``"appendix-b"`` (``1*query-char ["*"]``, trailing only). The readings differ exactly
    for a leading ``*``, so the leading-star cases assert both answers rather than
    quietly picking one.
    """
    fragments = _fragments()
    patterns = {
        "3.4": rf"(?:{fragments['QS_BARE_34']}|{fragments['QS_QUOTED_34']})",
        "appendix-b": rf"(?:{fragments['QS_BARE_APPB']}|{fragments['QS_QUOTED_APPB']})",
    }
    if reading not in patterns:
        raise AbnfGenerationError(f"unknown query-string reading {reading!r}")
    return re.fullmatch(patterns[reading], value) is not None


def uses_leading_wildcard(value: str, reading: str) -> bool:
    """True when ``reading`` derives ``value`` through its optional leading ``"*"``.

    This asks about the *derivation*, not about membership, and that distinction is the
    whole contradiction: ``*`` is itself a query-char, so the bytes ``*vogon`` are a
    legal Appendix B ``query-string`` read as a literal star. Only section 3.4 has a
    ``["*"]`` slot in front, so only 3.4 reads the same bytes as a leading wildcard.
    """
    if reading not in {"3.4", "appendix-b"}:
        raise AbnfGenerationError(f"unknown query-string reading {reading!r}")
    core = value[1:-1] if value.startswith('"') and value.endswith('"') else value
    return core.startswith("*") and reading == "3.4"


class Wire:
    """One transcript under construction plus the ABNF witnesses it carries.

    Every value that reaches a line goes through :func:`require` at the moment it is
    claimed, so an invalid artifact aborts generation before anything is written. The
    witness strings are re-checked against the finished transcript by
    :func:`validate_case`, which is what stops a claim naming a production the file
    never actually exercises.
    """

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self.lines: list[str] = []
        self.evidence: dict[str, list[str]] = {}
        self.rng = random.Random(zlib.crc32(case_id.encode("utf-8")))

    # -- claiming -------------------------------------------------------------
    def claim(self, production: str, witness: str) -> "Wire":
        require(production, witness)
        seen = self.evidence.setdefault(production, [])
        if witness not in seen:
            seen.append(witness)
        return self

    def line(self, text: str, *claims: tuple[str, str]) -> str:
        """Append one wire line and claim each ``(production, witness)`` pair on it."""
        for char in text:
            if char in "\r\n\x00":
                raise AbnfGenerationError(
                    f"{self.case_id}: line {text!r} holds {char!r}, which is outside any-char"
                )
        self.lines.append(text)
        for production, witness in claims:
            self.claim(production, witness if witness is not None else text)
        return text

    def mark(self) -> int:
        """Index of the next line, for building a multi-line witness with :meth:`span`."""
        return len(self.lines)

    def span(self, start: int, *productions: str) -> "Wire":
        """Claim ``productions`` over the lines added since ``start``, crlf included."""
        if start >= len(self.lines):
            raise AbnfGenerationError(f"{self.case_id}: empty span at line {start}")
        witness = CRLF.join(self.lines[start:]) + CRLF
        for production in productions:
            self.claim(production, witness)
        return self

    # -- output ---------------------------------------------------------------
    def rendered(self) -> str:
        return CRLF.join(self.lines) + CRLF

    def case(
        self,
        parser: str,
        note: str,
        expect: dict,
        *,
        kind: str = "valid",
        roundtrip: list[str] | None = None,
        raw: str | None = None,
        extra: dict | None = None,
    ) -> dict:
        """Finish the case. ``raw`` overrides the line join for wire-shaped fixtures."""
        if unknown := set(expect) - KNOWN_EXPECT_KEYS:
            raise AbnfGenerationError(
                f"{self.case_id}: manifest keys {sorted(unknown)} unknown"
            )
        case = {
            "id": self.case_id,
            "parser": parser,
            "kind": kind,
            "note": note,
            "expect": expect,
            "abnf": sorted(self.evidence),
            "evidence": {
                key: list(value) for key, value in sorted(self.evidence.items())
            },
        }
        if raw is not None:
            case["raw"] = raw
        else:
            case["lines"] = list(self.lines)
        if roundtrip:
            case["roundtrip"] = list(roundtrip)
        if extra:
            case.update(extra)
        return case


# -------------------------------------------------------------------------- tokens
#
# Every generator below returns a value that :func:`require` has already accepted for
# the production it belongs to. Randomness is confined to a ``random.Random`` seeded
# from ``zlib.crc32(case_id)``, so a case regenerates identically no matter when, where,
# or in what order the other cases were built.

WORDS = (
    "vogon",
    "joltafari",
    "marvin",
    "eddie",
    "slartibartfast",
    "deepthought",
    "magrathea",
)
AREA_WORDS = ("example", "rwhois", "subdomain", "nic", "hostmaster")
DOMAIN_SUFFIXES = ("net", "com", "org")
ID_WORDS = ("EXAMPLE", "TEST", "NETWORK", "DOMAIN", "CONTACT", "HOST")
ATEXT = "0123456789abcdefghijklmnopqrstuvwxyz!#$%&'*+-/=?^_`{|}~"
HIGH_OCTETS = "\x80\xa0\xc7\xe9\xf0\xfe\xff"  # any-char's upper half: octets 128..255
PUNCT = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"


def _pick(rng: random.Random, pool: tuple[str, ...] | str) -> str:
    return pool[rng.randrange(len(pool))]


def t_alpha(rng: random.Random) -> str:
    return require("alpha", _pick(rng, "abcdefghijklmnopqrstuvwxyz"))


def t_digit(rng: random.Random) -> str:
    return require("digit", _pick(rng, "0123456789"))


def t_class_name(rng: random.Random, stem: str | None = None) -> str:
    if stem is not None:
        return require("class-name", stem)
    return require(
        "class-name",
        f"{_pick(rng, ('domain', 'network', 'person', 'map'))}{t_digit(rng)}",
    )


def t_host_name(rng: random.Random) -> str:
    labels = [_pick(rng, AREA_WORDS)]
    if rng.randrange(2):
        labels.insert(0, f"ns{rng.randrange(1, 9)}")
    labels.append(_pick(rng, DOMAIN_SUFFIXES))
    return require("host-name", ".".join(labels))


def t_ip_address(rng: random.Random) -> str:
    prefix = _pick(
        rng, ("192.0.2", "198.51.100", "203.0.113")
    )  # RFC 5737 documentation
    return require("ip-address", f"{prefix}.{rng.randrange(1, 255)}")


def t_port(rng: random.Random) -> int:
    # host-port allows 1*5digit, so 99999 is in the language. registrata's Referral only
    # accepts 1..65535, so generated ports stay inside the range both readings allow.
    return rng.randrange(1024, 65536)


def t_authority_area(rng: random.Random, cidr: bool = False) -> str:
    if cidr:
        return require(
            "authority-area",
            f"{t_ip_address(rng)}/{_pick(rng, ('8', '16', '24', '32'))}",
        )
    return require(
        "authority-area", f"{_pick(rng, AREA_WORDS)}.{_pick(rng, DOMAIN_SUFFIXES)}"
    )


def t_object_id(rng: random.Random) -> str:
    stem = _pick(rng, ID_WORDS)
    return require(
        "object-id", f"{stem}-DNS-{rng.randrange(1, 99):02d}.{t_authority_area(rng)}"
    )


def t_email(rng: random.Random) -> str:
    local = "".join(
        _pick(rng, ATEXT.replace(".", "")) for _ in range(rng.randrange(4, 9))
    )
    local = f"{t_alpha(rng)}{local.strip('-_')}"
    return require("email", f"{local}@{t_host_name(rng)}")


def t_time_stamp(rng: random.Random) -> str:
    parts = (
        f"{rng.randrange(1995, 2030)}",
        f"{rng.randrange(1, 13):02d}",
        f"{rng.randrange(1, 29):02d}",
        f"{rng.randrange(0, 24):02d}",
        f"{rng.randrange(0, 60):02d}",
        f"{rng.randrange(0, 60):02d}",
        f"{rng.randrange(0, 1000):03d}",
    )
    # The 17 digits are year month day hour minute second milli-second; each part is
    # checked on its own so a transcription that mixes the widths is caught here.
    for production, value in zip(
        ("year", "month", "day", "hour", "minute", "second", "milli-second"), parts
    ):
        require(production, value)
    return require("time-stamp", "".join(parts))


def t_capability_id(rng: random.Random) -> str:
    response_id = "".join(_pick(rng, "0123456789abcdef") for _ in range(6))
    extra_id = _pick(rng, ("00", "ff"))
    require("response-id", response_id)
    require("extra-id", extra_id)
    return require("capability-id", f"{response_id}:{extra_id}")


def t_version_number(rng: random.Random) -> str:
    return require("version-number", f"V-1.{_pick(rng, '015')}")


def t_version(rng: random.Random, capability: bool = True) -> str:
    number = t_version_number(rng)
    return require(
        "version", number if not capability else f"{number}:{t_capability_id(rng)}"
    )


def t_attribute_value(rng: random.Random, flavour: str = "plain") -> str:
    """A value for ``attribute-value = 1*any-char``: octets 1..255, never CR, LF or NUL."""
    stem = _pick(rng, ID_WORDS).title()
    if flavour == "8bit":
        body = f"Caf{HIGH_OCTETS[5]} {stem}, Inc."
    elif flavour == "high":
        body = "".join(require("any-char", octet) for octet in HIGH_OCTETS)
    elif flavour == "punct":
        body = f"{stem}{PUNCT}"
    elif flavour == "colon":
        body = f"Source:{_pick(rng, ('ARIN', 'RIPE'))}"
    else:
        body = f"{stem} {_pick(rng, WORDS)}"
    return require("attribute-value", body)


def t_query_token(
    rng: random.Random, leading: bool = False, trailing: bool = False
) -> str:
    word = _pick(rng, WORDS)
    token = f"{'*' if leading else ''}{word}{'*' if trailing else ''}"
    for char in word:
        require("query-char", char)
    return require("query-string", token)


def t_quoted_query(rng: random.Random, tab: bool = False) -> str:
    """A quoted query string using the space (optionally tab) quoted-query-char adds."""
    separator = "\t" if tab else " "
    inner = f"{_pick(rng, WORDS)}{separator}{_pick(rng, WORDS)}"
    require("quoted-query-char", separator)
    return require("query-string", f'"{inner}"')


def t_on_off(rng: random.Random) -> str:
    return require("on-off", _pick(rng, ("on", "off")))


def t_bin_boolean(rng: random.Random) -> str:
    return require("bin-boolean", _pick(rng, ("and", "or")))


def t_key_id(rng: random.Random) -> str:
    # key-id is referenced by pgp-data and never defined by Appendix B, so this is the
    # conventional hex key identifier rather than a value a recognizer can validate.
    digits = "".join(_pick(rng, "0123456789ABCDEF") for _ in range(8))
    return require("key-id", f"0x{digits}")


# ----------------------------------------------------------------------- witnesses

#: How many characters a witness for a production spans. Everything else is one.
_WIDTHS = {"crlf": 2}


def claim_first(
    w: Wire, haystack: str, production: str, width: int | None = None
) -> str:
    """Claim the first span of ``haystack`` that is one instance of ``production``.

    Used for the character classes (``alpha``, ``digit``, ``any-char``, ``crlf``): the
    witness is lifted out of bytes the transcript really contains rather than invented,
    and a class the transcript never uses raises instead of going unclaimed.
    """
    span = _WIDTHS.get(production, 1) if width is None else width
    for start in range(max(len(haystack) - span, 0) + 1):
        needle = haystack[start : start + span]
        try:
            w.claim(production, needle)
        except AbnfGenerationError:
            continue
        return needle
    raise AbnfGenerationError(
        f"{w.case_id}: nothing in {haystack[:60]!r} is an instance of {production}"
    )


def claim_chars(w: Wire, value: str, *productions: str) -> None:
    """Claim each character class listed from whichever byte of ``value`` is one."""
    for production in productions:
        claim_first(w, value, production)


def claim_terminators(w: Wire, *productions: str) -> None:
    """Claim line endings and separators from the transcript's own rendered bytes."""
    rendered = w.rendered()
    wanted = productions or ("crlf", "cr", "lf")
    claim_chars(w, rendered, *wanted)


def emit_attribute(
    w: Wire,
    class_name: str,
    attribute: str,
    value: str,
    type_char: str | None = None,
    *extra: tuple[str, str],
) -> str:
    """Emit ``query-line`` (``class-name ":" attribute-name [[";" type-char]] ":" value``)."""
    suffix = f";{type_char}" if type_char else ""
    line = f"{class_name}:{attribute}{suffix}:{value}"
    claims = [
        ("query-line", line),
        ("class-name", class_name),
        ("attribute-name", attribute),
        ("attribute-value", value),
    ]
    if type_char:
        claims.append(("type-char", type_char))
    w.line(line, *claims, *extra)
    return line


def check_query_line(w: Wire, line: str) -> str:
    """Prove the library accepts the query the ABNF accepts, or report the finding.

    The corpus is generated from the specification, not from the library, so a library
    that rejects an ABNF-valid query is a finding to raise rather than a reason to bend
    the generator. ``src`` is never edited to make a fixture pass.
    """
    parse_query, _, rwhois_error = _library()
    try:
        query = parse_query(line)
        rebuilt = parse_query(query.to_wire())
    except rwhois_error as exc:
        raise AbnfGenerationError(
            f"{w.case_id}: registrata rejects the ABNF-valid query {line!r}: {exc}"
        ) from exc
    if rebuilt.to_wire() != query.to_wire():
        raise AbnfGenerationError(
            f"{w.case_id}: query {line!r} does not survive a library round-trip "
            f"({query.to_wire()!r} != {rebuilt.to_wire()!r})"
        )
    return line


def check_referral_url(w: Wire, url: str) -> str:
    """Same idea as :func:`check_query_line`, for ``referral-url``."""
    _, referral, rwhois_error = _library()
    require("referral-url", url)
    try:
        parsed = referral.parse_url(url)
    except rwhois_error as exc:
        raise AbnfGenerationError(
            f"{w.case_id}: registrata rejects the ABNF-valid referral URL {url!r}: {exc}"
        ) from exc
    if parsed.url != url:
        raise AbnfGenerationError(
            f"{w.case_id}: referral URL {url!r} re-serializes as {parsed.url!r}"
        )
    return url


def answer(w: Wire) -> str:
    """Terminate a dialogue with ``%ok`` and claim it as the response to what precedes."""
    return w.line("%ok", ("ok-response", "%ok"), ("response", "%ok"))


# --------------------------------------------------------------------- validation


def transcript_text(case: dict) -> str:
    """The bytes a case will write, so witnesses are checked against the real artifact."""
    raw = case.get("raw")
    if raw is not None:
        return raw
    if "lines" not in case:
        raise AbnfGenerationError(f"{case.get('id')}: case has neither lines nor raw")
    return CRLF.join(case["lines"]) + CRLF


def validate_case(case: dict) -> dict:
    """Re-check a finished generated case, then hand it back unchanged.

    Three things must hold: every claim names a production in the Appendix B inventory,
    every witness really instantiates that production, and every witness appears in the
    transcript the case writes. The third rule is what makes the ``abnf`` list evidence
    instead of commentary.
    """
    _, _, productions = _recognizers()
    case_id = case.get("id", "<no id>")
    if not case_id.startswith("abnf-"):
        raise AbnfGenerationError(
            f"{case_id}: generated case ids must start with 'abnf-'"
        )
    claims = list(case.get("abnf", []))
    evidence = case.get("evidence", {})
    unknown = sorted(set(claims) - set(productions))
    if unknown:
        raise AbnfGenerationError(f"{case_id}: not productions of RFC 2167: {unknown}")
    if set(claims) != set(evidence):
        raise AbnfGenerationError(
            f"{case_id}: claims {sorted(set(claims) - set(evidence))} without a witness and "
            f"witnesses {sorted(set(evidence) - set(claims))} that are never claimed"
        )
    text = transcript_text(case)
    for production, witnesses in sorted(evidence.items()):
        if not witnesses:
            raise AbnfGenerationError(
                f"{case_id}: {production} claims an empty witness list"
            )
        for witness in witnesses:
            require(production, witness)
            if witness not in text:
                raise AbnfGenerationError(
                    f"{case_id}: claims {production} but its witness {witness!r} is not in "
                    "the transcript"
                )
    return case


def _candidates(text: str, longest_span: int = 12) -> list[str]:
    """Substrings of ``text`` an automatic witness may be found in.

    Used for the hand-written cases, whose transcripts predate this generator and which
    therefore have no recorded witnesses: a claim is accepted only if some substring of
    the fixture is an instance of the production, so an annotation cannot be invented.
    The extraction patterns pull out the shapes a split alone cannot reach (a whole
    referral URL, a host-port pair, an e-mail address inside a value).
    """
    candidates = ["\r\n", "\r", "\n", " ", "\t", text]
    # Extraction and splitting are quadratic on a 200 KB junk line, and no witness a
    # legacy fixture needs lives past its first screenful. The `in text` filter below
    # still proves every candidate is really a substring of the whole transcript.
    probe = text if len(text) <= 8192 else text[:8192]
    for line in re.split(r"\r\n|\n|\r", probe):
        candidates.append(line)
        candidates.extend(re.split(r"[ \t]", line))
        candidates.extend(re.split(r"[ \t:;,=/]", line))
    for pattern in (
        r"rwhois://[^\s]+",
        r"[0-9A-Fa-f]{6}:[0-9A-Fa-f]{2}",
        r"[A-Za-z0-9][A-Za-z0-9.-]*:[0-9]{1,5}",
        r"[A-Za-z0-9!#$%&'*+-/=?^_`{|}~]+@[A-Za-z0-9.-]+",
        r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?",
    ):
        candidates.extend(re.findall(pattern, probe))
    for run in re.findall(r"[0-9A-Za-z]+", probe):
        # A long run is a value, not a leaf witness: only its first characters are
        # sliced, or a 200 KB junk line would generate a million candidates.
        window = run if len(run) <= 40 else run[:40]
        for width in (1, 2, 3, 4, 6, 17):
            candidates.extend(
                window[start : start + width]
                for start in range(max(len(window) - width, 0) + 1)
            )
    lines = text.split(CRLF)
    for start in range(len(lines)):
        for stop in range(start + 1, min(start + longest_span, len(lines)) + 1):
            candidates.append(CRLF.join(lines[start:stop]) + CRLF)
    seen: set[str] = set()
    unique: list[str] = []
    for candidate in candidates:
        # A composite witness is a record or a dialogue, never a 200 KB memory-bomb line,
        # and handing that to the protocol-wide alternations backtracks for minutes.
        if len(candidate) > 2048 or candidate in seen or candidate not in text:
            continue
        seen.add(candidate)
        unique.append(candidate)
    return unique


def find_witness(production: str, text: str) -> str | None:
    """Return a substring of ``text`` that instantiates ``production``, if one exists."""
    for candidate in _candidates(text):
        try:
            require(production, candidate)
        except AbnfGenerationError:
            continue
        return candidate
    return None


def validate_claims(case_id: str, claims: list[str], text: str) -> None:
    """Check hand-written claims the same way generated ones are, by searching for proof."""
    _, _, productions = _recognizers()
    for production in sorted(set(claims)):
        if production not in productions:
            raise AbnfGenerationError(
                f"{case_id}: {production!r} is not an Appendix B production"
            )
        if find_witness(production, text) is None:
            raise AbnfGenerationError(
                f"{case_id}: claims {production} but nothing in the transcript instantiates it"
            )


# ------------------------------------------------------------------------ cases
#
# One builder per protocol family. ``generate_cases`` runs them in this order, so the
# case list - and therefore the manifest - is identical on every machine and every run.

#: The seven time-stamp fields and their widths, in the order the ABNF concatenates them.
TIMESTAMP_FIELDS = (
    ("year", 4),
    ("month", 2),
    ("day", 2),
    ("hour", 2),
    ("minute", 2),
    ("second", 2),
    ("milli-second", 3),
)


def claim_time_stamp(w: Wire, stamp: str) -> None:
    """Claim ``time-stamp`` and each of the seven fields it is spelled from."""
    w.claim("time-stamp", stamp)
    offset = 0
    for production, width in TIMESTAMP_FIELDS:
        w.claim(production, stamp[offset : offset + width])
        offset += width


def case_lexicon_object() -> dict:
    """One object whose values span the ``any-char`` alphabet, octets 1 through 255.

    ``any-char`` excludes CR and LF because they end a line, and it excludes NUL by
    starting at 1: a value holding octet 0 is not an unfriendly value, it is not a
    value at all. The upper half is ordinary here - this is an 8-bit protocol.
    """
    w = Wire("abnf-lexicon-object")
    rng = w.rng
    cls = t_class_name(rng, "domain")
    obj_id = t_object_id(rng)
    area = t_authority_area(rng, cidr=True)
    host = t_host_name(rng)
    network = t_ip_address(rng)
    primary = f"{network}:{t_port(rng)}"
    mail = t_email(rng)
    stamp = t_time_stamp(rng)
    name8 = t_attribute_value(rng, "8bit")
    punct = t_attribute_value(rng, "punct")
    colons = t_attribute_value(rng, "colon")
    plain = t_attribute_value(rng, "plain")

    start = w.mark()
    emit_attribute(w, cls, "Class-Name", cls)
    emit_attribute(w, cls, "ID", obj_id, None, ("object-id", obj_id))
    emit_attribute(
        w,
        cls,
        "Auth-Area",
        area,
        None,
        ("authority-area", area),
        ("ip-address", network),
    )
    emit_attribute(w, cls, "Generic-Server", host, None, ("host-name", host))
    emit_attribute(
        w,
        cls,
        "Primary-Server",
        primary,
        None,
        ("host-port", primary),
        ("ip-address", network),
    )
    emit_attribute(w, cls, "E-Mail", mail, None, ("email", mail))
    emit_attribute(w, cls, "Register-Name", name8, None, ("space", " "))
    emit_attribute(w, cls, "Punct-Value", punct)
    emit_attribute(w, cls, "Source", colons)
    emit_attribute(w, cls, "Created", stamp)
    emit_attribute(w, cls, "Numeric-Id", require("attribute-value", "42"), "I")
    emit_attribute(w, cls, "Tag-List", require("attribute-value", "red,green"), "S")
    emit_attribute(w, cls, "Explicit-Text", plain, "T")
    w.span(start, "query-record")
    claim_time_stamp(w, stamp)
    answer(w)
    w.span(start, "rwhois-query-result")
    claim_chars(
        w,
        w.rendered(),
        "alpha",
        "digit",
        "hex-digit",
        "id-char",
        "dns-char",
        "email-char",
        "any-char",
        "space",
    )
    claim_terminators(w)
    return w.case(
        "query",
        "attribute values spanning any-char: 8-bit octets, punctuation, and an embedded colon",
        {
            "ok": True,
            "objects": 1,
            "object_class": cls,
            "attribute_count": 13,
            "record_id": obj_id,
            "auth_area": area,
            "attributes": {
                "ID": [obj_id],
                "Auth-Area": [area],
                "Primary-Server": [primary],
                "E-Mail": [mail],
                "Register-Name": [name8],
                "Punct-Value": [punct],
                "Source": [colons],
                "Created": [stamp],
            },
            "attribute_types": {
                "Class-Name": "T",
                "Numeric-Id": "I",
                "Tag-List": "S",
                "Explicit-Text": "T",
            },
        },
        roundtrip=["objects"],
    )


def case_wire_octets() -> dict:
    """A raw transcript whose value uses the top of the octet range."""
    w = Wire("abnf-wire-octets")
    cls = t_class_name(w.rng, "domain")
    value = t_attribute_value(w.rng, "high")
    first = f"{cls}:Any-Char:{value}"
    w.line(
        first,
        ("query-line", first),
        ("class-name", cls),
        ("attribute-name", "Any-Char"),
        ("attribute-value", value),
    )
    for octet in value:
        w.claim("any-char", octet)
    w.line("%ok", ("ok-response", "%ok"), ("response", "%ok"))
    claim_terminators(w)
    return w.case(
        "wire",
        "any-char is octets 1..255, so 0x80-0xff are ordinary value bytes on the wire",
        {"decoded_exact": first},
        kind="wire",
        raw=w.rendered(),
    )


def case_wire_bare_lf() -> dict:
    """A server that sends bare LF: ``lf`` without ``cr``, so no ``crlf`` witness exists."""
    w = Wire("abnf-wire-bare-lf")
    cls = t_class_name(w.rng, "domain")
    name = f"{t_attribute_value(w.rng, 'plain')}.EXAMPLE.NET".upper().replace(" ", "-")
    first = f"{cls}:Domain-Name:{name}"
    w.line(
        first,
        ("query-line", first),
        ("class-name", cls),
        ("attribute-name", "Domain-Name"),
        ("attribute-value", name),
    )
    w.line("%ok", ("ok-response", "%ok"), ("response", "%ok"))
    w.claim("lf", "\n")
    return w.case(
        "wire",
        "bare-LF terminated transcript: lf is its own production and crlf is absent",
        {"decoded_exact": first},
        kind="wire",
        raw="\n".join(w.lines) + "\n",
    )


def emit_line(w: Wire, production: str, line: str, *claims: tuple[str, str]) -> str:
    """Emit a whole line as one instance of ``production`` plus any extra witnesses."""
    w.line(line, (production, line), *claims)
    return line


def close_record(w: Wire, start: int, terminator: str, family: str) -> None:
    """Close a record group and claim the record, the response, and the response group."""
    w.line(terminator)
    w.span(start, f"{family}-record")
    answer(w)
    w.span(start, f"{family}-response")


def close_response(w: Wire, start: int, family: str) -> None:
    """Answer a group of lines that has no record terminator (``%status`` has none)."""
    answer(w)
    w.span(start, f"{family}-response")


def case_response_error() -> dict:
    """``error-response`` with an Appendix C code and the text a client shows."""
    w = Wire("abnf-response-error")
    codes = {
        "230": ("No objects found", "NoObjectsFound"),
        "330": ("Exceeded maximum objects limit", "ExceededMaximumObjectsLimit"),
        "401": ("Not authorized for directive", "NotAuthorizedForDirective"),
        "503": ("Idle time exceeded", "IdleTimeExceeded"),
    }
    code = _pick(w.rng, tuple(codes))
    require("error-code", code)
    text = require("error-text", f"{codes[code][0]} \u00e9")
    line = emit_line(
        w,
        "error-response",
        f"%error {code} {text}",
        ("error-code", code),
        ("error-text", text),
        ("response", f"%error {code} {text}"),
        ("space", " "),
    )
    claim_chars(w, line, "alpha", "digit", "any-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "error-response with a three digit Appendix C code; the text carries an 8-bit octet",
        {
            "ok": False,
            "error_code": int(code),
            "error_text": text,
            "error_class": codes[code][1],
        },
        roundtrip=["error_line"],
    )


def case_response_info_block() -> dict:
    """``info-response``: an ``%info on`` ... ``%info off`` block, body included."""
    w = Wire("abnf-response-info-block")
    body = [
        "Server maintenance 02:00-03:00 UTC; retry later.",
        "Contact hostmaster@example.net about the outage \u00e0 la longue",
    ]
    start = w.mark()
    w.line("%info on")
    for text in body:
        w.line(text)
    w.line("%info off")
    w.span(start, "info-response")
    answer(w)
    claim_chars(w, w.rendered(), "any-char", "alpha", "digit", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "info-response block: body is any-char text, closed by %info off before the response",
        {"ok": True, "info_messages": body},
    )


def case_banner() -> dict:
    """Banner lines: version-list, both ``version`` alternates, capability-id, host-name."""
    w = Wire("abnf-banner-versions")
    rng = w.rng
    host_a, host_b = t_host_name(rng), t_host_name(rng)
    # 00ffff:00 is the capability id from the RFC's own banner example, so the capability
    # expectation below is checked against the library rather than assumed.
    capability = require("capability-id", "00ffff:00")
    require("response-id", "00ffff")
    require("extra-id", "00")
    first = require("version", f"{t_version_number(rng)}:{capability}")
    second = t_version(rng)
    bare = t_version(rng, capability=False)
    implementation = require(
        "implementation", f"(Example RWhoisd {t_version_number(rng)})"
    )
    version_list = require("version-list", f"{first},{second}")

    line = emit_line(
        w,
        "rwhois-banner",
        f"%rwhois {version_list} {host_b} {implementation}",
        ("version-list", version_list),
        ("version", first),
        ("version", second),
        ("capability-id", capability),
        ("response-id", "00ffff"),
        ("extra-id", "00"),
        ("host-name", host_b),
        ("implementation", implementation),
        ("space", " "),
    )
    emit_line(
        w,
        "rwhois-banner",
        f"%rwhois {bare} {host_a}",
        ("rwhois-response", f"%rwhois {bare} {host_a}"),
        ("version", bare),
        ("version-number", bare),
        ("host-name", host_a),
    )
    answer(w)
    claim_chars(
        w, line, "alpha", "digit", "hex-digit", "dns-char", "id-char", "any-char"
    )
    claim_terminators(w)
    names = [version.split(":")[0] for version in (first, second)]
    best = max(names, key=lambda name: tuple(int(part) for part in name[2:].split(".")))
    return w.case(
        "response",
        "version-list with the bare and capability-qualified version alternates; the banner "
        "host is a host-name, which is why no port appears in it",
        {
            "ok": True,
            "banners": 2,
            "banner_host": host_b,
            "banner_versions": names,
            "banner_best_version": best,
            "banner_implementation": implementation,
            "banner_capabilities": ["SCHEMA", "SOA", "STATUS", "XFER", "REGISTER"],
        },
        roundtrip=["banner"],
    )


def case_class_record() -> dict:
    """``class-line`` in all three alternates, over two closed class records."""
    w = Wire("abnf-class-record")
    rng = w.rng
    cls = t_class_name(rng, "domain")
    other = t_class_name(rng, "host")
    described = require("meta-value", "Domain objects, one per registered domain")
    host_described = require("meta-value", "Host objects")
    stamp = t_time_stamp(rng)
    field = require("meta-field", f"x-{_pick(rng, ('primary-key', 'help', 'indexed'))}")
    meta = t_attribute_value(rng, "plain")

    first = w.mark()
    emit_line(
        w,
        "class-line",
        f"%class {cls}:description:{described}",
        ("class-name", cls),
        ("meta-value", described),
    )
    emit_line(w, "class-line", f"%class {cls}:version:{stamp}", ("time-stamp", stamp))
    claim_time_stamp(w, stamp)
    emit_line(
        w,
        "class-line",
        f"%class {cls}:{field}:{meta}",
        ("meta-field", field),
        ("meta-value", meta),
    )
    w.line("%class")
    w.span(first, "class-record")
    second = w.mark()
    emit_line(
        w,
        "class-line",
        f"%class {other}:description:{host_described}",
        ("class-name", other),
        ("meta-value", host_described),
    )
    close_record(w, second, "%class", "class")
    w.span(first, "class-response")
    claim_chars(
        w, w.rendered(), "alpha", "digit", "id-char", "dns-char", "any-char", "space"
    )
    claim_terminators(w)
    return w.case(
        "response",
        "class-line in each of its three alternates (description, version time-stamp, "
        "meta-field/meta-value), two records each closed by a bare %class",
        {
            "ok": True,
            "class_names": [cls, other],
            "class_descriptions": {cls: described, other: host_described},
            "class_versions": {cls: stamp},
        },
    )


def case_directive_record() -> dict:
    """``directive-line`` in both alternates inside two ``directive-record`` groups."""
    w = Wire("abnf-directive-record")
    rng = w.rng
    names = [
        require("directive-name", _pick(rng, ("rwhois", "limit", "schema"))),
        require("directive-name", f"x-{_pick(rng, ('hold', 'notify'))}"),
    ]
    described = require("meta-value", "RWhois directive")
    extra_field = require("attribute-name", f"x-{_pick(rng, ('available', 'since'))}")
    extra_value = t_attribute_value(rng, "colon")

    first = w.mark()
    emit_line(
        w,
        "directive-line",
        f"%directive directive:{names[0]}",
        ("directive-name", names[0]),
        ("attribute-name", "directive"),
    )
    emit_line(
        w,
        "directive-line",
        f"%directive description:{described}",
        ("meta-value", described),
        ("attribute-name", "description"),
    )
    emit_line(
        w,
        "directive-line",
        f"%directive {extra_field}:{extra_value}",
        ("attribute-name", extra_field),
        ("attribute-value", extra_value),
    )
    w.line("%directive")
    w.span(first, "directive-record")
    second = w.mark()
    emit_line(
        w,
        "directive-line",
        f"%directive directive:{names[1]}",
        ("directive-name", names[1]),
    )
    close_record(w, second, "%directive", "directive")
    w.span(first, "directive-response")
    claim_chars(w, w.rendered(), "alpha", "id-char", "any-char", "space", "query-char")
    claim_terminators(w)
    return w.case(
        "response",
        "directive-record with the description alternate and an attribute-name/value "
        "alternate, closed by a bare %directive",
        {"ok": True, "directive_groups": 2, "directive_names": names},
    )


def case_display_record() -> dict:
    """``display-record``: a display-name line, attribute lines, bare terminator."""
    w = Wire("abnf-display-record")
    rng = w.rng
    name = require("display-name", _pick(rng, ("dump", "short", "long", "contact")))
    cls, other = t_class_name(rng, "domain"), t_class_name(rng, "network")
    attr_a, attr_b = "Domain-Name", "Network-Name"
    value_a, value_b = t_attribute_value(rng, "plain"), t_attribute_value(rng, "8bit")

    start = w.mark()
    emit_line(
        w,
        "display-line",
        f"%display name:{name}",
        ("display-name", name),
        ("attribute-name", "name"),
    )
    emit_line(
        w,
        "display-line",
        f"%display {cls}:{attr_a}:{value_a}",
        ("class-name", cls),
        ("attribute-name", attr_a),
        ("attribute-value", value_a),
    )
    emit_line(
        w,
        "display-line",
        f"%display {other}:{attr_b}:{value_b}",
        ("class-name", other),
        ("attribute-name", attr_b),
        ("attribute-value", value_b),
    )
    close_record(w, start, "%display", "display")
    claim_chars(w, w.rendered(), "alpha", "id-char", "any-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "display-record: RFC 2167 leaves the display shape to the server, so this pins the "
        "name/attribute grouping that a bare %display closes",
        {"ok": True, "display_groups": 1},
    )


def case_soa_record() -> dict:
    """``soa-line`` in all eleven alternates across two records closed by a bare ``%soa``."""
    w = Wire("abnf-soa-record")
    rng = w.rng
    area, cidr = t_authority_area(rng), t_authority_area(rng, cidr=True)
    stamp = t_time_stamp(rng)
    if rng.randrange(2):
        primary_host, primary_claim = t_ip_address(rng), "ip-address"
    else:
        primary_host, primary_claim = t_host_name(rng), "host-name"
    primary = require("host-port", f"{primary_host}:{t_port(rng)}")
    tech, admin, hostmaster = t_email(rng), t_email(rng), t_email(rng)
    ttl, refresh, retry, increment = (
        f"{rng.randrange(300, 86400)}",
        f"{rng.randrange(60, 3600)}",
        f"{rng.randrange(30, 900)}",
        f"{rng.randrange(60, 7200)}",
    )
    field = require("attribute-name", f"x-{_pick(rng, ('notify', 'mirror', 'spare'))}")
    meta = t_attribute_value(rng, "plain")
    numeric = (
        ("ttl", ttl),
        ("refresh", refresh),
        ("increment", increment),
        ("retry", retry),
    )

    start = w.mark()
    emit_line(w, "soa-line", f"%soa authority:{area}", ("authority-area", area))
    for key, digits in numeric:
        emit_line(w, "soa-line", f"%soa {key}:{digits}")
    emit_line(w, "soa-line", f"%soa serial:{stamp}", ("time-stamp", stamp))
    claim_time_stamp(w, stamp)
    emit_line(w, "soa-line", f"%soa tech-contact:{tech}", ("email", tech))
    emit_line(w, "soa-line", f"%soa admin-contact:{admin}", ("email", admin))
    emit_line(w, "soa-line", f"%soa hostmaster:{hostmaster}", ("email", hostmaster))
    host_claims = ((primary_claim, primary_host),)
    emit_line(
        w, "soa-line", f"%soa primary:{primary}", ("host-port", primary), *host_claims
    )
    emit_line(
        w,
        "soa-line",
        f"%soa {field}:{meta}",
        ("attribute-name", field),
        ("attribute-value", meta),
    )
    w.line("%soa")
    w.span(start, "soa-record")
    second = w.mark()
    emit_line(w, "soa-line", f"%soa authority:{cidr}", ("authority-area", cidr))
    emit_line(w, "soa-line", f"%soa ttl:{ttl}")
    close_record(w, second, "%soa", "soa")
    w.span(start, "soa-response")
    claim_chars(
        w,
        w.rendered(),
        "alpha",
        "digit",
        "id-char",
        "dns-char",
        "email-char",
        "any-char",
        "space",
    )
    claim_terminators(w)
    fields = {
        "authority": area,
        "serial": stamp,
        "tech-contact": tech,
        "admin-contact": admin,
        "hostmaster": hostmaster,
        "primary": primary,
    }
    fields.update({key: digits for key, digits in numeric})
    return w.case(
        "response",
        "soa-line in every alternate: authority, the four digit timers, the serial "
        "time-stamp, three e-mails, a host-port primary, and one extension field",
        {"ok": True, "soa_records": 2, "soa_fields": fields},
    )


def case_status_record() -> dict:
    """``status-line`` in all seven alternates; the response group is lines plus ``%ok``."""
    w = Wire("abnf-status-record")
    rng = w.rng
    limit, authority = f"{rng.randrange(1, 1000)}", f"{rng.randrange(1, 5000)}"
    holdconnect, forward = t_on_off(rng), t_on_off(rng)
    display = require("attribute-value", f"{_pick(rng, ('standard', 'dump'))} menu")
    contact = t_email(rng)
    field = require("attribute-name", "Server-Version")
    value = t_attribute_value(rng, "colon")

    start = w.mark()
    emit_line(w, "status-line", f"%status limit:{limit}")
    emit_line(
        w, "status-line", f"%status holdconnect:{holdconnect}", ("on-off", holdconnect)
    )
    emit_line(w, "status-line", f"%status forward:{forward}", ("on-off", forward))
    emit_line(w, "status-line", f"%status authority:{authority}")
    emit_line(
        w,
        "status-line",
        f"%status display:{display}",
        ("space", " "),
        ("attribute-value", display),
    )
    emit_line(w, "status-line", f"%status contact:{contact}", ("email", contact))
    emit_line(
        w,
        "status-line",
        f"%status {field}:{value}",
        ("attribute-name", field),
        ("attribute-value", value),
    )
    close_response(w, start, "status")
    claim_chars(
        w, w.rendered(), "alpha", "digit", "id-char", "email-char", "any-char", "space"
    )
    claim_terminators(w)
    return w.case(
        "response",
        "status-line in all seven alternates; on-off is lower case as Appendix B spells it, "
        "which is not how the RFC's own section 3.3 example prints it",
        {
            "ok": True,
            "status": {
                "limit": limit,
                "holdconnect": holdconnect,
                "forward": forward,
                "authority": authority,
                "display": display,
                "contact": contact,
                field: value,
            },
        },
        roundtrip=["status"],
    )


def case_xfer_record() -> dict:
    """Two ``xfer-record`` groups of ``%xfer`` attribute lines, each ended by a bare one."""
    w = Wire("abnf-xfer-record")
    rng = w.rng
    cls = t_class_name(rng, "domain")
    obj_id = t_object_id(rng)
    area = t_authority_area(rng)
    value = t_attribute_value(rng, "8bit")

    start = w.mark()
    emit_line(w, "xfer-line", f"%xfer {cls}:Class-Name:{cls}", ("class-name", cls))
    emit_line(w, "xfer-line", f"%xfer {cls}:ID:{obj_id}", ("object-id", obj_id))
    emit_line(w, "xfer-line", f"%xfer {cls}:Auth-Area:{area}", ("authority-area", area))
    w.line("%xfer")
    w.span(start, "xfer-record")
    second = w.mark()
    emit_line(
        w,
        "xfer-line",
        f"%xfer {cls}:Register-Name:{value}",
        ("attribute-name", "Register-Name"),
        ("attribute-value", value),
    )
    close_record(w, second, "%xfer", "xfer")
    w.span(start, "xfer-response")
    claim_chars(
        w, w.rendered(), "alpha", "digit", "id-char", "dns-char", "any-char", "space"
    )
    claim_terminators(w)
    return w.case(
        "response",
        "xfer-record: transfer object lines, each record ended by a bare %xfer, so the "
        "groups are told apart by their terminator rather than by a blank line",
        {"ok": True, "xfer_objects": 2, "object_class": cls, "record_id": obj_id},
    )


def case_schema_record() -> dict:
    """Two ``schema-record`` groups, each closed by a bare ``%schema``."""
    w = Wire("abnf-schema-record")
    rng = w.rng
    cls = t_class_name(rng, "domain")
    attributes = [
        require("attribute-name", "Class-Name"),
        require("attribute-name", "Domain-Name"),
    ]
    described = require("attribute-value", "Type of the object")
    formatted = require("attribute-value", "re:[A-Za-z0-9-]+")

    first = w.mark()
    emit_line(
        w,
        "schema-line",
        f"%schema {cls}:attribute:{attributes[0]}",
        ("class-name", cls),
        ("attribute-name", "attribute"),
        ("attribute-value", attributes[0]),
    )
    emit_line(
        w,
        "schema-line",
        f"%schema {cls}:description:{described}",
        ("attribute-name", "description"),
        ("attribute-value", described),
    )
    emit_line(
        w,
        "schema-line",
        f"%schema {cls}:format:{formatted}",
        ("attribute-name", "format"),
        ("attribute-value", formatted),
    )
    w.line("%schema")
    w.span(first, "schema-record")
    second = w.mark()
    emit_line(
        w,
        "schema-line",
        f"%schema {cls}:attribute:{attributes[1]}",
        ("class-name", cls),
        ("attribute-value", attributes[1]),
    )
    close_record(w, second, "%schema", "schema")
    w.span(first, "schema-response")
    claim_chars(w, w.rendered(), "alpha", "digit", "id-char", "any-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "schema-record per attribute: each attribute of a class is its own record, closed by "
        "a bare %schema, which is why the terminator rather than the class names the group",
        {
            "ok": True,
            "schema_classes": [cls],
            "schema_attributes": attributes,
            "schema_groups": 2,
        },
    )


def case_session_control() -> dict:
    """Every single-line client directive, each answered by ``%ok``.

    These are client-to-server bytes: the library's parsers read server messages, so a
    directive line is an unmatched line here, and what is asserted is that the transcript
    parses at all plus the count of lines the parser did not claim. The ABNF claims come
    from the witnesses, which are checked against the fixture bytes.
    """
    w = Wire("abnf-directive-session-control")
    rng = w.rng
    area, cidr = t_authority_area(rng), t_authority_area(rng, cidr=True)
    classes = [t_class_name(rng, "domain"), t_class_name(rng, "host")]
    names = [
        require("directive-name", _pick(rng, ("rwhois", "quit", "limit"))),
        require("directive-name", "schema"),
    ]
    display = require("display-name", _pick(rng, ("dump", "short")))
    on, off = t_on_off(rng), t_on_off(rng)
    limit = f"{rng.randrange(1, 5000)}"
    version = t_version_number(rng)
    implementation = require("implementation", f"(registrata {version})")
    start = w.mark()
    emit_line(
        w,
        "rwhois-dir",
        f"-rwhois {version}",
        ("version-number", version),
        ("space", " "),
    )
    emit_line(
        w,
        "rwhois-dir",
        f"-rwhois {version} {implementation}",
        ("implementation", implementation),
    )
    emit_line(
        w,
        "class-dir",
        f"-class {area} {classes[0]} {classes[1]}",
        ("authority-area", area),
        ("class-name", classes[0]),
        ("space", " "),
    )
    emit_line(w, "class-dir", f"-class {cidr}", ("authority-area", cidr))
    emit_line(
        w,
        "directive-dir",
        f"-directive {names[0]} {names[1]}",
        ("directive-name", names[0]),
    )
    emit_line(w, "directive-dir", "-directive")
    emit_line(w, "display-dir", f"-display {display}", ("display-name", display))
    emit_line(w, "display-dir", "-display")
    emit_line(
        w, "holdconnect-dir", f"-holdconnect {on}", ("on-off", on), ("space", " ")
    )
    emit_line(w, "holdconnect-dir", f"-holdconnect {off}", ("on-off", off))
    w.line(
        "%ok",
        ("ok-response", "%ok"),
        ("holdconnect-response", "%ok"),
        ("response", "%ok"),
    )
    emit_line(w, "limit-dir", f"-limit {limit}", ("space", " "))
    w.line(
        "%ok", ("limit-response", "%ok"), ("ok-response", "%ok"), ("response", "%ok")
    )
    emit_line(
        w,
        "schema-dir",
        f"-schema {area} {classes[0]}",
        ("authority-area", area),
        ("class-name", classes[0]),
    )
    emit_line(w, "soa-dir", f"-soa {cidr}", ("authority-area", cidr))
    emit_line(w, "soa-dir", "-soa")
    emit_line(w, "status-dir", "-status")
    emit_line(w, "quit-dir", "-quit")
    w.line("%ok", ("ok-response", "%ok"), ("quit-response", "%ok"), ("response", "%ok"))
    w.claim("directives", f"-limit {limit}")
    w.span(start, "client-sends", "rwhois-protocol")
    answer(w)
    claim_chars(
        w, w.rendered(), "alpha", "digit", "id-char", "dns-char", "any-char", "space"
    )
    claim_terminators(w)
    return w.case(
        "response",
        "every single-line client directive in one session; directive lines are "
        "client-to-server bytes, so they are unmatched lines to the response parser and "
        "what is pinned is that the transcript is still readable",
        # 16 client directive lines: 2 rwhois, 2 class, 2 directive, 2 display, 2
        # holdconnect, 1 limit, 1 schema, 2 soa, 1 status, 1 quit.
        {"ok": True, "other_lines": 16},
    )


def case_transfer_directives() -> dict:
    """``xfer-dir`` with every ``attribute-def`` shape and the optional serial-number."""
    w = Wire("abnf-directive-transfer")
    rng = w.rng
    area, cidr = t_authority_area(rng), t_authority_area(rng, cidr=True)
    cls = t_class_name(rng, "domain")
    attr = require("attribute-name", "Domain-Name")
    serial = t_time_stamp(rng)

    start = w.mark()
    both = require("attribute-def", f" class={cls} attribute={attr}")
    emit_line(
        w,
        "xfer-dir",
        f"-xfer {area}{both} {serial}",
        ("attribute-def", both),
        ("serial-number", serial),
        ("time-stamp", serial),
        ("class-name", cls),
        ("attribute-name", attr),
        ("authority-area", area),
        ("space", " "),
    )
    only_class = require("attribute-def", f" class={cls}")
    emit_line(
        w,
        "xfer-dir",
        f"-xfer {cidr}{only_class}",
        ("attribute-def", only_class),
        ("authority-area", cidr),
    )
    emit_line(
        w,
        "xfer-dir",
        f"-xfer {area} {serial}",
        ("serial-number", serial),
        ("authority-area", area),
    )
    emit_line(w, "xfer-dir", f"-xfer {area}", ("authority-area", area))
    w.span(start, "client-sends")
    answer(w)
    claim_time_stamp(w, serial)
    claim_chars(w, w.rendered(), "alpha", "digit", "id-char", "dns-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "xfer-dir in its four shapes. attribute-def is optional in every part, so "
        "*attribute-def can loop on the empty string - the bare form below is legal and is "
        "why a parser cannot rely on it to make progress",
        {"ok": True, "other_lines": len(w.lines) - 1},
    )


def case_notify_directives() -> dict:
    """``notify-dir`` in all five alternates, with and without a class-restricted query."""
    w = Wire("abnf-directive-notify")
    rng = w.rng
    host, numeric = t_host_name(rng), t_ip_address(rng)
    port_a, port_b = t_port(rng), t_port(rng)
    area, cidr = t_authority_area(rng), t_authority_area(rng, cidr=True)
    url_a = check_referral_url(w, f"rwhois://{host}:{port_a}/auth-area={area}")
    url_b = check_referral_url(w, f"rwhois://{numeric}:{port_b}/auth-area={cidr}")
    cls = t_class_name(rng, "domain")
    query_a, query_b = t_query_token(rng, trailing=True), t_query_token(rng)

    start = w.mark()
    emit_line(
        w,
        "notify-dir",
        f"-notify badref {url_a} {cls} {query_a}",
        ("referral-query", f"{url_a} {cls} {query_a}"),
        ("referral-url", url_a),
        ("class-name", cls),
        ("query", query_a),
        ("query-string", query_a),
        ("host-port", f"{host}:{port_a}"),
        ("host-name", host),
        ("authority-area", area),
        ("space", " "),
    )
    emit_line(
        w,
        "notify-dir",
        f"-notify recurref {url_b} {query_b}",
        ("referral-query", f"{url_b} {query_b}"),
        ("referral-url", url_b),
        ("query", query_b),
        ("query-string", query_b),
        ("host-port", f"{numeric}:{port_b}"),
        ("ip-address", numeric),
        ("authority-area", cidr),
    )
    for keyword in ("update", "inssec", "delsec"):
        emit_line(
            w,
            "notify-dir",
            f"-notify {keyword} {numeric}:{port_b}:{area}",
            ("host-port", f"{numeric}:{port_b}"),
            ("authority-area", area),
        )
    w.span(start, "client-sends")
    w.line(
        "%ok", ("ok-response", "%ok"), ("notify-response", "%ok"), ("response", "%ok")
    )
    claim_chars(
        w, w.rendered(), "alpha", "digit", "id-char", "dns-char", "query-char", "space"
    )
    claim_terminators(w)
    return w.case(
        "response",
        "notify-dir in each of its five alternates: badref and recurref carry a referral-query "
        "(a referral-url plus the query that caused it), update/inssec/delsec carry a "
        "host-port and an authority area",
        {"ok": True, "other_lines": len(w.lines) - 1},
    )


def case_security_dialogue() -> dict:
    """``security-dir`` with a password method, a pgp method, and an extension method."""
    w = Wire("abnf-directive-security")
    rng = w.rng
    password = require("password-data", f"QZ{rng.randrange(10**8, 10**9)}uh")
    secret = require("security-data", f"{_pick(rng, ID_WORDS).lower()}-opaque-data")
    key_id = t_key_id(rng)
    pgp = require("pgp-data", f"signed-encrypt {key_id}")
    method = require("security-method", f"x-{_pick(rng, ('skey', 'extern'))}")
    payload = [
        require("attribute-value", f"Class-Name:{t_class_name(rng, 'domain')}"),
        require("attribute-value", f"_SEQ_{rng.randrange(100, 999)}"),
    ]

    start = w.mark()
    w.line(
        f"-security on request password {password}",
        ("direction", "request"),
        ("security-method", "password"),
        ("security-data", password),
        ("password-data", password),
        ("space", " "),
    )
    payload_start = w.mark()
    for line in payload:
        w.line(line)
    w.span(payload_start, "security-payload")
    w.line("-security off")
    w.span(start, "security-dir")
    # A security-dir need not be closed by "-security off": that part is optional, and so
    # is the payload, which is why the second and third dialogues below are shorter.
    second = w.mark()
    # The token after "signed-encrypt" is a PGP key identifier in the conventional hex
    # shape, but Appendix B never defines key-id, so nothing claims it: pgp-data and
    # security-data cover the bytes that are defined, and key-id stays in UNCOVERABLE.
    w.line(
        f"-security on response pgp {pgp}",
        ("direction", "response"),
        ("security-method", "pgp"),
        ("pgp-data", pgp),
        ("security-data", pgp),
    )
    w.line("-security off")
    w.span(second, "security-dir")
    third = w.mark()
    w.line(
        f"-security on request {method} {secret}",
        ("direction", "request"),
        ("security-method", method),
        ("security-data", secret),
    )
    w.span(third, "security-dir")
    w.line(
        "%ok", ("ok-response", "%ok"), ("security-response", "%ok"), ("response", "%ok")
    )
    claim_chars(w, w.rendered(), "alpha", "digit", "id-char", "any-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "security-dir: the directive line, its security-payload, and the optional "
        "-security off. Appendix B spells the method and data as an open set, so an "
        "extension method is as valid as password or pgp",
        {"ok": True, "other_lines": len(w.lines) - 1},
    )


def register_dialogue(case_id: str, verb: str, note: str) -> dict:
    """One ``-register on <verb>`` dialogue: header, payload, ``-register off``, reply."""
    w = Wire(case_id)
    rng = w.rng
    maintainer = t_email(rng)
    cls = t_class_name(rng, "domain")
    obj_id = t_object_id(rng)
    area = t_authority_area(rng)
    name = f"{_pick(rng, WORDS).upper()}.EXAMPLE.NET"
    stamp = t_time_stamp(rng)

    def register_line(line: str) -> None:
        attribute, _, value = line.partition(":")
        w.line(
            line,
            ("register-line", line),
            ("attribute-name", attribute),
            ("attribute-value", value),
        )

    start = w.mark()
    w.line(
        f"-register on {verb} {maintainer}",
        ("register-on", "-register on"),
        ("maintainer-id", maintainer),
        ("space", " "),
    )
    payload = w.mark()
    for line in (
        f"Class-Name:{cls}",
        f"ID:{obj_id}",
        f"Auth-Area:{area}",
        f"Domain-Name:{name}",
    ):
        register_line(line)
    if verb == "mod":
        w.line("_NEW_")
        for line in (
            f"Class-Name:{cls}",
            f"ID:{obj_id}",
            f"Auth-Area:{area}",
            f"Domain-Name:{name}",
        ):
            w.line(line, ("register-line", line))
    w.span(
        payload,
        "register-mod"
        if verb == "mod"
        else ("register-add" if verb == "add" else "register-del"),
    )
    w.line("-register off", ("register-off", "-register off"))
    w.span(start, "register-dir")

    reply = w.mark()
    pairs: dict[str, str] = {}
    if verb == "del":
        w.line("%ok", ("ok-response", "%ok"), ("response", "%ok"))
    else:
        field, value = ("ID", obj_id) if verb == "add" else ("Updated", stamp)
        pairs[field] = value
        extra = [("object-id", value)] if verb == "add" else [("time-stamp", value)]
        w.line(f"%register {field}:{value}", *extra)
        w.line("%ok", ("ok-response", "%ok"), ("response", "%ok"))
    w.span(reply, "register-off-response")
    w.claim("register-on-response", "%ok")
    if verb == "mod":
        claim_time_stamp(w, stamp)
    claim_chars(
        w, w.rendered(), "alpha", "digit", "id-char", "email-char", "any-char", "space"
    )
    claim_terminators(w)
    expect = {
        "ok": True,
        "other_lines": sum(1 for line in w.lines if not line.startswith("%")),
    }
    if pairs:
        expect["register_pairs"] = pairs
    return w.case("response", note, expect)


def case_register_add() -> dict:
    """``register-dir`` add form, answered with ``%register ID:`` and ``%ok``."""
    return register_dialogue(
        "abnf-register-add",
        "add",
        "register-dir in the add form: register-on with the literal add, the maintainer-id, "
        "the register-add payload of register-line data, register-off, and the object-id reply",
    )


def case_register_mod() -> dict:
    """``register-mod``: the ``_NEW_`` separator between the old and the new payload."""
    return register_dialogue(
        "abnf-register-mod",
        "mod",
        "register-dir in the mod form: register-mod is one or more register-lines, the "
        "literal _NEW_, then the replacement payload; the reply carries the Updated time-stamp",
    )


def case_register_del() -> dict:
    """``register-del``: the delete payload, answered by a bare response."""
    return register_dialogue(
        "abnf-register-del",
        "del",
        "register-dir in the del form; register-del is only the payload, so the third "
        "alternate of register-off-response (a plain response) is the one that applies",
    )


def case_x_dialogue() -> dict:
    """``x-dir`` with and without arguments, answered by an unconstrained ``x-response``."""
    w = Wire("abnf-x-dialogue")
    rng = w.rng
    directive = require("x-directive", _pick(rng, ("ping", "status", "trace")))
    arguments = require("x-arguments", f"{_pick(rng, WORDS)} {rng.randrange(1, 999)}")
    free = (
        require("attribute-value", f"X-{directive.upper()} ok"),
        require("attribute-value", f"elapsed {rng.randrange(1, 60)}ms on the ring"),
    )
    start = w.mark()
    emit_line(
        w,
        "x-dir",
        f"-X-{directive} {arguments}",
        ("x-directive", directive),
        ("x-arguments", arguments),
        ("space", " "),
    )
    emit_line(w, "x-dir", f"-X-{directive}", ("x-directive", directive))
    for line in free:
        w.line(line)
    answer(w)
    w.span(start, "x-response")
    claim_chars(w, w.rendered(), "alpha", "digit", "id-char", "any-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        'x-dir and x-response: the X namespace is defined only as "the server may say '
        'anything", so an x-response is any run of lines terminated by a response',
        {"ok": True, "other_lines": len(w.lines) - 1},
    )


def _referral_url(rng: random.Random) -> str:
    return (
        f"rwhois://{t_host_name(rng)}:{t_port(rng)}/auth-area={t_authority_area(rng)}"
    )


def case_server_returns() -> dict:
    """A whole server dialogue: ``responses``, ``server-returns``, ``rwhois-protocol``."""
    w = Wire("abnf-protocol-server-returns")
    rng = w.rng
    cls = t_class_name(rng, "domain")
    banner = require("rwhois-banner", f"%rwhois {t_version(rng)} {t_host_name(rng)}")
    limit = f"{rng.randrange(1, 100)}"
    start = w.mark()
    w.line(banner, ("rwhois-banner", banner), ("rwhois-response", banner))
    emit_line(w, "status-line", f"%status limit:{limit}")
    emit_line(
        w,
        "class-line",
        f"%class {cls}:description:{require('meta-value', 'Domain objects')}",
        ("class-name", cls),
    )
    w.line("%class")
    emit_line(
        w, "schema-line", f"%schema {cls}:attribute:Class-Name", ("class-name", cls)
    )
    w.line("%schema")
    emit_line(w, "soa-line", f"%soa authority:{t_authority_area(rng)}")
    w.line("%soa")
    emit_line(
        w, "directive-line", f"%directive directive:{require('directive-name', 'quit')}"
    )
    w.line("%directive")
    emit_line(w, "display-line", f"%display name:{require('display-name', 'short')}")
    w.line("%display")
    emit_line(w, "xfer-line", f"%xfer {cls}:Class-Name:{cls}", ("class-name", cls))
    w.line("%xfer")
    emit_line(
        w, "referral-line", f"%referral {check_referral_url(w, _referral_url(rng))}"
    )
    w.line("%notify on")
    w.line("Free form server commentary that no response family claims")
    answer(w)
    w.span(start, "responses", "server-returns", "rwhois-protocol")
    claim_chars(w, w.rendered(), "alpha", "digit", "id-char", "any-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "one server dialogue carrying every recognised response family. responses and "
        "server-returns are protocol-wide alternations, and x-response alone accepts any "
        "text ending in a response, so the witness is the whole span rather than one line",
        # Unmatched by this library's response parser: %notify and the free-form line.
        {"ok": True, "banners": 1, "status": {"limit": limit}, "other_lines": 2},
    )


# ------------------------------------------------------------------- entry points

#: The builders, by name, in the order that defines the corpus. Names rather than objects
#: so this list can sit before the builders it names, and ``_declared_builders`` refuses
#: to run if a ``case_*`` function is added without being listed here, or if a name here
#: has no function: a case cannot be written and then silently never generated.
_BUILDERS = (
    "case_lexicon_object",
    "case_wire_octets",
    "case_wire_bare_lf",
    "case_response_error",
    "case_response_info_block",
    "case_banner",
    "case_class_record",
    "case_directive_record",
    "case_display_record",
    "case_schema_record",
    "case_soa_record",
    "case_status_record",
    "case_xfer_record",
    "case_query_result_multiclass",
    "case_query_result_referrals",
    "case_query_trailing_star",
    "case_query_leading_star",
    "case_query_quoted",
    "case_query_attribute_and_boolean",
    "case_session_control",
    "case_transfer_directives",
    "case_notify_directives",
    "case_security_dialogue",
    "case_register_add",
    "case_register_mod",
    "case_register_del",
    "case_x_dialogue",
    "case_server_returns",
)


def _declared_builders() -> list:
    builders = []
    for name in _BUILDERS:
        builder = globals().get(name)
        if not callable(builder):
            raise AbnfGenerationError(
                f"_BUILDERS names {name!r}, which is not a function"
            )
        builders.append(builder)
    missing = sorted(
        name for name in globals() if name.startswith("case_") and name not in _BUILDERS
    )
    if missing:
        raise AbnfGenerationError(f"case builders not listed in _BUILDERS: {missing}")
    return builders


def generate_cases() -> list[dict]:
    """Every ABNF-derived case, each validated against the recognizer before it is kept."""
    cases = [validate_case(builder()) for builder in _declared_builders()]
    seen: set[str] = set()
    for case in cases:
        if case["id"] in seen:
            raise AbnfGenerationError(f"duplicate case id {case['id']!r}")
        seen.add(case["id"])
    return cases


def coverage(cases: list[dict] | None = None) -> dict[str, list[str]]:
    """Production -> the ids of the cases whose transcript instantiates it."""
    covered: dict[str, list[str]] = {}
    for case in generate_cases() if cases is None else cases:
        for production in case.get("abnf", []):
            covered.setdefault(production, []).append(case["id"])
    return covered


def uncovered(cases: list[dict] | None = None) -> dict[str, str]:
    """Productions with no witness, and the reason they have none.

    A production listed in :data:`UNCOVERABLE` that a case nevertheless claims is an
    error rather than good news: it would leave a gap documented as open when the corpus
    says it is closed.
    """
    _, _, productions = _recognizers()
    covered = coverage(cases)
    overlap = sorted(set(UNCOVERABLE) & set(covered))
    if overlap:
        raise AbnfGenerationError(
            f"documented as uncoverable but claimed by a case anyway: {overlap}"
        )
    gaps = dict(UNCOVERABLE)
    for name in sorted(set(productions) - set(covered)):
        gaps.setdefault(name, "no case carries a witness for it")
    return gaps


#: Places where the grammar, the recognizer, the library and RFC 2167 itself disagree.
#: Recorded here because a derived corpus makes these visible, and each one is a decision
#: somebody has to make deliberately rather than in a fixture.
FINDINGS: tuple[str, ...] = (
    "query-string: section 3.4 allows a leading '*', Appendix B does not. registrata "
    "follows 3.4, so abnf-query-string-leading-star-3-4 is generated from 3.4 and labelled "
    "contested; the bytes are Appendix B-legal only read as a literal query-char star.",
    "quoted-query-char: Appendix B admits a double quote inside a quoted query string; "
    "registrata.query rejects a double quote anywhere in a value, so the alternative is "
    "uncoverable as a valid case and is recorded in DOCUMENTED_DEVIATIONS instead.",
    "on-off: Appendix B spells it lower case, and rwhois_abnf_match rejects 'OFF', yet "
    "RFC 2167's own section 3.3 example prints '%status holdconnect:OFF' - which is what "
    "the hand-written directive-status fixture inherited, so that fixture is not a witness "
    "for on-off and abnf-status-record uses the Appendix B spelling.",
    "banner host: rwhois-banner and rwhois-response take a host-name, so the hand-written "
    "banner-multi-version line, whose host field is 'rwhois.example.net:4321', is not an "
    "instance of rwhois-banner. The fixture is unchanged (it pins library behaviour); the "
    "claim is simply not made, and abnf-banner-versions uses a bare host-name.",
    "any-char: rwhois_abnf_match's ANY_CHAR also excludes TAB (0x09), while Appendix B "
    "excludes only CR and LF, so a tab cannot be claimed inside an attribute-value even "
    "though the production allows it. Tabs are covered where the grammar explicitly puts "
    "them - quoted-query-char - until the recognizer is settled.",
    "info-response leniency: mutating the space in this corpus's '%info off' terminator "
    "(tests/test_rwhois_abnf.py's drop-space battery) leaves a line that is legal "
    "any-char block text, so parse_response swallows it and still returns; the battery "
    "expects a rejection. That is a src decision, not a fixture change.",
)


def unexpected_gaps(cases: list[dict] | None = None) -> dict[str, str]:
    """Gaps that are not the documented ones - the ones a generator run must fail on."""
    return {
        name: reason
        for name, reason in uncovered(cases).items()
        if name not in UNCOVERABLE
    }


def coverage_report(cases: list[dict] | None = None) -> list[str]:
    """Per-group ``covered/total`` lines - the numbers the coverage gate is judged on."""
    from rwhois_grammar import groups

    covered = coverage(cases)
    lines: list[str] = []
    total = hit = 0
    for group, names in groups().items():
        found = sum(1 for name in names if name in covered)
        hit += found
        total += len(names)
        missing = [name for name in names if name not in covered]
        lines.append(
            f"{group:<13} {found:>3}/{len(names):<3}"
            + (f"  missing: {', '.join(missing)}" if missing else "")
        )
    lines.append(f"{'TOTAL':<13} {hit:>3}/{total:<3}")
    return lines


def selfcheck() -> list[str]:
    """Prove the guards refuse what they are supposed to refuse.

    A validator that never rejects anything is indistinguishable from no validator, so
    these negative checks are part of the deliverable: they are the evidence that
    ``require`` and ``validate_case`` can actually fail.
    """
    problems: list[str] = []

    def refuses(production: str, value: str, why: str) -> None:
        try:
            require(production, value)
        except AbnfGenerationError:
            return
        problems.append(f"{why}: {production} accepted {value!r}")

    refuses("any-char", "\x00", "NUL is outside ASCII 1..255")
    refuses("attribute-value", "line\nwith lf", "LF ends a line")
    refuses("attribute-value", "line\rwith cr", "CR ends a line")
    refuses("on-off", "OFF", "Appendix B spells on-off in lower case")
    refuses("host-name", "under_score.net", "underscore is not a dns-char")
    refuses("authority-area", "/com", "an authority area may not begin with a slash")
    refuses("type-char", "t", "type characters are upper case")
    refuses("time-stamp", "19961120123455", "a time-stamp is 17 digits")
    refuses("error-code", "23a", "an error code is three digits")
    refuses("query-char", '"', "a double quote is not a query-char")

    if not query_string_matches("vogon*", "appendix-b"):
        problems.append("Appendix B must accept a trailing wildcard")
    if not query_string_matches("*vogon", "3.4"):
        problems.append("section 3.4 must accept a leading wildcard")
    if not uses_leading_wildcard("*vogon", "3.4"):
        problems.append("3.4 derives *vogon through its leading wildcard slot")
    if uses_leading_wildcard("*vogon", "appendix-b"):
        problems.append("Appendix B has no leading slot to derive a wildcard from")
    if uses_leading_wildcard("vogon*", "3.4"):
        problems.append("a trailing star is not a leading wildcard")

    parse_query, _, rwhois_error = _library()
    try:
        parse_query('"vo"gon"')
    except rwhois_error:
        pass
    except Exception as exc:  # noqa: BLE001 - the point is that it is not a RwhoisError
        problems.append(
            f"inner quote: registrata raised {type(exc).__name__}, not RwhoisError"
        )
    else:
        problems.append(
            "inner quote: registrata accepted a double quote inside a value, so "
            "DOCUMENTED_DEVIATIONS is stale and quoted-query-char can be covered directly"
        )

    forged = {
        "id": "abnf-selfcheck",
        "lines": ["%ok"],
        "abnf": ["class-name"],
        "evidence": {"class-name": ["not-present-in-transcript"]},
    }
    try:
        validate_case(forged)
    except AbnfGenerationError:
        pass
    else:
        problems.append(
            "validate_case accepted a witness that is not in the transcript"
        )
    bogus = {
        "id": "abnf-selfcheck",
        "lines": ["%ok"],
        "abnf": ["not-a-production"],
        "evidence": {"not-a-production": ["%ok"]},
    }
    try:
        validate_case(bogus)
    except AbnfGenerationError:
        pass
    else:
        problems.append(
            "validate_case accepted a name that is not an Appendix B production"
        )
    try:
        check_query_line(Wire("abnf-selfcheck"), 'domain "vo"gon"')
    except AbnfGenerationError:
        pass
    else:
        problems.append(
            "check_query_line did not report the library refusing an artifact"
        )
    return problems


def main() -> int:
    cases = generate_cases()
    problems = selfcheck()
    for line in problems:
        print(f"SELFCHECK {line}")
    print(f"cases: {len(cases)}")
    for line in coverage_report(cases):
        print(line)
    for name, reason in sorted(UNCOVERABLE.items()):
        print(f"documented gap {name}: {reason}")
    for name, reason in sorted(unexpected_gaps(cases).items()):
        print(f"UNCOVERED {name}: {reason}")
    for production, note in sorted(DOCUMENTED_DEVIATIONS.items()):
        print(f"deviation {production}: {note}")
    for finding in FINDINGS:
        print(f"finding {finding}")
    print(f"selfcheck problems: {len(problems)}")
    return 1 if problems or unexpected_gaps(cases) else 0


def case_query_result_multiclass() -> dict:
    """Two records of different classes, separated by a blank line as section 3.4 shows."""
    w = Wire("abnf-query-result-multiclass")
    rng = w.rng
    domain, network = t_class_name(rng, "domain"), t_class_name(rng, "network")
    domain_name = f"{_pick(rng, WORDS).upper()}.EXAMPLE.NET"
    first_id, second_id = t_object_id(rng), t_object_id(rng)
    area = t_authority_area(rng)
    cidr = t_authority_area(rng, cidr=True)

    first = w.mark()
    emit_attribute(w, domain, "Class-Name", domain)
    emit_attribute(w, domain, "ID", first_id, None, ("object-id", first_id))
    emit_attribute(w, domain, "Auth-Area", area, None, ("authority-area", area))
    emit_attribute(w, domain, "Domain-Name", domain_name)
    w.span(first, "query-record")
    w.line("")
    second = w.mark()
    emit_attribute(w, network, "Class-Name", network)
    emit_attribute(w, network, "ID", second_id, None, ("object-id", second_id))
    emit_attribute(w, network, "Auth-Area", cidr, None, ("authority-area", cidr))
    w.span(second, "query-record")
    answer(w)
    w.span(first, "rwhois-query-result")
    claim_chars(w, w.rendered(), "alpha", "digit", "id-char", "dns-char", "any-char")
    claim_terminators(w)
    return w.case(
        "query",
        "a blank line separates records, so a domain record and a network record may share "
        "one response; a class change inside a record is still rejected",
        {
            "ok": True,
            "objects": 2,
            "object_class": domain,
            "attribute_count": 4,
            "record_id": first_id,
            "auth_area": area,
            "domain_names": [domain_name, None],
        },
        roundtrip=["objects"],
    )


def case_query_result_referrals() -> dict:
    """``referral-record``: consecutive ``%referral`` lines, then an object record."""
    w = Wire("abnf-query-result-referrals")
    rng = w.rng
    numeric_host, name_host = t_ip_address(rng), t_host_name(rng)
    numeric_port, name_port = t_port(rng), t_port(rng)
    cidr, area = t_authority_area(rng, cidr=True), t_authority_area(rng)
    url_a = check_referral_url(
        w, f"rwhois://{numeric_host}:{numeric_port}/auth-area={cidr}"
    )
    url_b = check_referral_url(w, f"rwhois://{name_host}:{name_port}/auth-area={area}")
    cls = t_class_name(rng, "domain")
    partial = f"{_pick(rng, WORDS).upper()}.EXAMPLE.NET"

    start = w.mark()
    emit_line(
        w,
        "referral-line",
        f"%referral {url_a}",
        ("referral-url", url_a),
        ("host-port", f"{numeric_host}:{numeric_port}"),
        ("ip-address", numeric_host),
        ("authority-area", cidr),
        ("space", " "),
    )
    emit_line(
        w,
        "referral-line",
        f"%referral {url_b}",
        ("referral-url", url_b),
        ("host-port", f"{name_host}:{name_port}"),
        ("host-name", name_host),
        ("authority-area", area),
    )
    w.span(start, "referral-record")
    w.line("")
    second = w.mark()
    emit_attribute(w, cls, "Class-Name", cls)
    emit_attribute(w, cls, "Domain-Name", partial)
    w.span(second, "query-record")
    answer(w)
    w.span(start, "rwhois-query-result")
    claim_chars(w, w.rendered(), "alpha", "digit", "id-char", "dns-char", "any-char")
    claim_terminators(w)
    return w.case(
        "query",
        "referral-record of two consecutive referral lines, one with a numeric host-port and "
        "one with a host-name, then a partial object record",
        {
            "ok": True,
            "referrals": 2,
            "referral_keys": [
                [numeric_host, numeric_port, cidr],
                [name_host, name_port, area],
            ],
            "objects": 1,
            "domain_names": [partial],
        },
        roundtrip=["referrals"],
    )


def case_query_trailing_star() -> dict:
    """``query-string`` as Appendix B spells it: the wildcard only at the end."""
    w = Wire("abnf-query-string-trailing-star")
    rng = w.rng
    cls = t_class_name(rng, "domain")
    for token in (
        t_query_token(rng, trailing=True),
        t_query_token(rng, trailing=False),
    ):
        if not query_string_matches(token, "appendix-b"):
            raise AbnfGenerationError(
                f"{w.case_id}: {token!r} is not an Appendix B query-string"
            )
        emit_line(
            w,
            "rwhois-query",
            check_query_line(w, token),
            ("query", token),
            ("query-string", token),
            ("query-char", token[0]),
        )
        line = f"{cls} {token}"
        emit_line(
            w,
            "rwhois-query",
            check_query_line(w, line),
            ("query", token),
            ("query-string", token),
            ("class-name", cls),
            ("query-char", token[0]),
            ("space", " "),
        )
    answer(w)
    claim_chars(w, w.rendered(), "alpha", "id-char", "dns-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "query-string with the trailing wildcard both readings agree on; each client line is "
        "also round-tripped through registrata.query while the case is built",
        {"ok": True, "other_lines": len(w.lines) - 1},
    )


def case_query_leading_star() -> dict:
    """Leading wildcard: permitted by section 3.4, rejected by Appendix B, kept contested.

    The witness must satisfy 3.4 and must *not* satisfy Appendix B. That double assertion
    is the point of the case: the corpus records which reading a transcript came from
    instead of pretending the grammar is unanimous. registrata follows 3.4, so the line is
    round-tripped through the library as well, not exempted from it.
    """
    w = Wire("abnf-query-string-leading-star-3-4")
    rng = w.rng
    cls = t_class_name(rng, "domain")
    for token in (
        t_query_token(rng, leading=True),
        t_query_token(rng, leading=True, trailing=True),
    ):
        if not query_string_matches(token, "3.4"):
            raise AbnfGenerationError(
                f"{w.case_id}: {token!r} fails even the section 3.4 reading"
            )
        if not uses_leading_wildcard(token, "3.4") or uses_leading_wildcard(
            token, "appendix-b"
        ):
            raise AbnfGenerationError(
                f"{w.case_id}: {token!r} does not separate the two readings of query-string"
            )
        line = f"{cls} {token}"
        emit_line(
            w,
            "rwhois-query",
            check_query_line(w, line),
            ("query", token),
            ("query-string", token),
            ("class-name", cls),
            ("query-char", token[1]),
            ("space", " "),
        )
    answer(w)
    claim_chars(w, w.rendered(), "alpha", "id-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "DERIVED FROM SECTION 3.4, NOT Appendix B: 3.4 allows a leading '*' (its prose says "
        "the wildcard may appear in the front and/or at the end) while Appendix B puts the "
        "'*' only at the end. The bytes are derivable under Appendix B only as a literal "
        "query-char star, which is a different search; registrata implements 3.4",
        {"ok": True, "other_lines": len(w.lines) - 1},
    )


def case_query_quoted() -> dict:
    """Quoted query strings: the space and tab that ``quoted-query-char`` adds."""
    w = Wire("abnf-query-string-quoted")
    rng = w.rng
    cls = t_class_name(rng, "domain")
    for token, separator in (
        (t_quoted_query(rng, tab=False), " "),
        (t_quoted_query(rng, tab=True), "\t"),
    ):
        emit_line(
            w,
            "rwhois-query",
            check_query_line(w, f"{cls} {token}"),
            ("query", token),
            ("query-string", token),
            ("class-name", cls),
            ("quoted-query-char", separator),
            ("space", " "),
        )
        if separator == "\t":
            w.claim("tab", "\t")
    answer(w)
    claim_chars(w, w.rendered(), "alpha", "id-char", "query-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "quoted-query-char exercised with the space and tab it adds to query-char; an inner "
        "double quote is in the production too, but registrata.query rejects one anywhere in "
        "a value, so that alternative is a documented deviation instead of a case",
        {"ok": True, "other_lines": len(w.lines) - 1},
    )


def case_query_attribute_and_boolean() -> dict:
    """``attribute-query`` and ``bin-boolean``, including a three term chain."""
    w = Wire("abnf-query-attribute-and-boolean")
    rng = w.rng
    cls = t_class_name(rng, "domain")
    attr = require("attribute-name", "Domain-Name")
    token = t_query_token(rng, trailing=True)
    attribute_query = f"{attr}={token}"
    emit_line(
        w,
        "rwhois-query",
        check_query_line(w, f"{cls} {attribute_query}"),
        ("attribute-query", attribute_query),
        ("attribute-name", attr),
        ("query", attribute_query),
        ("query-string", token),
        ("class-name", cls),
        ("space", " "),
    )
    emit_line(
        w,
        "rwhois-query",
        check_query_line(w, attribute_query),
        ("attribute-query", attribute_query),
        ("query", attribute_query),
    )
    for _ in range(2):
        left, right = t_query_token(rng), t_query_token(rng)
        operator = t_bin_boolean(rng)
        chain = f"{left} {operator} {right}"
        emit_line(
            w,
            "rwhois-query",
            check_query_line(w, f"{cls} {chain}"),
            ("query", chain),
            ("bin-boolean", operator),
            ("query-string", left),
            ("query-char", left[0]),
            ("class-name", cls),
            ("space", " "),
        )
    first_term = t_query_token(rng)
    chain = f"{first_term} and {t_query_token(rng)} or {t_query_token(rng)}"
    emit_line(
        w,
        "rwhois-query",
        check_query_line(w, chain),
        ("query", chain),
        ("bin-boolean", "and"),
        ("query-string", first_term),
    )
    answer(w)
    claim_chars(w, w.rendered(), "alpha", "id-char", "space")
    claim_terminators(w)
    return w.case(
        "response",
        "attribute-query and bin-boolean; query is left-recursive as written, so a chain is "
        "read as nesting with a depth limit, exactly as the grammar inventory notes",
        {"ok": True, "other_lines": len(w.lines) - 1},
    )


# --------------------------------------------------------- hand-written cases (ABNF)
#
# The 45 transcripts that ``generate_rwhois_corpus.py`` already contained predate this
# generator, so they carry no witnesses. Their claims are checked a different way, by
# :func:`validate_claims`: for every production listed below, some substring of that
# fixture must instantiate it, so an annotation cannot be invented. Where a legacy
# transcript is malformed, only the parts of it that are well formed are claimed - and the
# RFC's own ``%status holdconnect:OFF`` is deliberately not claimed as ``on-off``, which
# Appendix B spells in lower case.

_CRL = ("crlf", "cr", "lf")
_ANSWER = ("ok-response", "response")
_LETTERS = ("alpha", "any-char", "id-char")

LEGACY_ABNF: dict[str, tuple[str, ...]] = {
    "banner-rfc-example": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "hex-digit",
        "id-char",
        "dns-char",
        "any-char",
        "host-name",
        "version",
        "version-number",
        "version-list",
        "capability-id",
        "response-id",
        "extra-id",
        "implementation",
        "rwhois-banner",
        "rwhois-response",
    )
    + _ANSWER,
    "banner-multi-version": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "hex-digit",
        "id-char",
        "dns-char",
        "any-char",
        "version",
        "version-number",
        "version-list",
        "capability-id",
        "response-id",
        "extra-id",
        "implementation",
    )
    + _ANSWER,
    "query-domain-object": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "id-char",
        "dns-char",
        "any-char",
        "email-char",
        "class-name",
        "attribute-name",
        "attribute-value",
        "query-line",
        "query-record",
        "rwhois-query-result",
        "authority-area",
        "host-name",
        "email",
    )
    + _ANSWER,
    "query-typed-attributes": _CRL
    + (
        "alpha",
        "digit",
        "id-char",
        "dns-char",
        "any-char",
        "class-name",
        "attribute-name",
        "attribute-value",
        "query-line",
        "query-record",
        "type-char",
        "rwhois-query-result",
    )
    + _ANSWER,
    "query-multiple-objects": _CRL
    + (
        "alpha",
        "id-char",
        "dns-char",
        "any-char",
        "class-name",
        "attribute-name",
        "attribute-value",
        "query-line",
        "query-record",
        "rwhois-query-result",
    )
    + _ANSWER,
    "query-referral": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "id-char",
        "dns-char",
        "any-char",
        "referral-line",
        "referral-url",
        "referral-record",
        "rwhois-query-result",
        "host-port",
        "host-name",
        "authority-area",
    )
    + _ANSWER,
    "query-referral-chain": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "id-char",
        "dns-char",
        "any-char",
        "referral-line",
        "referral-url",
        "referral-record",
        "rwhois-query-result",
        "host-port",
        "host-name",
        "authority-area",
    )
    + _ANSWER,
    "query-objects-and-referral": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "id-char",
        "dns-char",
        "any-char",
        "referral-line",
        "referral-url",
        "referral-record",
        "query-line",
        "query-record",
        "rwhois-query-result",
        "host-port",
        "host-name",
        "authority-area",
        "class-name",
        "attribute-name",
        "attribute-value",
    )
    + _ANSWER,
    "query-no-objects": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "id-char",
        "any-char",
        "error-response",
        "error-code",
        "error-text",
        "response",
    ),
    "error-idle-time-exceeded": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "hex-digit",
        "id-char",
        "dns-char",
        "any-char",
        "host-name",
        "version",
        "version-number",
        "version-list",
        "capability-id",
        "response-id",
        "extra-id",
        "implementation",
        "rwhois-banner",
        "error-response",
        "error-code",
        "error-text",
        "response",
    ),
    "directive-status": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "id-char",
        "dns-char",
        "any-char",
        "email-char",
        "email",
        "status-line",
        "status-response",
        "attribute-name",
        "attribute-value",
    )
    + _ANSWER,
    "directive-schema": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "id-char",
        "any-char",
        "schema-line",
        "schema-record",
        "schema-response",
        "class-name",
        "attribute-name",
        "attribute-value",
    )
    + _ANSWER,
    "directive-class": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "id-char",
        "dns-char",
        "any-char",
        "class-line",
        "class-record",
        "class-response",
        "class-name",
        "meta-value",
        "time-stamp",
        "year",
        "month",
        "day",
        "hour",
        "minute",
        "second",
        "milli-second",
    )
    + _ANSWER,
    "directive-soa": _CRL
    + (
        "space",
        "alpha",
        "digit",
        "id-char",
        "dns-char",
        "any-char",
        "email-char",
        "soa-line",
        "soa-record",
        "soa-response",
        "authority-area",
        "email",
        "host-port",
        "host-name",
        "time-stamp",
        "year",
        "month",
        "day",
        "hour",
        "minute",
        "second",
        "milli-second",
    )
    + _ANSWER,
    "directive-info-block": _CRL
    + ("space", "alpha", "digit", "id-char", "dns-char", "any-char")
    + _ANSWER,
    "directive-xfer": _CRL
    + (
        "space",
        "alpha",
        "id-char",
        "dns-char",
        "any-char",
        "xfer-line",
        "class-name",
        "attribute-name",
        "attribute-value",
    )
    + _ANSWER,
    "directive-directive-list": _CRL
    + (
        "space",
        "alpha",
        "id-char",
        "dns-char",
        "any-char",
        "directive-line",
        "directive-record",
        "directive-response",
        "directive-name",
    )
    + _ANSWER,
    "directive-display": _CRL
    + (
        "space",
        "alpha",
        "id-char",
        "dns-char",
        "any-char",
        "display-line",
        "class-name",
        "attribute-name",
        "attribute-value",
    )
    + _ANSWER,
    "directive-register-notify": _CRL
    + ("space", "alpha", "id-char", "any-char", "attribute-name", "attribute-value")
    + _ANSWER,
}

#: Malformed and wire fixtures: only the well formed parts are claimed, because a
#: transcript that exists to be rejected still contains bytes that instantiate other
#: productions, and the point of the malformed line is recorded in ``kind`` and ``source``.
LEGACY_ABNF.update(
    {
        "info-block-missing-on": _CRL + _LETTERS + ("space",) + _ANSWER,
        "info-off-without-on": _CRL + _LETTERS + ("space",) + _ANSWER,
        "attribute-missing-value": _CRL + _LETTERS + ("class-name", "attribute-name"),
        "attribute-missing-class-separator": _CRL + _LETTERS + ("space",),
        "class-name-invalid-characters": _CRL
        + _LETTERS
        + ("space", "attribute-name", "attribute-value"),
        "attribute-bad-type-suffix": _CRL
        + _LETTERS
        + ("class-name", "attribute-name", "attribute-value"),
        "referral-nonnumeric-port": _CRL
        + _LETTERS
        + ("dns-char", "space", "host-name", "authority-area")
        + _ANSWER,
        "referral-port-out-of-range": _CRL
        + _LETTERS
        + ("digit", "dns-char", "space", "host-name", "host-port", "authority-area")
        + _ANSWER,
        "referral-wrong-scheme": _CRL
        + _LETTERS
        + ("digit", "dns-char", "space", "host-name", "host-port", "authority-area")
        + _ANSWER,
        "referral-missing-auth-area": _CRL
        + _LETTERS
        + ("digit", "dns-char", "space", "host-name", "host-port")
        + _ANSWER,
        "referral-bare-line": _CRL + ("alpha", "any-char") + _ANSWER,
        "banner-missing-host": _CRL
        + _LETTERS
        + (
            "digit",
            "hex-digit",
            "space",
            "version",
            "version-number",
            "capability-id",
            "response-id",
            "extra-id",
        )
        + _ANSWER,
        "banner-bad-capability-id": _CRL
        + _LETTERS
        + ("digit", "space", "dns-char", "version", "version-number", "host-name")
        + _ANSWER,
        "banner-short-capability-id": _CRL
        + _LETTERS
        + ("digit", "space", "dns-char", "version", "version-number", "host-name")
        + _ANSWER,
        "error-code-wrong-width": _CRL
        + _LETTERS
        + ("digit", "space", "error-text", "response"),
        "error-code-nonnumeric": _CRL + _LETTERS + ("space", "error-text", "response"),
        "status-missing-colon": _CRL + _LETTERS + ("space",) + _ANSWER,
        "class-record-too-few-parts": _CRL
        + _LETTERS
        + ("class-name", "attribute-name")
        + _ANSWER,
        "schema-record-too-few-parts": _CRL
        + _LETTERS
        + ("class-name", "attribute-name")
        + _ANSWER,
        "register-missing-colon": _CRL + _LETTERS + ("attribute-name",) + _ANSWER,
        "xfer-missing-attribute-separator": _CRL
        + _LETTERS
        + ("class-name", "attribute-name")
        + _ANSWER,
        "soa-missing-authority": _CRL
        + _LETTERS
        + ("digit", "space", "soa-line", "soa-record")
        + _ANSWER,
        "object-class-mismatch-mid-record": _CRL
        + _LETTERS
        + ("class-name", "attribute-name", "attribute-value", "query-line")
        + _ANSWER,
        "oversized-line-memory-bomb": _CRL
        + ("alpha", "id-char", "dns-char", "any-char", "class-name", "attribute-name"),
        "non-ascii-octets-are-8-bit-safe": _CRL
        + _LETTERS
        + (
            "dns-char",
            "space",
            "class-name",
            "attribute-name",
            "attribute-value",
            "query-line",
        ),
        "bare-lf-terminated": ("lf", "alpha", "any-char") + _ANSWER,
    }
)


def legacy_abnf() -> dict[str, list[str]]:
    """Production claims for the hand-written cases, keyed by case id."""
    return {case_id: sorted(names) for case_id, names in sorted(LEGACY_ABNF.items())}


if __name__ == "__main__":
    raise SystemExit(main())
