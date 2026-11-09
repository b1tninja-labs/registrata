"""RFC 2167 Appendix B grammar, transcribed production by production.

This is data, not logic: every production in the RFC's ABNF, with the definition text
copied from the specification so that a reader can check it against the RFC without
trusting a summary. ``tests/test_rwhois_abnf.py`` uses the inventory to demand that
each production is exercised by at least one corpus case, which is what turns "we have
a lot of parser tests" into "every construct the protocol defines has a test".

Two things in the source specification are genuinely inconsistent and are recorded
here rather than silently resolved, because a test that quietly picks a reading is
worse than a known ambiguity:

- ``query-string``: section 3.4 allows a leading ``*`` in both the bare and quoted
  forms (``["*"] 1*query-char ["*"]``) and its prose says wildcards may appear "in the
  front and/or at the end", while Appendix B puts the ``*`` only at the end
  (``1*query-char ["*"]``). The library follows section 3.4, the more detailed text.
- ``any-char`` is "ASCII 1..255 except LF and CR", so NUL (octet 0) is *outside* the
  alphabet: a value containing NUL is not merely unusual, it is not a valid
  attribute-value. The 1..255 range is also what makes this an 8-bit protocol.
"""

from __future__ import annotations

from dataclasses import dataclass

APPENDIX_B = "RFC 2167 Appendix B"
SECTION_3_1_9 = "RFC 2167 3.1.9"
SECTION_3_4 = "RFC 2167 3.4"


@dataclass(frozen=True)
class Production:
    """One ABNF production, as written in the RFC."""

    name: str
    abnf: str
    group: str
    refs: tuple[str, ...]

    @property
    def is_leaf(self) -> bool:
        """True when the production spells out its own characters."""
        return self.group == "lexical"


# (group, refs, [(production, definition text verbatim from the RFC)])
_GRAMMAR: list[tuple[str, tuple[str, ...], list[tuple[str, str]]]] = [
    (
        "lexical",
        (APPENDIX_B, SECTION_3_1_9),
        [
            ("alpha", 'alpha = "a".."z" / "A".."Z"'),
            ("digit", 'digit = "0".."9"'),
            ("hex-digit", 'hex-digit = digit / "a".."f" / "A".."F"'),
            ("id-char", 'id-char = alpha / digit / "_" / "-"'),
            (
                "any-char",
                "any-char = <ASCII 1..255, except LF (linefeed) and CR (carriage return)>",
            ),
            ("dns-char", 'dns-char = alpha / digit / "-"'),
            ("email-char", "email-char = <see [RFC 822]>"),
            ("space", 'space = " "'),
            ("tab", "tab = <ASCII TAB (tab)>"),
            ("lf", "lf = <ASCII LF (linefeed)>"),
            ("cr", "cr = <ASCII CR (carriage return)>"),
            ("crlf", "crlf = cr lf"),
        ],
    ),
    (
        "general",
        (APPENDIX_B, SECTION_3_1_9),
        [
            ("year", "year = 4digit"),
            ("month", "month = 2digit"),
            ("day", "day = 2digit"),
            ("hour", "hour = 2digit"),
            ("minute", "minute = 2digit"),
            ("second", "second = 2digit"),
            ("milli-second", "milli-second = 3digit"),
            ("host-name", 'host-name = dns-char *(dns-char / ".")'),
            ("email", 'email = 1*email-char "@" host-name'),
            (
                "authority-area",
                'authority-area = (dns-char / ".") *(dns-char / "." / "/")',
            ),
            ("object-id", 'object-id = 1*id-char "." authority-area'),
            ("host-port", 'host-port = (host-name / ip-address) ":" 1*5digit'),
            (
                "ip-address",
                'ip-address = 1*3digit "." 1*3digit "." 1*3digit "." 1*3digit',
            ),
            ("class-name", "class-name = 1*id-char"),
            ("attribute-name", "attribute-name = 1*id-char"),
            ("attribute-value", "attribute-value = 1*any-char"),
            (
                "time-stamp",
                "time-stamp = year month day hour minute second milli-second",
            ),
            ("on-off", 'on-off = "on" / "off"'),
        ],
    ),
    (
        "response",
        (APPENDIX_B, SECTION_3_1_9),
        [
            (
                "response",
                "response = ok-response crlf / error-response crlf / info-response",
            ),
            ("ok-response", 'ok-response = "%ok"'),
            (
                "error-response",
                'error-response = "%error" space error-code space error-text',
            ),
            ("error-code", "error-code = 3digit"),
            ("error-text", "error-text = 1*any-char"),
            (
                "info-response",
                'info-response = "%info" space "on" crlf *(*any-char crlf) "%info" space "off" crlf',
            ),
        ],
    ),
    (
        "banner",
        (APPENDIX_B, SECTION_3_1_9),
        [
            (
                "rwhois-banner",
                'rwhois-banner = "%rwhois" space version-list space host-name [space implementation] crlf',
            ),
            ("version-list", 'version-list = version *("," version)'),
            (
                "version",
                'version = version-number [":" capability-id] / "V-1.5" ":" capability-id',
            ),
            ("version-number", 'version-number = "V-" 1*digit "." 1*digit'),
            ("capability-id", 'capability-id = response-id ":" extra-id'),
            ("response-id", "response-id = 6hex-digit"),
            ("extra-id", "extra-id = 2hex-digit"),
            ("implementation", "implementation = 1*any-char"),
        ],
    ),
    (
        "protocol",
        (APPENDIX_B, SECTION_3_1_9),
        [
            ("rwhois-protocol", "rwhois-protocol = client-sends / server-returns"),
            ("client-sends", "client-sends = *(directives / rwhois-query)"),
            ("server-returns", "server-returns = *(responses / rwhois-query-result)"),
            (
                "directives",
                (
                    "directives = rwhois-dir / class-dir / directive-dir / display-dir / "
                    "holdconnect-dir / limit-dir / notify-dir / quit-dir / register-dir / "
                    "schema-dir / security-dir / soa-dir / status-dir / xfer-dir / x-dir"
                ),
            ),
            (
                "responses",
                (
                    "responses = rwhois-response / class-response / directive-response / "
                    "display-response / holdconnect-response / limit-response / notify-response / "
                    "quit-response / register-response / schema-response / security-response / "
                    "soa-response / status-response / xfer-response / x-response"
                ),
            ),
        ],
    ),
    (
        "required",
        (APPENDIX_B,),
        [
            (
                "rwhois-dir",
                'rwhois-dir = "-rwhois" space version-number [space implementation] crlf',
            ),
            (
                "rwhois-response",
                'rwhois-response = "%rwhois" space version space host-name [space implementation] crlf',
            ),
        ],
    ),
    (
        "class",
        (APPENDIX_B,),
        [
            (
                "class-dir",
                'class-dir = "-class" space authority-area *(space class-name) crlf',
            ),
            ("class-response", "class-response = *class-record response"),
            ("class-record", 'class-record = *class-line "%class" crlf'),
            (
                "class-line",
                (
                    'class-line = "%class" space class-name ":" "description" ":" 1*any-char crlf / '
                    '"%class" space class-name ":" "version" ":" time-stamp crlf / '
                    '"%class" space class-name ":" meta-field ":" meta-value crlf'
                ),
            ),
            ("meta-field", "meta-field = 1*id-char"),
            ("meta-value", "meta-value = 1*any-char"),
        ],
    ),
    (
        "directive",
        (APPENDIX_B,),
        [
            (
                "directive-dir",
                'directive-dir = "-directive" *(space directive-name) crlf',
            ),
            ("directive-name", "directive-name = 1*id-char"),
            ("directive-response", "directive-response = *directive-record response"),
            (
                "directive-record",
                (
                    'directive-record = "%directive" space "directive" ":" directive-name crlf '
                    '*directive-line "%directive" crlf'
                ),
            ),
            (
                "directive-line",
                (
                    'directive-line = "%directive" space "description" ":" 1*any-char crlf / '
                    '"%directive" space attribute-name ":" attribute-value crlf'
                ),
            ),
        ],
    ),
    (
        "display",
        (APPENDIX_B,),
        [
            (
                "display-dir",
                'display-dir = "-display" crlf / "-display" space display-name crlf',
            ),
            ("display-name", "display-name = 1*id-char"),
            ("display-response", "display-response = *display-record response"),
            (
                "display-record",
                'display-record = "%display" space "name" ":" display-name crlf *display-line "%display" crlf',
            ),
            (
                "display-line",
                'display-line = "%display" space attribute-name ":" attribute-value crlf',
            ),
        ],
    ),
    (
        "holdconnect",
        (APPENDIX_B,),
        [
            ("holdconnect-dir", 'holdconnect-dir = "-holdconnect" space on-off crlf'),
            ("holdconnect-response", "holdconnect-response = response"),
        ],
    ),
    (
        "limit",
        (APPENDIX_B,),
        [
            ("limit-dir", 'limit-dir = "-limit" space 1*digit crlf'),
            ("limit-response", "limit-response = response"),
        ],
    ),
    (
        "notify",
        (APPENDIX_B,),
        [
            (
                "notify-dir",
                (
                    'notify-dir = "-notify" space "badref" space referral-query crlf / '
                    '"-notify" space "recurref" space referral-query crlf / '
                    '"-notify" space "update" space host-port ":" authority-area crlf / '
                    '"-notify" space "inssec" space host-port ":" authority-area crlf / '
                    '"-notify" space "delsec" space host-port ":" authority-area crlf'
                ),
            ),
            (
                "referral-query",
                "referral-query = referral-url space [class-name space] query",
            ),
            ("notify-response", "notify-response = response"),
        ],
    ),
    (
        "quit",
        (APPENDIX_B,),
        [
            ("quit-dir", 'quit-dir = "-quit" crlf'),
            ("quit-response", "quit-response = response"),
        ],
    ),
    (
        "register",
        (APPENDIX_B,),
        [
            (
                "register-dir",
                (
                    'register-dir = register-on space "add" space maintainer-id crlf register-add register-off / '
                    'register-on space "mod" space maintainer-id crlf register-mod register-off / '
                    'register-on space "del" space maintainer-id crlf register-del register-off'
                ),
            ),
            ("register-on", 'register-on = "-register" space "on"'),
            ("register-off", 'register-off = "-register" space "off" crlf'),
            ("register-add", "register-add = 1*(register-line crlf)"),
            (
                "register-mod",
                'register-mod = 1*(register-line crlf) "_NEW_" crlf 1*(register-line crlf)',
            ),
            ("register-del", "register-del = 1*(register-line crlf)"),
            ("maintainer-id", "maintainer-id = email"),
            ("register-line", 'register-line = attribute-name ":" attribute-value'),
            ("register-on-response", "register-on-response = response"),
            (
                "register-off-response",
                (
                    'register-off-response = "%register" space "ID" ":" object-id crlf response / '
                    '"%register" space "Updated" ":" time-stamp crlf response / response'
                ),
            ),
        ],
    ),
    (
        "schema",
        (APPENDIX_B,),
        [
            (
                "schema-dir",
                'schema-dir = "-schema" space authority-area *(space class-name) crlf',
            ),
            ("schema-response", "schema-response = *schema-record response"),
            ("schema-record", 'schema-record = *schema-line "%schema" crlf'),
            (
                "schema-line",
                'schema-line = "%schema" space class-name ":" attribute-name ":" attribute-value crlf',
            ),
        ],
    ),
    (
        "security",
        (APPENDIX_B,),
        [
            (
                "security-dir",
                (
                    'security-dir = "-security" space "on" space direction space security-method '
                    '[space security-data] crlf security-payload ["-security" space "off" crlf]'
                ),
            ),
            ("direction", 'direction = "request" / "response"'),
            ("security-method", 'security-method = "password" / "pgp" / 1*id-char'),
            ("security-data", "security-data = password-data / pgp-data / 1*any-char"),
            ("password-data", "password-data = 1*any-char"),
            # pgp-data refers to key-id, which Appendix B never defines; the grammar records
            # the reference so the gap is visible rather than quietly invented.
            (
                "pgp-data",
                'pgp-data = "signed" / "encrypt" [space key-id] / "signed-encrypt" [space key-id]',
            ),
            ("key-id", "key-id = (referenced by pgp-data, not defined in RFC 2167)"),
            ("security-payload", "security-payload = *(*any-char crlf)"),
            ("security-response", "security-response = response"),
        ],
    ),
    (
        "soa",
        (APPENDIX_B,),
        [
            ("soa-dir", 'soa-dir = "-soa" *(space authority-area) crlf'),
            ("soa-response", "soa-response = *soa-record response"),
            ("soa-record", 'soa-record = *soa-line "%soa" crlf'),
            (
                "soa-line",
                (
                    'soa-line = "%soa" space "authority" ":" authority-area crlf / '
                    '"%soa" space "ttl" ":" 1*digit crlf / '
                    '"%soa" space "serial" ":" time-stamp crlf / '
                    '"%soa" space "refresh" ":" 1*digit crlf / '
                    '"%soa" space "increment" ":" 1*digit crlf / '
                    '"%soa" space "retry" ":" 1*digit crlf / '
                    '"%soa" space "tech-contact" ":" email crlf / '
                    '"%soa" space "admin-contact" ":" email crlf / '
                    '"%soa" space "hostmaster" ":" email crlf / '
                    '"%soa" space "primary" ":" host-port crlf / '
                    '"%soa" space attribute-name ":" attribute-value crlf'
                ),
            ),
        ],
    ),
    (
        "status",
        (APPENDIX_B,),
        [
            ("status-dir", 'status-dir = "-status" crlf'),
            ("status-response", "status-response = *status-line response"),
            (
                "status-line",
                (
                    'status-line = "%status" space "limit" ":" 1*digit crlf / '
                    '"%status" space "holdconnect" ":" on-off crlf / '
                    '"%status" space "forward" ":" on-off crlf / '
                    '"%status" space "authority" ":" 1*digit crlf / '
                    '"%status" space "display" ":" 1*any-char crlf / '
                    '"%status" space "contact" ":" email crlf / '
                    '"%status" space attribute-name ":" attribute-value crlf'
                ),
            ),
        ],
    ),
    (
        "xfer",
        (APPENDIX_B,),
        [
            (
                "xfer-dir",
                'xfer-dir = "-xfer" space authority-area *attribute-def [space serial-number] crlf',
            ),
            # Every part of attribute-def is optional, so `*attribute-def` may loop on the
            # empty string: the ABNF permits it, which is why a parser cannot rely on it to
            # make progress. Kept as a note rather than a "fixed" rule.
            (
                "attribute-def",
                'attribute-def = [space "class=" class-name] *(space "attribute=" attribute-name)',
            ),
            ("serial-number", "serial-number = time-stamp"),
            ("xfer-response", "xfer-response = *xfer-record response"),
            ("xfer-record", 'xfer-record = *xfer-line "%xfer" crlf'),
            (
                "xfer-line",
                'xfer-line = "%xfer" space class-name ":" attribute-name ":" attribute-value crlf',
            ),
        ],
    ),
    (
        "x",
        (APPENDIX_B,),
        [
            ("x-dir", 'x-dir = "-X-" x-directive [space *[x-arguments]] crlf'),
            ("x-directive", "x-directive = 1*id-char"),
            ("x-arguments", "x-arguments = *any-char"),
            ("x-response", "x-response = *(*any-char crlf) response"),
        ],
    ),
    (
        "query",
        (APPENDIX_B, SECTION_3_4),
        [
            ("rwhois-query", "rwhois-query = [class-name space] query crlf"),
            # Left-recursive as written; the corpus treats a boolean chain as nesting with a
            # depth limit, because a generator cannot follow `query -> query bin-boolean query`
            # literally without recursing forever.
            (
                "query",
                "query = query-string / attribute-query / query bin-boolean query",
            ),
            ("query-char", 'query-char = <any-char, except """, space, tab>'),
            ("quoted-query-char", 'quoted-query-char = query-char / space / tab / "'),
            (
                "query-string",
                (
                    'query-string = ["*"] 1*query-char ["*"] / """ ["*"] 1*quoted-query-char ["*"] """ (3.4) / '
                    'query-string = 1*query-char ["*"] / """ 1*quoted-query-char ["*"] """ (Appendix B)'
                ),
            ),
            ("attribute-query", 'attribute-query = attribute-name "=" query-string'),
            ("bin-boolean", 'bin-boolean = "and" / "or"'),
        ],
    ),
    (
        "query-result",
        (APPENDIX_B, SECTION_3_4),
        [
            (
                "rwhois-query-result",
                "rwhois-query-result = *(query-record / referral-record) response",
            ),
            ("query-record", "query-record = 1*query-line crlf"),
            (
                "query-line",
                'query-line = class-name ":" attribute-name [";" type-char] ":" attribute-value crlf',
            ),
            ("type-char", 'type-char = "T" / "I" / "S"'),
            ("referral-record", "referral-record = 1*(referral-line crlf)"),
            ("referral-line", 'referral-line = "%referral" space referral-url'),
            (
                "referral-url",
                'referral-url = "rwhois" ":" "//" host-port "/" "auth-area=" authority-area',
            ),
        ],
    ),
]

#: Every production in RFC 2167's ABNF, keyed by name.
PRODUCTIONS: dict[str, Production] = {}
for _group, _refs, _entries in _GRAMMAR:
    for _name, _abnf in _entries:
        if _name in PRODUCTIONS:
            raise AssertionError(f"duplicate production in grammar inventory: {_name}")
        PRODUCTIONS[_name] = Production(
            name=_name, abnf=_abnf, group=_group, refs=_refs
        )

GROUPS: dict[str, list[str]] = {}
for _production in PRODUCTIONS.values():
    GROUPS.setdefault(_production.group, []).append(_production.name)
for _names in GROUPS.values():
    _names.sort()

#: Productions whose text refers to something RFC 2167 never defines. They stay in the
#: inventory so the gap is visible, and the coverage gate treats them as documented
#: rather than silently dropping them.
UNDEFINED_REFERENCES = ("key-id", "email-char")


def production_names() -> list[str]:
    return sorted(PRODUCTIONS)


def groups() -> dict[str, list[str]]:
    return {group: list(names) for group, names in sorted(GROUPS.items())}


__all__ = [
    "APPENDIX_B",
    "GROUPS",
    "PRODUCTIONS",
    "SECTION_3_1_9",
    "SECTION_3_4",
    "UNDEFINED_REFERENCES",
    "Production",
    "groups",
    "production_names",
]
