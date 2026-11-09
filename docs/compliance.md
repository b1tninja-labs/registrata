# Compliance and maturity report

This document tracks what is complete, what is partial, and what must be improved before claiming RFC-complete or production-ready status.

## RFC 2167 RWhois compliance

### Wire basics

| Requirement | Status | Notes |
|---|---|---|
| TCP port 4321 default | implemented | Server and client default to 4321. |
| CRLF line endings | implemented | Client/server encode CRLF; reader tolerates LF-only. |
| 8-bit line values | partial | Current code uses `latin-1`; needs byte-level fuzzing. |
| Directive vs query dispatch | implemented | Leading `-` means directive. |
| Response `%ok` / `%error` | implemented | Error code mapping complete. |
| Info block handling | implemented | Basic `%info on/off` parsing. |

### Directives

| Directive | Client | Server | Completeness |
|---|---|---|---|
| `-rwhois` | yes | yes | Basic version negotiation implemented; multi-version behavior needs hardening. |
| `-limit` | yes | yes | Works for common cases. |
| `-holdconnect` | yes | yes | Implemented, and the server keeps the specified default of `off`; `RwhoisClient` negotiates `on` at connect time so sessions still work. See "Connection handling" below. |
| `-forward` | yes | partial | Directive accepted, but full server-side forwarding is not complete. |
| `-display` | yes | partial | Lists/sets standard `dump`. |
| `-status` | yes | yes | Emits common status fields. |
| `-soa` | yes | yes | Memory backend and parser cover standard fields. |
| `-schema` | yes | partial | Works with generated memory schema. `-register` validates submitted objects against it (see the `-register` row); value formats are enforced only for the types Appendix B fixes exactly, SEE-ALSO and NUMBER. |
| `-class` | yes | partial | Basic meta-information works. |
| `-directive` | yes | partial | Lists advertised directive catalog. |
| `-notify` | no convenience API | partial | Backend hook exists; MemoryBackend does not default-enable full notification policy. |
| `-register` | yes | implemented | `add`/`mod`/`del` validate the submitted object against the class this server advertises, and answer with the Appendix C code that names the fault: 320 undeclared attribute or a client-assigned `ID`, 321 malformed line, empty value, bad repetition, or a value contradicting its declared type, 322 required attribute or identifying `ID`/`Updated` missing, 323 the two halves of a `mod` disagree, 324 duplicate primary key, 325 `Updated` no longer matches the stored record, 336 unknown `ID`, 340/341 unknown authority area or class, 400 for a read-only backend, 401 when the backend can authenticate and the session has not. The server assigns `ID` and `Updated` and returns them, and every write advances the SOA serial so slaves re-transfer. `120 Registration deferred` is wired up as a maintenance switch (`RwhoisServer(..., registration_deferred=True)`, or `registrata serve --defer-registrations`): queries keep being answered, writes are refused with the spec's own code. `Guardian` enforcement is partial -- see the section below. |
| `-security` | yes | partial | Password auth hook exists; it now also gates `-register` (401) when the backend can authenticate. The password a session authenticated with is retained on the session so a `Guardian` whose `Guard-Scheme` is `password` can be checked against it. PGP intentionally unavailable. |
| `-xfer` | raw command | partial | Basic export exists; incremental serial semantics remain. |
| `-quit` | yes | yes | Implemented. |
| `-X-` | raw command | partial | Custom handlers supported in server API; no CLI yet. |

### Guardians (RFC 2167 §2.3.6)

The `guardian` class declares `Guard-Scheme` and `Guard-Info`, both required as the section
says, with `Guard-Info` marked `Private` because the section says it "should not be
displayed". Enforcement covers what the section actually specifies:

- A `Guardian` value that names no guardian object is refused with **323** -- the section
  says the value *is* the ID of a guardian object, so a dangling one is a broken reference,
  not a description of an unprotected object.
- `mod` and `del` of a guarded object require one of its guardians to be satisfied.
  Guardians have no rank, so any one is enough. Adding is not gated: the text names
  "modify, delete, or possibly view", and `add` is none of those.
- The only scheme this server can satisfy is `password`, which is the section's own example
  of what `Guard-Info` may hold. The session must have authenticated (via `-security`) with
  the password the guardian's `Guard-Info` contains. A guardian naming any other scheme
  cannot be satisfied here, and the section requires a scheme be understood by both client
  and server, so an unsatisfiable guardian yields **420** rather than a pass -- treating "I
  cannot check this" as "allowed" would make declaring a stronger guardian a way around
  protection.
- Reading guardians by ID is a backend capability. `MemoryBackend` has it; a backend without
  it declares `supports_object_lookup = False`, and the server logs `guardian_checks_skipped`
  instead of reporting a check it did not perform.

Not implemented: schemes other than `password` (PGP would need key material this project does
not manage), and the authority-area-wide guardian of §2.3.6's last paragraph, whose text
describes the effect -- a guardian linked to an area applies to everything in it -- but not
the mechanism that creates that link. And `Guardian` does not gate *reads*: the spec hedges
it to "possibly view", which is a deployment decision, not a rule to enforce.

### Private attributes and objects (RFC 2167 §2.3.1)

`Private` is a per-attribute schema property -- "publicly not viewable", defaulting to false
-- and, in the base class, a per-object flag of the same name. The flag used to be advertised
in `%schema` and parsed back from it, but nothing on the serving path consulted it, so every
private value went to anyone who could open a socket. Both are enforced now: a record whose
class declares private attributes is emitted with those attribute-value pairs removed, and a
record flagged private at object level is not emitted at all, unless the session satisfies one
of the object's guardians. That is the same check registration uses, from the same function,
because two copies of "who is allowed" eventually disagree about something.

Three consequences worth naming:

- A withheld record is reported as **no match** (`%error 230`), not as an empty result set.
  "Nothing matched" and "something matched, but you may not see it" must not be
  distinguishable to the caller, or the filter becomes an oracle for the existence of records.
- A guardian object guards itself (§2.3.6), so `Guard-Info` is readable only by a session
  presenting that value -- and editing a guardian object requires the password inside it,
  which is also how rotating that password has to work.
- Reads fail closed. A backend that cannot read guardians hides private values; the same
  backend is allowed to accept writes and logs `guardian_checks_skipped`, because refusing
  every write on such a backend would make the feature unusable while a hidden read leaks
  the thing the flag exists to protect.

Not implemented: per-object guardians attached to an entire authority area (see the guardian
section above), and any protection for values already handed to a client. One boundary is worth
stating rather than leaving implicit: the zone-transfer path (`export`/`%xfer`) is **not**
filtered, so a slave replicates the whole zone including private values. That is defensible for a
slave that needs to serve the data, but the transfer is not wired to any authorization of its own
yet -- see the `-xfer` item in the roadmap -- so a server that answers `%xfer` today should not be
reachable from anywhere it does not trust with the entire zone.

### Result and query behavior

| Requirement | Status | Notes |
|---|---|---|
| Dump result records | implemented | Supports `class:attr:T:I:S:value`. |
| Blank record separator | implemented | Parsers flush on blank lines. |
| `%referral` URL | implemented | Parses `rwhois://host:port/auth-area=area`. |
| Multiple referrals same auth-area | implemented | Resolver dedupes by auth-area. |
| Punt and link referrals | partial | Server/referral rules exist; index-server routing is not complete. |
| Wildcard query behavior | implemented | Memory backend supports exact/prefix/suffix wildcard matching. |
| Boolean query behavior | partial | Parser supports simple `and`/`or`; operator semantics need fuzzing and conformance. |

### ABNF inventory and grammar ambiguities

`tools/rwhois_grammar.py` transcribes all 130 productions of RFC 2167's Appendix B ABNF
(with the duplicates in sections 3.1.9 and 3.4 recorded as shared references), and
`tools/rwhois_abnf_match.py` transcribes a recognizer for each leaf production directly
from the ABNF text. `tests/test_rwhois_abnf.py` demands that every production is
exercised by at least one corpus case, so "all ABNF constructs have tests" is a checked
property that fails with a named list when it stops being true.

Exercising a production is not the same as enforcing it. The gate proves the recognizers agree
with the grammar; it does not make the parser reject everything the grammar forbids. One concrete
gap: `attribute-value = 1*any-char` requires at least one character, yet `parse_response` accepts
`domain:Domain-Name:` — an empty value — rather than failing the response, so an optional
attribute a server left blank costs the client nothing. The strictness deliberately lives one
layer up: `validate_object` refuses an empty value for a required attribute, since Appendix B
gives no way to express "present but blank", and `tests/test_schema_validate.py` records which
checks that predicate makes and which it cannot make at all.

Two places where the specification contradicts itself:

| Ambiguity | The two readings | What registrata does |
|---|---|---|
| Leading wildcard in `query-string` | 3.4: `["*"] 1*query-char ["*"]`, with prose saying an asterisk may appear "in the front and/or at the end". Appendix B: `1*query-char ["*"]`, trailing only. | Follows section 3.4. `*vogon`, `vogon*`, `*vogon*` and `domain=*ns1*` all parse, and the memory backend implements prefix and suffix matching. Section 3.4 is the more detailed normative text and prefix wildcards are what servers actually serve. |
| Double quote inside a quoted query | `quoted-query-char = query-char / space / tab / "` admits a `"` into the body of a quoted string | Rejected with `350 Invalid query syntax`. The rule is not implementable as written: a delimiter that may occur inside its own body, with no escape mechanism anywhere in the protocol, makes the quoted form ambiguous. Refusing it is the only reading that parses to exactly one answer. |

Grammar pathologies the corpus records rather than quietly repairs:

- `query = query-string / attribute-query / query bin-boolean query` is left-recursive as
  written, so generated boolean nesting is bounded by depth instead of following the rule
  literally.
- `attribute-def` is optional at every position and `xfer-dir` repeats it as
  `*attribute-def`, so the rule can loop on the empty string. A parser must not rely on
  it to make progress.
- `pgp-data` references `key-id`, which RFC 2167 never defines. The inventory keeps the
  entry, marked undefined, and the coverage gate exempts it by name rather than inventing
  a syntax for it.
- `any-char` is ASCII octets 1..255 except CR and LF. Octet 0 is outside that range, so a
  value containing NUL is invalid by the letter of the specification, not merely
  unfriendly — and the 1..255 bound is what makes RWhois an 8-bit protocol, which is why
  fixtures are latin-1 and octets 0x80-0xff must survive a round trip.
- `host-name` is built from `dns-char`, which has no underscore, while `class-name` and
  `attribute-name` are `1*id-char`, which does. An underscore in a host name or referral
  URL is therefore malformed on the wire even though it is common in practice, so the
  parser's tolerance there is a deliberate choice and not the grammar's.

### Loop-freedom on grouped keywords

Five response keywords introduce a multi-line group: `%class`, `%schema`, `%directive`,
`%display`, `%xfer`. Each group ends at the first line the handler does not recognize, so a
line that carries the prefix but not the `space` the grammar requires (`class-line = "%class"
space ...`) is recognized by neither the group terminator nor the field branch. That shape
used to return "zero lines consumed" for the line the handler had just been handed, and
because the driver advances with `i += consumed`, the cursor never moved: `parse_response`
spun forever on a hostile or sloppy server line, raising nothing, which meant no caller
timeout could rescue it. It is fixed at two levels -- the handlers raise
`RwhoisParseError` for a glued prefix, and the driver refuses to advance by zero -- so
loop-freedom does not depend on one call site remembering an invariant.

### Documented leniencies

These are grammar-invalid inputs the library accepts. Each is pinned in
`tests/test_rwhois_abnf.py::LENIENT_BEHAVIOURS`, where the test asserts the grammar's verdict
and the library's verdict together, so an entry cannot silently become policy in the other
direction. Listing them is the point: a protocol library that never says which junk it
tolerates cannot tell you what it will do with a server nobody has tested against.

| Input | Grammar | Library | Why kept |
|---|---|---|---|
| NUL inside an attribute value | outside `any-char` (octets 1..255) | accepted, survives into the object | Only CR and LF are guarded, since they end a line. Tightening would reject live data over a byte that cannot break framing. |
| `_` in a host name or referral URL | `host-name` is built from `dns-char`, which has no `_` | accepted | Following a slightly odd referral is more useful than failing resolution. |
| Port beyond five digits in `%soa primary:` | `host-port` is 1..5 digits | accepted | SOA keeps the field verbatim as a data holder; the same overflow in a referral URL **is** rejected, so the two paths differ on purpose. |
| 18-digit `%soa serial:` | `time-stamp` is exactly 17 | accepted | Same split: strict on paths that act on the value, lenient where it is only carried. |
| A `%`-stripped field line inside a `%soa` group | not a `soa-record` | **silently dropped**, serial reverts to its default, nothing records it | The weakest entry: corrupted input leaves no trace. Kept for now, recorded knowingly. |
| `%statuslimit:20`, `%soaauthority:example.com`, `%registerX-Handle:ON`, `%rwhoisV-1.5:00ffff:00 host (impl)` | keyword requires one `space` | accepted (text after the prefix is stripped) | These four handlers consume their line, so they cannot stall. The grouped keywords that *could* stall now **reject** the same shape: after the fix, `%error`, `%info`, `%referral`, `%class`, `%schema`, `%directive`, `%display` and `%xfer` are strict (8) while `%status`, `%soa`, `%register` and `%rwhois` stay lenient (4). |
| Two spaces after `%referral` | one `space` | accepted | Whitespace tolerance on a line whose payload is unambiguous. |
| `a AND b`, `%status holdconnect:OFF` | Appendix B spells literals lower case | accepted, `AND` normalizes to `and` | In-grammar, not leniency: RFC 2234 2.3 makes ABNF quoted literals case-insensitive. RFC 2167's own section 3.3 example prints `holdconnect:OFF`. Case that **is** enforced: the `type-char` (`person:N;t:v` raises) and the literal `%info on` block start. |
| Truncated transcript | no terminator | parses, `ok` is False | A partial answer beats an exception; `ok=True` is never reported unless `%ok` was present. |
| A line with its `%` removed | `x-response` permits `*(*any-char crlf) response` | lands in `other_lines` | The grammar genuinely allows unstructured text. |
| `%rwhois` banner host field carrying a port | `rwhois-banner` takes a `host-name`, not a `host-port` | accepted | Some daemons print `host:port` in their banner. The banner is informational, so a wider reading costs nothing. |
| Leading whitespace in `%error` text | `error-text` is `1*any-char`, which includes space | the separator eats it: `%error 230   oops` yields text `oops` | `ERROR_LINE_RE` separates code from text with `[ \t]+` rather than the single `space` Appendix B specifies. Once it accepts runs of spaces there is no fact of the matter about where the separator ends and the message begins, so the leading run is attributed to the separator. Pinned in `tests/test_rwhois_property.py::test_error_text_with_a_leading_space_is_not_recoverable` so that tightening the separator must update the test rather than change behaviour quietly. |
| Bare LF line ending | `crlf = cr lf` | tolerated by the wire reader | Real servers do this; rejecting it would break interoperability for nothing. |

### Generative property tests

The corpus mutates fixed fixtures, so its reach is bounded by what those fixtures contain.
`tests/test_rwhois_property.py` instead generates its inputs from the production alphabets
with a seeded PRNG (stdlib `random`, no property framework; the dev group is pytest and ruff
only), so a hostile byte can land in any position of any artifact, and every failure reports
the seed that reproduces it. Four properties: fidelity where the mapping is injective,
`parse -> serialize -> parse` fixed points where the serializer normalizes on purpose, no
builtin escaping a parse, and no parse exceeding an executed-line budget. An anti-vacuity
assertion counts the rejections the splices actually produce, so narrowing the hostile
alphabet cannot leave the file green while checking nothing.

Two findings came out of the first run of it:

- **`format_error_line` dropped zero padding.** `error-code` is `3DIGIT`, so 30 is the
  grammatical `"030"`; the formatter rendered `int(code)`, emitting `%error 30 ...`, which
  `parse_error_line` then rejected with its own three-digit requirement -- a formatter
  producing lines its own parser cannot read, failing at the far end on a server answering a
  client. Now padded to three digits, with `ValueError` for a code outside 0..999. It is worth
  noting how narrowly this was missed: an assertion that error codes run 100..999 (true of
  Appendix C's *documented* codes, false of the grammar) would have excluded the three seeds
  that found it.
- **Error text with a leading space is unrecoverable**, which is a consequence of the
  separator tolerance above rather than a defect, and is recorded as such.

### Framing integrity on the server side

An RWhois response is a sequence of CRLF-terminated octet lines, so a value carrying a CR or
LF turns one intended line into two. The payload that can carry it is data being *served* --
a backend row, a zone import, a directive description, an operator-set banner -- rather than a
client request, which the wire reader has already delimited. The worst outcome is not a
garbled record but an early `%ok`: `read_until` ends on the first line beginning with the
terminator, so an injected one truncates the response and everything after it gets attributed
to the next query.

`RwhoisRequestHandler.send_lines` joined lines and encoded them itself, going around
`wire.encode_line`, which is where the "no CR or LF" rule lives. It now encodes the whole
batch through `encode_line` before writing any of it, so a line break in any served value
raises `RwhoisProtocolError` and nothing reaches the socket -- a refusal cannot leave a
half-sent response behind. `send_error` now calls `format_error_line` instead of keeping its
own copy of the rendering; that copy had the same zero-padding defect, and fixing only the
library's version would have left a server emitting `%error 30` lines that no client can
parse. Two renderings of one wire format drift, so there is one.

`tests/test_rwhois_framing.py` (98 tests) drives the handler's real emission path and reads
the bytes back through `LineReader` with deliberately small `recv` chunks, asserting that what
went out is what comes back (including 8-bit octets and blank-line record separators), that
every line-break shape is refused with nothing written, and -- as an anti-vacuity check, since
a `send_lines` that simply refused everything would pass those -- that emitting `%ok` really
does put `%ok\r\n` on the socket.

**Where a refusal is reported.** `handle()` wraps command processing and answers a
`RwhoisProtocolError` with `%error 402` (Appendix C's "Unidentified error"), then keeps the
session going. That is one policy point rather than one per send site: a line break can arrive
from a backend row, a class description, an extension's return value, or operator
configuration, and guarding each caller individually is how some of them end up reporting
properly while others reset. Because `send_lines` encodes a whole batch before writing any of
it, a refusal cannot leave a partial response behind, and because the exception propagates out
of the command handler, a refused batch is never followed by `%ok`.

Three sources of raw strings are tested over a real loopback connection, so the policy is shown
to be central rather than extension-specific:

- `-x-` extensions, where operator code returns a `list[str]` that is written as it stands --
  no record, no `AttributeLine`, no construction-time check in front of it;
- `-soa`, where `MemoryBackend.add_soa` stores the authority string as given and `_do_soa`
  renders the record with f-strings, so backend data reaches the wire directly;
- `-class`, where `SchemaClass.to_class_lines` interpolates `description` and `extra`, neither
  of which is validated.

In each case nothing forged arrives, no part of the refused group arrives, the client receives
`%error 402`, and a follow-up `-status` on the same connection still answers -- which is what
makes the failure recoverable for a resolver walking several zones instead of a dead socket per
bad record. Requiring that `%error 402` specifically is also what keeps these tests honest: the
first two drafts of the `-class` case passed the wrong argument shape and were refused as 338 or
340 *before* any send happened, so a test that only asserted "nothing forged arrived" would have
passed while exercising nothing.

**Bad configuration fails at startup.** `RwhoisServer.__init__` validates `server_name` and
`implementation` through `wire.validate_wire_text`, because both land in the banner that
`setup()` writes -- previously a bad value produced a server that accepted a connection and then
hung up, which reads as a network fault and never points at the config line responsible. The
emission guard remains the backstop: a wire rule enforced only in a constructor is not enforced,
since attributes can be set afterwards by a subclass, a reload path, or a test.

### Connection handling

Section 3.3.5 is explicit: *"Normally, the server closes the connection after each query… By
default, the holdconnect state must be set to `off` for each connection."* The server follows
that, and `RwhoisClient` asks for what it needs -- `__enter__` sends `-holdconnect on` before the
caller does anything else and records the outcome in `client.session_held`.

Section 3.1.6, the session sequence, closes the loop in the client's favour: its last step is
*"The server closes the connection, unless the client has directed it not to close the connection."*
A client that directs otherwise is doing what the document anticipates, not working around it. Both
quotations are now taken from the fetched source text rather than from this project's own notes.
The citation that originally justified the opposite default turns out to have been wrong twice over:
section 3.1.4 is titled *Result* and says nothing about connections at all.

Getting here took three attempts and each wrong turn is worth recording. The session state first
defaulted to closing, which matched the specification but meant a client could issue exactly one
query per connection -- unusable for a resolver walking a referral chain, which is what this
library exists for. An earlier version of this section then asserted that the RFC *required*
hold-open-by-default, citing section 3.1.4 and claiming section 3.3 agreed; both halves were
written without reading section 3.3.5, and the server default was flipped on the strength of it.
A conformance document that dresses a convenience choice in the language of a requirement is worse
than no document at all, because it makes the deviation hard for anyone else to see.

The client is the only place this can live. With the specified default the socket is gone by the
time a caller wants a second query, so a lazy "ask when it is needed again" scheme has nothing to
ask on. A refusal is recorded rather than raised: `400 Directive not available`, `401 Not
authorized for directive`, and `338 Invalid directive syntax` all describe a server following the
protocol, and the single query the connection was opened for still works. `check_server` passes
`hold_connect=False` for its own session so the negotiation cannot hide the thing it is probing --
a server that advertises the capability and declines the directive.

The reason the original bug survived is a testing failure rather than a coding one. Every test
opened a fresh connection per query, so none exercised the default; and the one test that issued
several queries on one connection called `-holdconnect on` first, which asserts the workaround
rather than the behaviour. A test that opts into correct behaviour cannot notice it is not the
default. That is also why the server-side check below speaks raw sockets: a `RwhoisClient`-based
test cannot observe what the server does when nobody asks.

Now pinned by name in `tests/test_server_client.py`: `test_the_server_closes_after_one_query_by_default`
(raw socket: `-status` reports `holdconnect:OFF` and the connection ends after one query),
`test_a_client_session_survives_multiple_queries` (negotiated, two queries on one connection),
`test_a_client_that_declines_to_negotiate_gets_the_specified_default`,
`test_a_server_that_refuses_holdconnect_still_serves_one_query` (`%error 400` recorded in
`session_held`, session still usable), `test_holdconnect_off_closes_after_the_next_response`
(the opt-out has to actually close; `-status` reports `ON` only because the client asked for it),
and `test_idle_timeout_is_reported_then_the_connection_closed` (an idle client is sent
`%error 503 Idle time exceeded`, which is Appendix C's code rather than one the implementation
chose, and then sees EOF).

### Error codes checked against the appendix

`tests/test_rfc2167_appendix_c.py` asserts `ErrorCode` and `ERROR_TEXT` against a transcription of
Appendix C read out of the RFC text fetched directly from rfc-editor.org (retrieved 2026-11-05), not
out of this repository's notes: every code, every error text, the fourteen RFC 1714 codes Appendix C
records as obsolete, which must read as unknown rather than valid, and the rule that an
implementation-specific code carries 6 in the second position -- so adding a private code stays a
deliberate act rather than a quiet drift.

The reason for writing it is that the previous state was circular. The conformance checker accepted a
code 201 that appears nowhere in RFC 2167, and nothing in the repository could say so, because the
only authority for the code list was this project's own transcription of it. Reading the appendix
corrected three more assumptions in the same pass: section 3.1.4 is about query results rather than
connections; section 3.1.6 authorises exactly the `-holdconnect on` negotiation the client performs;
and the banner-on-connect rule belongs to 3.1.6, not to the 3.1.1 the client's diagnostic had been
citing on assumption.

### Client transport against an adversarial server

The client's ceilings -- 1 MiB per line, 100,000 lines per response, 16 MiB per response --
were previously tested only against fake socket objects, which cannot show what a real peer
does to a read loop. `tests/test_rwhois_hostile_server.py` (23 tests) runs a scripted server on
loopback and drives the real `RwhoisClient` at it: an over-long line is refused rather than
buffered, a flood is stopped by the line budget and again by the byte budget, a response with no
terminator is reported incomplete rather than complete, a server that goes silent mid-response ends
in a timeout rather than a hang, a first line that is not a banner is refused at connect, and binary noise (NUL, high
octets, a blank-line flood, a `%ok` flood, ANSI escapes) never escapes as a builtin. Twelve seeds
of spliced grammar artifacts are replayed over the socket as well, so the bytes are not only the
ones someone thought to write down.

One of those cases also describes a real endpoint now. Live probing found
`rwhois.arin.net:4321` -- still named after the protocol, no longer speaking it -- which accepts a
connection, sends nothing until it is asked, and then answers with plain WHOIS text. Never
bannering is a protocol failure rather than a socket nuisance, because section 3.1.6 makes the
banner the second thing that happens on any connection, right after the client connects, so
`RwhoisClient` raises `RwhoisProtocolError` naming the endpoint, the timeout,
and the section instead of surfacing a bare `timed out`, and closes the socket it was refused on
rather than leaving it for the collector: a tool pointed at the wrong port a few hundred times
should not accumulate half-open connections against it.

That sentence about silence covered the easy half. A server that never goes silent -- one byte
every few tens of milliseconds, no line ending, no EOF -- resets the socket timeout on every
`recv`, so the per-syscall bound never fires, and at five bytes a second it never reaches the
byte ceiling either. Measured against a loopback dribbler before anything was changed, both
`RwhoisClient` and the classic WHOIS client were still blocked after five times their stated
`timeout`: the size ceilings assume the timeout is a total, and it is not. `LineReader` now takes
`line_deadline_seconds` (the client passes its own `timeout`) and raises `TimeoutError`, which is
what a silent socket raises, so callers that handle one handle the other; the WHOIS read loop
counts down a per-attempt total and raises the same, so a dribbling peer goes through the retry
plan instead of bypassing it. The bound is per line rather than per response so a slow honest
server is not punished, and `tests/test_slow_peer.py` pins that choice with an exchange whose
every line arrives inside the deadline while the whole response runs past it -- a case a
per-response budget would have failed, which is the only reason the test discriminates.

A detail of those tests is worth keeping in mind for any future bound: a test that waits for an
exception *hangs* rather than fails when the bound is removed, which is worse in CI than having
no test at all. Each case runs under a watchdog that turns "never returned" into an assertion
failure, verified by deleting the client's deadline and watching the suite fail in seconds.

One hazard there is worth recording, because it produced a flaky test before it was understood:
closing with `SO_LINGER` 0 sends an RST, which can **discard data the peer has not read yet**. An
assertion about delivered bytes against an RST-closing server is a coin flip. The suite therefore
closes gracefully when it asserts on content, and asserts narrowly against a reset -- that a
response cut short is never reported as `ok` -- which is the strongest claim an RST actually
supports.

## RFC 3912 WHOIS compliance

| Requirement | Status | Notes |
|---|---|---|
| TCP port 43 | partial experimental | `registrata.experimental.whois.whois_query` uses port 43 by default. |
| Query terminated by CR/LF | implemented | Raw client sends CRLF. |
| Response ends at connection close | implemented | Reads until close. |
| Character encoding handling | partial | Tries UTF-8 and falls back. |
| Strong security | not possible | RFC 3912 itself has none. |
| Field parsing | partial experimental | Common registry fields extracted, plus basic registry profile adapters. |
| Referral following | partial experimental | `lookup_whois(..., follow_referrals=True)` follows explicit `Refer`/`Whois Server` hints with a hop limit. |
| CLI `lookup` | partial experimental | Combines RDAP/WHOIS/RWhois behind one experimental command. |
| CLI comparison/schema commands | partial experimental | `compare` compares normalized records; `record-schema` prints or applies the stable normalized record schema. |
| CLI diagnostics commands | partial experimental | `trace` reports source hops/status/errors; `doctor` checks feature flags, classification, records, bootstrap cache, breaker state, and suggested commands. |
| CLI resource commands | partial experimental | `whois`, `domain`, `ip`, `asn`, and `rdap` commands are available. |
| CLI `bulk` runner | partial experimental | `registrata bulk` runs the unified lookup over a file of resources, or stdin when the source is `-`, on a bounded thread pool (default 4, ceiling 32) with a limiter, circuit breaker, and cache shared across the run, per-endpoint plus optional global rate limiting, dispatch-level stop conditions, and streaming JSONL output. Thread-based concurrency over blocking sockets; not event-loop-native I/O. |

## RDAP compliance

| Requirement | Status | Notes |
|---|---|---|
| RFC 9082 query paths | partial experimental | Domain/IP/ASN basic paths are supported. |
| RFC 9083 JSON response parsing | partial experimental | Common top-level fields plus the RFC 9083 section 4 data structures below. |
| RFC 9083 §4.1 `rdapConformance` | implemented client-side | Read from the topmost object only, as the RFC requires; identifiers other than `rdap_level_0` are reported as extension tokens in `record.conformance` and `record.context["extensions"]`. |
| RFC 9083 §4.2 links | implemented client-side | `value`, `rel`, and `href` are treated as mandatory and `complete` marks links that omit one; `hreflang` is normalized to a list; a `related` link repeating a `self` href is flagged `self_duplicate` and excluded from `record.referrals()`, which is what stops referral walking from looping. |
| RFC 9083 §4.3 notices and remarks | implemented client-side | Normalized `title`, `type`, `description` (always a list), and `links`; remarks are collected from nested entities, nameservers, networks, variants, and search results with a `scope` label, while notices are attributed to the topmost object. |
| RFC 9083 §4.4 language identifier | implemented client-side | The nearest enclosing `lang` wins and is inherited by nested structures. |
| RFC 9083 §6 error response body | implemented client-side | `errorCode`, `title`, and `description` are exposed through `RdapResult.error_details()` and the CLI/gateway payloads. |
| RFC 9083 §9 and §10.2.1 truncated responses | implemented client-side | The six registered truncation type values set `record.truncated` and populate `record.truncation` with the object scope that was reduced. |
| RFC 7480 §9.3 language and HTTP headers | implemented client-side | Language comes from the body; `Content-Language` is transport context only, matching the RFC's instruction not to conflate the two. |
| RFC 8288 `Link` header fields | partial experimental | Parsed (including repeated header fields and quoted parameters) and merged into `record.links` with scope `http:link`. |
| RFC 8982 partial response | partial experimental | The `fieldSet` query parameter can be requested; `subsetting_metadata` and the `subsetting` conformance token are normalized into `record.subsetting`. |
| RFC 9537 redacted fields | partial experimental | `redacted` entries are normalized with name (registered or unregistered), method (default `removal`), `pathLang` (default `jsonpath`), reason, and a flag when `prePath`/`postPath` are both set. JSONPath expressions are preserved, not evaluated. |
| RFC 9224 bootstrap resolution | partial experimental | Domain and IP/CIDR bootstrap helper functions added. |
| Bootstrap caching | partial experimental | TTL cache, conditional ETag/Last-Modified refresh, and stale-cache fallback are implemented. A per-file lock makes a cold fetch single-flight across threads, and the cache file is replaced by rename so concurrent readers never observe a partial document. |
| Response caching | partial experimental | Optional memory/file/SQLite TTL response cache is available for RDAP queries. |
| HTTP conditional caching | partial experimental | Implemented for RDAP bootstrap files and RDAP query responses. |
| RFC 8977 sorting and paging | planned | Result paging/sorting query parameters are not implemented. |
| RFC 8521 object tagging | planned | Tags are preserved in `raw` but not normalized. |
| RFC 9877 geofeed data | planned | Not normalized. |
| RFC 9910 RIR search, RFC 9536 reverse search | planned | Search response paths are not implemented, although `redacted` inside search results is normalized. |
| RFC 9560 federated authentication | planned | No OIDC client support. |

RDAP work here is client-side: this project reads and normalizes RDAP responses and
does not serve them, so "implemented" above always means a client behaviour. Two
mechanisms sometimes described for RDAP partial responses are deliberately absent
because the standards do not define them: `groupId`/`linksWithRel` do not exist in
RFC 9083, and a `Notice: 11100` response header is defined in neither RFC 7480 nor
RFC 9082. Truncation is therefore detected from the response body only, and any
`Notice` header is kept as opaque context.

## Normalized registration model

`registrata.model.RegistrationRecord` is the shared internal shape for RWhois objects,
classic WHOIS fields, and RDAP JSON. It preserves source raw data while exposing a
small comparison-friendly structure:

- `source`, `kind`, `identifier`, and `handle` for provenance and identity;
- `statuses`, `events`, `contacts`, `registrar`, `networks`, and `nameservers`;
- RDAP-specific `dnssec`, `notices`, `links`, `conformance`, `lang`, `truncated`,
  `truncation`, `redacted`, `subsetting`, and transport `context`;
- WHOIS/RWhois raw fields and objects under `raw`.

The normalized record schema is versioned (`registrata.record_schema.RECORD_SCHEMA_VERSION`,
currently `0.2`). Version 0.2 adds the RDAP extension fields listed above; consumers
that ignore unknown keys are unaffected, while code that asserted the exact key set
has to be updated.

The current implementation is intentionally conservative: dates keep both the source
string and a best-effort ISO value, because registration-data formats vary too much to
silently normalize.

## RWhois server conformance checker

`registrata check-server` performs a live, non-mutating probe of a server:

- reads and validates the banner/capability ID;
- exercises advertised `-holdconnect`, `-limit`, `-status`, `-soa`, `-directive`, and `-display` behavior;
- probes `-class`, and scores the answer by what the error code says about the *directive* rather
  than about the probe;
- sends a query probe and accepts structured expected errors such as `230` or `350`.

Three verdicts, not two. A directive gated by a banner capability that was never advertised is a
`skip`, and so is a `%error 400 Directive not available` answer to `-class`, because RFC 2167
section 3.3 files `-class` under "Optional Directives -- the server should implement the following
directives": declining it is lawful, and scoring it `fail` condemned servers that conform. What
counts as `pass` is an answer that proves the directive exists -- class metadata, or `230`, `340`,
`350`, since the probe sends a handle where an authority area belongs and any server that
implements `-class` reaches its own argument checking before it can answer those. Anything else is
`fail`.

An earlier version of that whitelist read `{201, 340, 230, 350}`. No RFC 2167 error is numbered
201, so the entry matched nothing legitimate; what it did let through was *unrecognised* codes,
which means the phantom entry's actual effect was to score an error the checker had never heard of
as evidence of conformance. That is the general hazard in a whitelist of codes -- the entry that
matches nothing is what decides the meaning of an unknown answer.
`tests/test_conformance_verdicts.py` pins each branch against a scripted server, which is the only
way a checker's verdicts can be tested at all: against this library's own server, every answer is
the friendly one.

`score` is the fraction of checks that ran, with skipped checks excluded from both sides, so a
server that advertises nothing optional does not report 0.33 next to an `ok` verdict.

This is a first conformance report, not a full RFC 2167 conformance suite.

## Structured logging

`registrata.observability` provides CLI logging configuration and a JSON formatter.
Library code emits low-noise diagnostics through normal Python loggers:

- RDAP HTTP request, retry, cache hit/miss/store, and error events;
- classic WHOIS query, retry, cache hit/miss/store, and referral-follow events;
- CLI command start and transport error events.

The CLI exposes:

```text
--log-level debug|info|warning|error|critical
--log-json
```

## Response safety limits

The clients now reject excessively large responses by default:

| Surface | Default limit | Behavior |
|---|---:|---|
| RWhois line reader | 1 MiB per line | Raises `RwhoisProtocolError`. |
| RWhois client response | 100,000 lines / 16 MiB bytes | Raises `RwhoisError`. |
| RDAP HTTP response | 4 MiB bytes | Returns `RdapResult.error`. |
| Classic WHOIS response | 4 MiB bytes | Returns `WhoisResult.error`. |

These limits reduce memory-bomb risk from malformed or malicious servers.

## Provenance, comparison, and schema output

`LookupResult.provenance()` returns source hop metadata for RDAP URLs/statuses,
classic WHOIS servers/referrals, and RWhois server/query/referral/error state. The
full structured JSON output includes it under `provenance`.

`registrata.comparison` compares normalized `RegistrationRecord` objects from multiple
sources. It normalizes case, trailing dots, ordering, common date spellings, email
addresses, and phone digits before diffing. The report includes:

- `matches`: fields that compare equal -- including fields every source left empty, which do
  agree; the absence is recorded separately rather than cancelling the match;
- `differences`: per-source normalized values for fields that disagree;
- `missing_or_empty`: sources where a field is absent or empty, whether or not the sources agree
  about being empty;
- `score`: fraction of compared fields that match, or `null` when nothing was compared;
- `comparable` and `reason`: whether a cross-check actually happened, and if not why -- one
  source, no sources, or a field list naming nothing recognised. These exist because a single
  record agrees with itself by construction, and the report used to answer that with
  `score: 1.0` and no differences -- indistinguishable from a healthy agreement, in the exact
  case where the second source had failed.

`registrata.record_schema` exposes stable normalized-record schema metadata, a
`record_to_schema()` wrapper, and a validator that walks the published document: required
members, types at every level of nesting, the item schemas for `links`, `notices` and `redacted`,
and their enums. It previously consulted only a flat top-level type map, which left the item
schemas shipped with version `0.2` describing shapes nothing checked -- a bare string inside
`notices`, or a redaction `method` outside RFC 9537's four values, both validated cleanly. That
mattered because `registrata doctor` derives its `invalid` record count and its overall health
verdict from this function, so an unchecked schema meant a malformed record reported healthy.
`validate_record()` takes the record payload (`record.as_dict()`, or `wrapped["record"]`) rather
than the wrapper, and the test suite pins both shapes so the difference is not a guess.

It is still a project-level contract for normalized output, not a JSON Schema validation engine:
no `$ref`, no `additionalProperties`, no `format`, and members the document does not mention are
accepted. `RECORD_TYPES` remains for callers that want only the outermost shape, and a test
asserts it agrees with the document rather than letting the two drift apart again.

## Circuit breaker and bootstrap cache behavior

`registrata.circuitbreaker` tracks consecutive endpoint failures in three states:
`closed`, `open`, and `half_open`. The unified lookup surface records endpoint
failures for RDAP, classic WHOIS, and RWhois sources and emits `LookupErrorItem`
entries when a breaker is open; those entries carry `kind="circuit_open"`, which is
what the bulk runner keys on instead of matching on message text. Gateway health
responses include the current breaker snapshot.

RDAP bootstrap files are cached on disk when `cache_dir` is supplied. After the
TTL expires, `load_bootstrap()` sends `If-None-Match` and `If-Modified-Since`
when the server previously supplied ETag/Last-Modified headers. A `304 Not
Modified` refreshes the cached timestamp without re-downloading the file. If a
refresh fails and a stale cached bootstrap file exists, the stale file is used
instead of failing the lookup.

The whole check-fetch-store sequence runs under a lock per bootstrap file, so the
several workers of a bulk run cost one download rather than one each, and the file
is written to a private temporary name and renamed into place, so a reader can never
observe the truncated document that `write_text` would have exposed mid-write.

RDAP query responses use the same conditional revalidation pattern through the
shared response cache. Successful responses store the JSON body plus validators
and a fresh-by timestamp. Expired entries with validators are revalidated with
conditional headers; expired entries without validators are fetched normally, and
transient failures fall back to stale data when available.

## Gateway mode

`registrata gateway` starts a local HTTP or HTTPS bridge for the experimental lookup surface.

Safety posture:

- disabled unless the gateway command or environment flag enables it;
- default bind is localhost;
- non-local binds require `allow_remote=True` or `--allow-remote`;
- optional per-client rate limiting;
- optional shared response cache;
- optional per-endpoint circuit breaking, visible from `/health` and `/metrics`;
- optional shared metrics counters and request-duration observations;
- optional API-key authentication via `X-API-Key` or `Authorization: Bearer`, compared in constant time, with `/health` left open for probes;
- optional TLS: `--tls-certfile` and `--tls-keyfile` wrap the listener in a server-side `ssl.SSLContext` with a TLS 1.2 minimum; the pair is validated before the socket is bound and `/health` reports `"tls": true`.

Endpoints:

```text
GET /health
GET /metrics
GET /lookup
GET /domain
GET /ip
GET /asn
GET /whois
GET /rdap
GET /rwhois
```

When an API key is configured, `/health` remains open for liveness checks and the
remaining endpoints require authentication.

`GET /rdap` mirrors the RDAP server's status code for a negative answer and adds a
decoded `rdap_error` member (RFC 9083 section 6) plus the extension fields
(`conformance`, `lang`, `truncated`, `truncation`, `redacted`, `subsetting`,
`context`) inside `normalized`; `field_set` requests an RFC 8982 partial response.

## Testing gaps

Current suite covers core RWhois and some server/client behavior, but needs:

- ABNF corpus;
- parser round-trip tests;
- fuzz corpus (basic malformed/oversized unit tests exist; full corpus remains);
- public server fixture recordings;
- RDAP bootstrap integration fixtures (RDAP extension, error-body, and HTTP-link
  behaviour is unit-tested in `tests/test_rdap_extensions.py` and
  `tests/test_rdap_http.py`; recorded server transcripts are not);
- WHOIS registry fixture corpus;
- CLI matrix tests;
- bulk runner coverage beyond the unit level: the bulk runner tests pin input
  ordering, the per-resource status vocabulary, the stop conditions, and the
  aggregate rate limit, but there is nothing that exercises a run against live
  registries or asserts real wall-clock timing.

## Release gate before claiming “protocol-complete”

Do not claim full RFC 2167 completeness until:

1. all ABNF constructs have tests; (met for 129 of 130: `tools/rwhois_grammar.py`
   inventories every Appendix B production and the coverage gate in
   `tests/test_rwhois_abnf.py` fails, naming the constructs, if any is exercised by no
   corpus case. `key-id` is the one gap and it is not closeable: Appendix B references it
   from `pgp-data` and never defines it, so there is no language to instantiate. Claiming
   it would be the false coverage this gate exists to prevent.)
2. server optional directive behavior is explicitly documented;
3. unsupported PGP security is not advertised;
4. forwarding behavior is either complete or disabled in capability flags;
5. registration/xfer semantics are tested against backend hooks;
6. fuzzing and malformed-input tests pass.

## Release gate before claiming “modern whois toolkit”

Do not claim modern WHOIS/RDAP toolkit until:

1. unified lookup model is stable;
2. RDAP bootstrap caching works;
3. rate limiting and retry policy are implemented; (per-server token bucket, retry/backoff, TTL response caching, RDAP bootstrap/query conditional and stale caching, and per-endpoint circuit breaking are implemented; proxy support and bulk policy remain)
4. CLI supports domain/IP/ASN/lookup workflows; (resource-specific `whois`, `domain`, `ip`, `asn`, and `rdap` commands are implemented; `compare`, `record-schema`, `trace`, and `doctor` are implemented; `profile` and richer server-side doctor checks remain)
5. normalized record output is documented;
6. at least common RDAP/WHOIS fixtures pass offline tests.

## RFC 2167 transcript corpus

`tests/fixtures/rwhois/` holds 73 transcripts consumed by `tests/test_rwhois_corpus.py`
through `manifest.json`, and `tools/generate_rwhois_corpus.py` rebuilds them
deterministically. 45 are hand-written; 28 are derived mechanically from the Appendix B
grammar by `tools/rwhois_abnf_gen.py`, which refuses to emit a value that its own
recognizer rejects and records, for every production it claims, the exact substring of the
transcript that instantiates it. Regenerating twice changes nothing on disk, and the
hand-written transcripts survive regeneration byte-for-byte.

| Population | Cases | What it pins |
|---|---|---|
| `valid/` | 45 | Banner, version lists and capability bits, object records with `;T`/`;I`/`;S` types, multi-object responses, referrals, Appendix C errors, `%status`/`%schema`/`%class`/`%soa`/`%directive`/`%display`/`%register`/`%notify`/`%xfer` grouping, and `%info` blocks. |
| `malformed/` | 23 | The rejection contract for hostile servers: missing separators, invalid ids, wrong-width error codes, bad capability ids, malformed referral URLs, malformed `%info` blocks. |
| `wire/` | 5 | `LineReader` behaviour: an over-long line is refused instead of buffered, 8-bit octets decode, and a bare LF still terminates a line. |

Guarantees the suite enforces:

- **Structure** — each valid transcript asserts parsed counts, attributes, and directive
  groups, not merely "it did not raise".
- **Round-trips** — banners, referrals, error lines, and status lines re-serialize
  byte-for-byte; object records re-parse to identical name/value/type triples.
- **Failure contract** — a malformed transcript must raise the documented
  `RwhoisError` subclass and nothing else. Seven inputs previously escaped as builtin
  `TypeError`/`ValueError` (bare `%info`, `%info off` without `%info on`, attribute lines
  missing a separator, non-numeric referral port, `Referral(port=...)`, malformed
  `%xfer` line); the parsers now raise `RwhoisParseError`, so a hostile server cannot
  surface as an HTTP 500 through the gateway.
- **Coverage** — every line prefix known to `protocol._PREFIXES` appears in at least one
  transcript, so a new prefix cannot ship without a fixture.

Provenance: transcripts are **synthesized to match the RFC 2167 grammar**, several quoted
verbatim from RFC 2167 examples (banner, `%status`, `%class`, `%directive`). None is a
live capture; every manifest entry carries `"recorded": false`. Real recordings slot in by
adding the transcript and marking it recorded with capture metadata.

Modelling notes the corpus records:

- `;T` normalizes to the bare attribute form on output because TEXT is the RFC 2167
  default type, so object round-trips compare re-parsed semantics rather than bytes.
- `%schema`, `%class`, and `%directive` are grouped per RFC 2167 (`*-record = *line
  "<prefix>"`): each record describes one attribute/class/directive and ends with the
  bare prefix line.
- `%notify` and unrecognized `%`-lines are preserved verbatim in `other_lines` instead of
  being dropped.
