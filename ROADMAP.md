# Roadmap

`registrata` is being positioned as a Python registration-data toolkit with first-class RWhois correctness, modern WHOIS/RDAP compatibility, and a unified structured lookup model.

The project is not trying to be only a historical RWhois client. The long-term goal is to beat today’s WHOIS tooling in three areas:

1. protocol correctness;
2. structured machine-readable results;
3. server/compliance tooling.

## Naming

The project was renamed from `pyrwhois` (importing as `rwhois`) to `registrata`
(imports as `registrata`, command `registrata`). Rationale: the toolkit spans RWhois,
classic WHOIS, and RDAP, so a protocol-specific name under-sells it, and the `reg`/`rda`
acronym space on PyPI is already occupied by regression tooling, Windows-registry
tooling, redistricting analytics (`rdapy`), and NCAR's Research Data Archive.

Deprecated seams that still work, and their removal criteria:

| Seam | Behaviour | Remove when |
|---|---|---|
| `import rwhois` | Re-exports `registrata`, aliases every submodule to the same module object, emits `DeprecationWarning`. | A release with no reported use of the old import path. |
| `rwhois` console script | Same entry point as `registrata`. | Same. |
| `pyrwhois_cache` SQLite table | Renamed to `registrata_cache` on first open. | Cache files older than one release cycle. |
| `pyrwhois` log-record payload key | Still read by `JsonFormatter`. | Downstream log pipelines migrate to `registrata`. |
| `RWHOIS_*` environment variables | `RWHOIS_ENABLE_EXPERIMENTAL*` and `RWHOIS_GATEWAY_API_KEY` are still read; `REGISTRATA_*` wins when both are set. | One release cycle after `REGISTRATA_*` is documented everywhere. |


## Obligation matrix

The honesty rule: a row may read `[ok]` only when a named test would fail if the behaviour
regressed. `tests/test_roadmap_rows.py` refuses a row that claims progress without naming a test that
exists. The phase checklists below are the narrative; this table is the work queue.

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is missing stated --
`[ ]` not implemented -- `[no]` deliberate non-goal.

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `banner.parse_banner()` | RFC 2167 section 3.1.6 | `[ok]` | `tests/test_banner.py::test_banner_parse_rfc_example` | M1 |
| `query.parse_query()` | RFC 2167 section 3.4, Appendix B | `[ok]` | `tests/test_query.py::test_parse_query_class_restricted` | M1 |
| `protocol.parse_response()` | RFC 2167 section 3.1, Appendix C | `[ok]` | `tests/test_rfc2167_appendix_c.py::test_the_enum_is_exactly_appendix_c` | M1 |
| `wire.encode_line()` | RFC 2167 section 3.1 (line framing; a served line may not carry CR or LF) | `[ok]` | `tests/test_rwhois_framing.py::test_a_line_break_in_a_served_line_is_refused_before_anything_is_written` | M1 |
| `resolver.dedupe_referrals()` | RFC 2167 sections 2.5, 2.5.1 (missing: index-server routing) | `[part]` | `tests/test_resolver.py::test_resolver_follows_link_referrals` | M2 |
| `schema.validate_for_registration()` | RFC 2167 section 2.3, Appendix C | `[ok]` | `tests/test_register.py::test_del_removes_the_object_it_identifies` | M2 |
| `conformance.check_server()` | RFC 2167 sections 3.1, 3.3, Appendix C | `[ok]` | `tests/test_conformance.py::test_check_server_reports_ok_on_local_memory_server` | M2 |
| `rwhois.private-policy` | RFC 2167 section 2.3.1 | `[ok]` | `tests/test_register.py::test_a_private_object_is_withheld_and_reads_as_no_match` | M2 |
| `rwhois.guardian` | RFC 2167 section 2.3.6 (password scheme only; missing: other schemes and the area-wide guardian) | `[part]` | `tests/test_register.py::test_the_guardians_own_password_satisfies_it` | M2 |
| `rwhois.registration-deferred` | RFC 2167 section 3.3.9 | `[ok]` | `tests/test_register.py::test_registration_can_be_deferred_while_queries_keep_working` | M2 |
| `rwhois.invalid-class` | RFC 2167 section 4 | `[ok]` | `tests/test_server_client.py::test_a_query_naming_an_unknown_class_is_refused_as_invalid_class` | M2 |
| `rwhois.forward-notify-xfer` | RFC 2167 section 3.3 | `[ ]` | `tests/test_server_extra.py::test_forward_notify_xfer` (to be written) | M3 |
| `rwhois.live-transcript` | RFC 2167 (no public RWhois server remains to record from; the corpus is synthesized from Appendix B) | `[no]` | `tests/test_rwhois_corpus.py` | - |
| `whois.parse_fields` | RFC 3912 | `[ok]` | `tests/test_experimental_whois.py::test_parse_whois_fields` | M4 |
| `whois.referral-following` | RFC 3912 | `[ok]` | `tests/test_experimental_whois.py::test_lookup_whois_follow_referrals_and_caches` | M4 |
| `whois.registry-adapters` | RFC 3912 (registry profiles are not specified by it; only ARIN and RIPE are pinned) | `[part]` | `tests/test_whois_adapters.py::test_detect_whois_profiles` | M4 |
| `rdap.bootstrap` | RFC 9224 | `[ok]` | `tests/test_experimental_rdap.py::test_resolve_domain_base_longest_match` | M5 |
| `rdap.normalize` | RFC 9083 | `[ok]` | `tests/test_experimental_rdap.py::test_normalize_rdap` | M5 |
| `rdap.error-body` | RFC 9083 section 6 | `[ok]` | `tests/test_rdap_http.py::test_error_details_reads_full_section_6_body` | M5 |
| `rdap.link-header` | RFC 8288 | `[ok]` | `tests/test_rdap_http.py::test_parse_link_header_two_targets_in_one_value` | M5 |
| `rdap.partial-response` | RFC 8982 | `[ok]` | `tests/test_rdap_extensions.py::test_subsetting_metadata_normalizes_the_field_sets` | M5 |
| `rdap.redacted-fields` | RFC 9537 | `[ok]` | `tests/test_rdap_extensions.py::test_redacted_defaults_and_registered_name` | M5 |
| `rdap.sort-paging` | RFC 8977 | `[ ]` | `tests/test_experimental_rdap.py::test_sort_and_paging` (to be written) | M6 |
| `rdap.object-tagging` | RFC 8521 | `[ ]` | `tests/test_experimental_rdap.py::test_object_tagging` (to be written) | M6 |
| `rdap.geofeed` | RFC 9877 | `[ ]` | `tests/test_rdap_extensions.py::test_geofeed` (to be written) | M6 |
| `rdap.rir-and-reverse-search` | RFC 9910, RFC 9536 | `[ ]` | `tests/test_experimental_rdap.py::test_search_extensions` (to be written) | M6 |
| `rdap.federated-auth` | RFC 9560 | `[ ]` | `tests/test_experimental_rdap.py::test_federated_auth` (to be written) | M6 |
| `special_names.special_use_reason()` | RFC 2606, RFC 6761 | `[ok]` | `tests/test_special_names.py::test_special_use_names_are_recognised` | M7 |
| `cache.make_cache()` | design | `[ok]` | `tests/test_cache.py::test_make_cache_backends` | M7 |
| `retry.with_retries()` | design | `[ok]` | `tests/test_retry.py::test_with_retries_returns_success_and_sleeps` | M7 |
| `circuitbreaker.run_with_circuit()` | design | `[ok]` | `tests/test_circuitbreaker.py::test_registry_and_run_with_circuit_block_open_endpoint` | M7 |
| `ratelimit.token-bucket` | design | `[ok]` | `tests/test_ratelimit.py::test_token_bucket_acquire_and_refill` | M7 |
| `lookup.unified` | design (one normalized record over RWhois, WHOIS and RDAP) | `[ok]` | `tests/test_experimental_lookup.py::test_lookup_rdap_and_whois_normalizes_rdap` | M8 |
| `lookup.batch` | design | `[ok]` | `tests/test_batch.py::test_batch_returns_items_in_input_order_while_on_result_sees_completion_order` | M8 |
| `gateway.tls` | design | `[ok]` | `tests/test_gateway.py::test_gateway_tls_wraps_listening_socket` | M8 |
| `cache.redis` | design | `[ ]` | `tests/test_cache.py::test_redis_cache` (to be written) | M9 |
| `net.proxy-and-pooling` | design | `[ ]` | `tests/test_rdap_http.py::test_proxy_and_pooling` (to be written) | M9 |
| `obs.opentelemetry` | design | `[ ]` | `tests/test_observability.py::test_opentelemetry_hooks` (to be written) | M9 |
| `rwhois.replication-helpers` | RFC 2167 section 3.3.14 | `[ ]` | `tests/test_server_extra.py::test_replication_helpers` (to be written) | M9 |

Section numbers marked above were carried over from this project's `docs/spec.md` and
`docs/compliance.md`; `docs/rfc-map.md` records the status of every document the table cites, verified
against the publisher record through rfclib on 2026-11-09.

## Milestones

- M1 RWhois wire layer: banner, query, response and framing
- M2 RWhois server: registration, privacy, guardians, conformance checking and referral resolution
- M3 RWhois directives still stubbed: forward, notify, xfer
- M4 Classic WHOIS (RFC 3912) client, referral following and registry adapters
- M5 RDAP core: bootstrap, normalization, errors, links and the shipped extensions
- M6 RDAP extensions not yet implemented
- M7 Production client behaviour: special-use refusal, caching, retry, breaker and rate limit
- M8 Unified lookup, bulk runner and the local gateway
- M9 Optional extras: Redis, proxy and pooling, OpenTelemetry, replication helpers

## Status legend

| Status | Meaning |
|---|---|
| Implemented | Exists and is covered by tests. |
| Partial | Basic implementation exists but is not production-complete. |
| Planned | Intended roadmap item. |
| Explicit non-goal | Not doing it by default unless there is a concrete reason. |

## Current maturity

| Area | Status | Notes |
|---|---|---|
| RFC 2167 RWhois wire parsing | Implemented | Banners, capability IDs, responses, result records, referrals, errors. |
| RWhois TCP client | Implemented | Directives, queries, holdconnect, status, SOA, schema, class, basic register/security. |
| RWhois TCP server | Partial | Threaded toolkit, memory backend, many directives implemented, replication/security/forwarding remain limited. |
| Referral resolver | Partial | Follows referrals and dedupes by auth-area; needs richer routing/index-server behavior. |
| Schema/SOA helpers | Partial | Parsing and model objects exist; validation and policy need more work. |
| CLI | Partial | Core RWhois commands plus resource-oriented `whois`, `domain`, `ip`, `asn`, `rdap`, unified `lookup`, `trace`, `doctor`, `compare`, and `record-schema`. |
| Classic WHOIS RFC 3912 | Partial experimental | Raw client, field extractor, registry profile adapters, encoding/referral handling, referral following, response cache hooks. |
| RDAP bootstrap/JSON | Partial experimental | Bootstrap TTL and conditional (ETag/Last-Modified) cache, stale bootstrap fallback, response TTL cache with conditional query revalidation/stale fallback, improved normalization, retry/limiter hooks. |
| Unified lookup API | Partial experimental implemented | Shared normalized `RegistrationRecord` model, source-specific record conversion, provenance/hop trace, comparison, stable schema output, cache/referral/retry/circuit-breaker hooks. |
| Caching/rate limiting | Partial experimental implemented | Memory/file/SQLite TTL caches, RDAP bootstrap and query response conditional/stale caching, per-server token bucket, retry/backoff, and per-endpoint circuit breaker. |
| Observability | Partial | Structured logging, JSON formatter, and CLI diagnostics for cache/referral/retry flows. |
| Reliability hardening | Partial | Line-length and response-size limits for RWhois/RDAP/WHOIS, malformed decoding tests, cache serialization tests; the RWhois transcript corpus (73 cases, 45 hand-written plus 28 derived from the Appendix B grammar) now pins parser structure, round-trips, the hostile-input exception contract, and ABNF production coverage. Seeded generative properties (`tests/test_rwhois_property.py`) and a server framing guard (`tests/test_rwhois_framing.py`, refusing to emit a served value containing CR or LF, which is response-line injection in this protocol) extend that beyond the fixed fixtures. |
| Async/bulk queries | Done for experimental | `registrata.experimental.batch.batch_lookup()` and `registrata bulk` cover a bounded thread pool over the unified lookup (default 4, ceiling 32), a shared limiter/circuit-breaker/cache per run, per-endpoint plus optional global rate limiting, fail-fast/stop-on-open-circuit/deadline/cancel stop conditions, and streaming JSONL output. Not covered: event-loop-native RDAP/WHOIS I/O (`batch_lookup_async()` is a thread offload), a distributed queue, and bulk scanning policy. |
| Server conformance checker | Basic implemented | `registrata check-server` probes banner, advertised directives, classes, and query behavior. |
| Gateway mode | Basic experimental implemented | Local HTTP endpoints for lookup/domain/ip/asn/whois/rdap/rwhois/health/metrics with cache, rate-limit, circuit-breaker, metrics, and optional API-key hooks. TLS and richer authz remain. |
| Full RDAP server | Non-goal initially | Existing RDAP servers are specialized; this project may integrate with or bridge them. |

## Phase 0 — RWhois core

Goal: make the basic RFC 2167 foundation reliable.

Implemented:

- dependency-free Python package;
- typed wire objects;
- TCP client;
- TCP server toolkit;
- capability IDs;
- error codes;
- referral URL handling;
- query builder/parser;
- SOA and schema helpers;
- in-memory backend;
- CLI prototype;
- test suite.

## Phase 1 — RWhois conformance hardening

Goal: make RWhois genuinely protocol-complete and testable.

Planned tasks:

- [x] Add ABNF-derived corpus tests (`tools/rwhois_grammar.py` inventories all 130 Appendix B productions, `tools/rwhois_abnf_match.py` transcribes a recognizer per production, `tools/rwhois_abnf_gen.py` derives 28 wire cases whose claims are witness-checked, and `tests/test_rwhois_abnf.py` gates coverage at 129/130 with `key-id` documented rather than claimed).
- [x] Add parser round-trip property tests (`tests/test_rwhois_property.py`: seeded generators over the production alphabets, fidelity plus serialize/parse fixed points, a hostile-splice battery that asserts no builtin escapes and no parse exceeds a line budget, and an anti-vacuity rejection count. Seeded stdlib generation, not hypothesis; the generators drive the parser directly rather than round-tripping through a live server, which remains open).
- [x] Add fuzz corpus for malformed server responses (`tests/fixtures/rwhois/malformed/` + `wire/`, 28 cases).
- [ ] Expand server conformance checks for optional directives.
- [ ] Document which optional directives are supported, stubbed, or backend-specific.
- [x] Tighten registration validation: required attributes, primary key rules, repeatable vs
  multi-line rules, and ID/Updated assignment are all enforced against the advertised class
  schema now, each fault answering with the Appendix C code that names it (320-325, 336, 338,
  340, 341, 400, 401) instead of one catch-all 402. The backend's write paths had been
  extending the class definition to fit whatever arrived, which made validation unreachable.
  `tests/test_register.py` drives it over real sockets.
- [ ] Implement or clearly stub:
  - `-forward`;
  - `-notify`;
  - `-xfer` serial tracking.
- [x] Private attribute and object policy (RFC 2167 §2.3.1). This was not a missing feature so
  much as a hole: `Private` was advertised in `%schema`, parsed back out of it, and never
  consulted when a response was built, so every private attribute-value pair was served to any
  client that could open a socket -- including the `Guard-Info` password the guardian work had
  just started writing into guardian objects. Both levels are enforced at the single emission
  site now (attribute values stripped; an object flagged private at object level withheld
  entirely), gated on the same guardian check registration uses so the two cannot diverge, and a
  withheld record answers `%error 230` rather than an empty set so the filter cannot be used as
  an existence oracle. A guardian object guards itself, so its own password is what unlocks
  reads and edits of it.
- [x] Guardian enforcement for `-register` (RFC 2167 §2.3.6). The `guardian` class now declares
  `Guard-Scheme` and `Guard-Info`, both required, the latter `Private` as the text directs. A
  `Guardian` value naming no guardian object is refused with 323; `mod` and `del` of a guarded
  object require one guardian to be satisfied (no rank -- any one suffices), the only satisfiable
  scheme being `password`, the section's own example for `Guard-Info`; a scheme this server
  cannot check is a 420 rather than a pass, because treating "cannot check" as "allowed" would
  make declaring a stronger guardian a way around protection. Backends without ID lookup declare
  `supports_object_lookup = False` and the server logs `guardian_checks_skipped` rather than
  claiming a check it did not run. Not done: schemes other than `password`, the area-wide
  guardian of §2.3.6's last paragraph (the text gives the effect, not the mechanism), and any
  gating of reads, which the spec hedges to "possibly view".
- [x] `120 Registration deferred`: `RwhoisServer(registration_deferred=True)` refuses register
  directives with the code §3.3.9 lists for exactly this, while queries keep being answered --
  a maintenance window that speaks the protocol instead of hanging.
- [~] RDAP conditional revalidation cannot engage against the largest gTLD registries. Live
  capture on 2026-11-05: `rdap.verisign.com/com/v1` returns only
  `Content-Type`; PIR's endpoint returns only `Date` and `Content-Type`. No `ETag`, no
  `Last-Modified`, no `Cache-Control`, no `Expires` -- so the 304 path, which the fixture tests
  exercise correctly, never fires in production for `.com` or `.org`, and freshness falls back to the
  configured TTL. Re-checked from this environment with the same result, so it is not a one-day
  artifact.
  - [x] `docs/experimental.md` now says this plainly: which validators are actually absent, that
    the 304 path therefore never fires against these two registries, and that the local TTL is
    what bounds staleness in the meantime.
  - [ ] Consider RFC 7480
    Appendix B's cache-busting parameter for `force_refresh` (section 4.3 requires servers to ignore
    unknown query parameters, so the trick is compatible -- though Appendix B itself offers it as
    informational rather than specified). Deliberately not done for now: it only helps behind a
    caching proxy, and inventing a query parameter for registries that advertise no shared caching
    trades a clean request URL for a benefit that does not exist here. The doc note names this so a
    deployer behind a proxy knows to revisit it.

  Verified in passing, so that nobody "corrects" it later: **RFC 7480 is not obsoleted.** RFC 9082
  states "This document obsoletes RFC 7482", and RFC 7480's own text carries no obsolescence notice,
  so the `RFC 7480 §9.3` transport-context citation in the docs is against a current document.

- [x] A query restricted to an unknown class now answers `%error 341 Invalid class`. Section 4 lists
  341 among the errors a query may return, so this was answerable from the source text once the
  document was fetched whole. The server used to answer `%error 230 No objects found`, which made a
  typo in a class name read as an absent resource -- while this library's own client treats 230 as an
  answer and 341 as a failure, so the server was reporting a broken query as information about the
  world. `tests/test_server_client.py` pins both halves, including that a known class with nothing
  matching still answers 230.

- [x] Verify the remaining RFC 2167 source claims, by fetching the document in full and reading the
  parts that had been carried as notes. The whole file fits in one local fetch, which removes the
  truncation that blocked this. Findings:
  - **There is no error code 201.** The list runs 120, 130, 230, 300 onward, and 201 appears nowhere
    in the document, so dropping it from `check_server`'s whitelist was correct.
    `tests/test_rfc2167_appendix_c.py` now asserts the enum against a fresh transcription of
    Appendix C: every code, every error text, the fourteen obsolete RFC 1714 codes that must read as
    unknown rather than valid, and the rule that an implementation-specific code carries 6 in the
    second position. That file is what replaces "trust this project's own copy of the appendix".
  - **Section 3.1.4 is "Result"**, not connection handling: it says the last line of a result is
    `%ok` or `%error`. The citation that once justified holding connections open by default was
    wrong about the section as well as wrong about the default.
  - **Section 3.1.6 corroborates the design that shipped.** Its session sequence ends "The server
    closes the connection, unless the client has directed it not to close the connection", so a
    client negotiating `-holdconnect on` is using the documented path rather than working around the
    protocol.
  - The banner-on-connect rule is in 3.1.6 and the glossary, not 3.1.1. The client's no-banner
    diagnostic and `docs/compliance.md` cited 3.1.1 on assumption; both now cite 3.1.6.

## Phase 2 — Classic WHOIS compatibility

Goal: make the library practically useful for today’s WHOIS ecosystems.

Planned tasks:

- [x] Add RFC 3912 raw WHOIS client.
- [x] Add common WHOIS field extractor.
- [x] Add resource classifier for domain/IP/CIDR/ASN/entity/text.
- [x] Add experimental unified `lookup` CLI.
- [x] Add safe WHOIS server discovery helpers.
- [x] Add registry-specific adapters as optional modules.
- [x] Add structured referral extraction.
- [x] Add raw text preservation and encoding handling.
- [x] Add CLI commands:
  - `whois`
  - `domain`
  - `ip`
  - `asn`
  - `rdap`

## Phase 3 — RDAP compatibility

Goal: support the modern successor to WHOIS without losing the RWhois core.

Planned tasks:

- [x] Add RDAP bootstrap file loader.
- [x] Add minimal RDAP JSON response normalization.
- [x] Add bootstrap caching with TTL.
- [ ] Add domain, IP, CIDR, ASN, nameserver, entity, help queries.
- [x] Support HTTP headers and conditional caching for RDAP query responses.
- [x] Support richer HTTP notices and links handling for RDAP query responses
  (RFC 8288 `Link` fields, repeated header combination, `Content-Language` kept as
  advisory transport context per RFC 7480 §9.3).
- [x] Normalize the RFC 9083 §4 data structures: `rdapConformance` (§4.1), links
  with mandatory-member and loop-risk flags (§4.2), notices and remarks with
  scope and language provenance (§4.3), `lang` inheritance (§4.4), and the
  §6 error response body.
- [x] Detect truncated/partial responses from typed notices and remarks
  (RFC 9083 §9 with the type registry in §10.2.1).
- [x] Add extension awareness:
  - [x] partial response (RFC 8982 `fieldSet` parameter and `subsetting_metadata`);
  - [x] redacted fields (RFC 9537 `redacted` member, paths preserved unevaluated);
  - [ ] pagination/sorting (RFC 8977);
  - [ ] object tagging (RFC 8521);
  - [ ] geofeed (RFC 9877);
  - [ ] RIR search (RFC 9910) and reverse search (RFC 9536);
  - [ ] federated authentication (RFC 9560).
- [x] Add RDAP-aware rate limiting and backoff.
- [x] Add `rdap` CLI subcommand.

## Phase 4 — Unified lookup model

Goal: one Python API for multiple registration-data sources.

Target API:

```python
from registrata.experimental import lookup

result = lookup("isoc.org", sources=["rdap", "whois"])
result.normalized
result.raw
result.servers
result.errors
```

Planned work:

- [x] Define a stable normalized record model.
- [x] Convert RWhois objects to normalized records.
- [x] Convert WHOIS fields to normalized records.
- [x] Convert RDAP JSON to normalized records.
- [x] Add source provenance and server hop traces.
- [x] Add comparison/diff output.
- [x] Add stable JSON schema output.
- [x] Refuse RFC 2606/6761 special-use names before asking a public registry, reported as `LookupResult.unqueryable` (batch status `reserved`) so a name that cannot exist is never recorded as a miss or a fault. Explicitly targeted servers are still asked, since a private RWhois tree may hold such objects.

## Phase 5 — Production client behavior

Goal: make bulk and interactive use safe.

Planned tasks:

- [x] Add basic caching:
  - [x] memory;
  - [x] disk (JSON);
  - [x] SQLite;
  - [ ] optional Redis backend.
- [x] Add per-server rate limiting.
- [x] Add retry/backoff.
- [x] Add per-endpoint circuit breaker for lookup sources and gateway requests.
- [x] Add response-size limits for RWhois, RDAP, and classic WHOIS clients.
- [x] Add a bounded bulk runner over the unified lookup surface
  (`registrata.experimental.batch.batch_lookup()`, CLI `registrata bulk`): thread pool
  with a 1-32 worker clamp, limiter/circuit breaker/cache shared across the run,
  optional global rate limit, fail-fast/stop-on-open-circuit/deadline/cancel stop
  conditions, and streaming JSONL output. Event-loop-native I/O and a distributed
  queue are out of scope for now.
- [ ] Add proxy support.
- [ ] Add HTTP connection pooling via optional extra.
- [x] Add timing and structured logging. Cache/referral/retry diagnostics are emitted through `logging`; OpenTelemetry remains planned.
- [ ] Add OpenTelemetry hooks.

## Phase 6 — Better CLI

Goal: make the project pleasant for operators.

Planned commands:

```text
registrata whois <resource> [--json]
registrata domain <resource> [--json] [--records-only]
registrata ip <resource> [--json] [--records-only]
registrata asn <resource> [--json] [--records-only]
registrata rdap <resource> [--json] [--record-only]
registrata lookup <resource> [--source rwhois|whois|rdap] [--json]  # experimental
registrata lookup <resource> [--json] [--provenance]
registrata compare <resource> --sources rdap,whois [--fields identifier,statuses]
registrata record-schema [resource] [--json]
registrata bulk <file|-> [--json|--jsonl] [--concurrency N]  # experimental
registrata trace <resource> [--json]
rwhois profile <server>
registrata check-server <host> <port>
registrata doctor <resource> [--json] [--no-lookup]
registrata serve
```

## Phase 7 — Server and compliance toolkit

Goal: provide a unique alternative to client-only WHOIS tools.

Planned tasks:

- [x] Add `registrata check-server`.
- [x] Add conformance report generation.
- [x] Make `-register` real on the server. The directive parsed and reached write methods
  that validated nothing usefully — `create_object` called `ensure_class(area, class, obj)`,
  extending the class schema to fit whatever the client had just sent, so no object could
  fail validation — and a single `except Exception` turned every failure, the client's
  malformed line as much as a server fault, into `%error 402 unidentified error`. Submitted
  objects are now validated against the class the server
  advertises, answered with the Appendix C code that names the fault (320 undeclared
  attribute or client-assigned `ID`, 321 malformed value, 322 missing required or
  identifying attribute, 323 disagreeing `mod` halves, 324 duplicate primary key, 325 stale
  `Updated`, 336 unknown `ID`, 338 bad line, 340/341 unknown area/class, 400 read-only
  backend, 401 unauthenticated); the server assigns `ID`/`Updated`; every write advances the
  SOA serial, which is how a slave decides to re-transfer. `Guardian` authorization and
  `120 Registration deferred` remain open. 27 tests in `tests/test_register.py` drive it
  over a socket — there were none, which is how the broken write path survived.
- [x] Record payloads from live registry services. This was previously written as blocked on
  network egress, and the evidence recorded with it (TCP handshakes completing while zero bytes
  came back) was real at the time. Re-probed on 2026-11-05 the sandbox has working egress: DNS
  returns genuine registry addresses and real data flows. Five captures now live in
  `tests/fixtures/live/` (PIR WHOIS, Verisign WHOIS, IANA WHOIS, Verisign RDAP, PIR RDAP), all of
  reserved RFC 2606 documentation domains, with provenance in that directory's README and an
  offline replay suite in `tests/test_live_fixtures.py` (set `REGISTRATA_RUN_LIVE=1` to run the
  same resources against the live services). Authenticity rests on content a relay could not
  supply: a `Last update of WHOIS database` stamp matching the capture minute, registry-specific
  terms of use, and `rdapConformance` values including `redacted`.
  **This is the highest-value pass of the project so far.** Three defects came out of it, none of
  which every spec-derived fixture in the repository had caught: prose containing a URL was being
  parsed into WHOIS fields; RFC 9537 redaction was reported as truncation, which made the CLI warn
  on essentially every modern gTLD record; and a followed referral chain was not recorded anywhere,
  so an answer that arrived from a different server about a different object looked like a wrong
  record. See `docs/experimental.md` and the fixture README.
- [ ] Record a live RWhois transcript. Still impossible, but for a different reason than egress:
  **there is no public RWhois server left to record from.** `rwhois.arin.net:4321` accepts a
  connection and says nothing until asked, then answers with plain WHOIS text beginning `#\n# ARIN
  WHOIS data and services...` -- not a `%rwhois V-1.5:` banner, so it is not speaking RFC 2167
  however the port is labelled; `rwhois.denic.de` and `rwhois.nic.cz` no longer resolve. The RWhois
  corpus therefore remains synthesized from the Appendix B grammar, and the wire-compatibility claim
  should be read with that limit on it. What live contact did produce is a client-side behaviour: a
  server that never banners now raises a `RwhoisProtocolError` naming the endpoint and section 3.1.1
  instead of surfacing a bare `timed out`.
- [x] Add malicious-server fuzz fixtures (23 malformed transcripts plus 5 wire-level cases, pinning that only `RwhoisError` subclasses escape).
- [x] Exercise the client transport against an adversarial server (`tests/test_rwhois_hostile_server.py`: a scripted loopback server drives the real `RwhoisClient` through oversized lines, line- and byte-budget floods, mid-response closes and resets, silence, a non-banner first line, binary noise, and 12 seeds of spliced grammar artifacts replayed over a socket).
- [ ] Add replication helpers for slave/master state.
- [ ] Add example registry backends:
  - domain;
  - IPv4/IPv6;
  - ASN;
  - entity.
- [ ] Add metrics and audit hooks for server deployments.

## Phase 8 — Optional gateway mode

Goal: expose legacy protocols through modern local interfaces.

Planned tasks:

- [x] Local HTTP endpoint for `/whois`, `/rwhois`, `/rdap`, `/lookup`, `/domain`, `/ip`, `/asn`, `/health`, and `/metrics`.
- [x] TLS support (`--tls-certfile`/`--tls-keyfile` as a pair, server-side context pinned to TLS 1.2+, validated before bind).
- [x] Authentication policy. Richer authorization policies (roles, OAuth, per-client quotas) remain.
- [x] Response caching.
- [x] Rate limiting.
- [x] Metrics.

## Research and competitive comparison

See:

- `docs/research.md`
- `docs/compliance.md`

### Known gap in the local RFC index (rfclib)

RFC 2167 has no machine-readable table of contents, so rfclib segments it with
the left-margin fallback scan. That scan ran candidate titles through a
capitalisation filter, and RFC 2167 names its directive subsections with a bare
lowercase word (`3.3.5 holdconnect`), so all of `3.2.1` and `3.3.1`-`3.3.15`
were invisible and every directive quote resolved to the parent `3.3`. RFC 1714
(obsoleted by 2167, same lowercase titles) was never affected: it has a ToC,
and ToC titles bypass the filter.

Fixed in rfclib (`chunker._clean_title` gained an opt-in `allow_lowercase` used
only by that scan, which is already gated by the outline-successor rule) plus
`tests/test_txtseg.py`. Verified: RFC 2167 goes from 46 to 62 sections, nothing
lost, 13 other Legacy documents unchanged, full rfclib suite green.

Until the corpus is re-indexed (`rfclib index build`, which cannot be scoped to
one document) the DB still carries the old `3.3` labelling, so quotes for the
directive sections are taken from the fetched RFC text, not from the index.

## Feature flags

Experimental functionality lives under:

```python
from registrata.experimental import whois, rdap
```

Flags are controlled by environment variables:

```powershell
$env:REGISTRATA_ENABLE_EXPERIMENTAL = "1"
$env:REGISTRATA_ENABLE_EXPERIMENTAL_WHOIS = "1"
$env:REGISTRATA_ENABLE_EXPERIMENTAL_RDAP = "1"
$env:REGISTRATA_ENABLE_EXPERIMENTAL_GATEWAY = "0"
```

The pre-rename `RWHOIS_*` spellings are still read; `REGISTRATA_*` wins when both are set.

Default:

| Feature | Default |
|---|---|
| `whois` | enabled |
| `rdap` | enabled |
| `gateway` | disabled |

The default enables the most useful experimental paths while keeping the unstable gateway mode off.

