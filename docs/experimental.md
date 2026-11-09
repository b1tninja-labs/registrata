# Experimental features

Experimental features live under `registrata.experimental`. They are useful for research and building toward the modern roadmap, but their public API may change.

## Flags

| Feature | Env var | Default |
|---|---|---|
| Classic WHOIS | `REGISTRATA_ENABLE_EXPERIMENTAL_WHOIS` | enabled |
| RDAP | `REGISTRATA_ENABLE_EXPERIMENTAL_RDAP` | enabled |
| Gateway/bridge | `REGISTRATA_ENABLE_EXPERIMENTAL_GATEWAY` | disabled |

`REGISTRATA_ENABLE_EXPERIMENTAL` enables or disables all experimental features, and individual feature env vars override it.
The pre-rename `RWHOIS_*` spellings are still read for compatibility; a `REGISTRATA_*` value wins when both are set.

## Classic WHOIS

```python
from registrata.experimental import whois

result = whois.whois_query("example.com", "whois.iana.org")
print(result.fields)
print(result.referrals)
```

Status:

- raw RFC 3912 client;
- common field parser, with banner and commentary lines skipped so a sentence containing a URL is
  not mistaken for a field;
- referral extraction, plus `result.hops` recording every server asked, in order;
- experimental server discovery only for domains via IANA.

Following referrals defaults to **off in the API** (`follow_referrals=True` opts in) and **on in
the CLI** (`--no-referrals` opts out): a chain is the normal case at a command line and a surprise
inside a library call. Either way `hops` says where the answer came from, and that matters more
than it sounds, because a chain can end somewhere that answers about a different object — live
Verisign data for `example.com` names `whois.iana.org` as the registrar service, and IANA answers
about the `.COM` TLD rather than the domain.

## RDAP

```python
from registrata.experimental import rdap

result = rdap.lookup_rdap("example.com")
normalized = rdap.normalize_rdap(
    result.data,
    headers=result.headers,
    url=result.url,
    status=result.status,
)
print(normalized.nameservers)
print(normalized.truncated, normalized.redacted, normalized.conformance)
```

Status:

- IANA bootstrap resolver helpers;
- basic RDAP JSON GET support;
- basic normalization;
- bootstrap TTL cache, conditional ETag/Last-Modified refresh, and stale bootstrap fallback;
- optional memory/file/SQLite response cache;
- RDAP query-response conditional revalidation and stale fallback;
- extension-aware normalization of the RFC 9083 section 4 data structures, plus
  partial responses (RFC 8982) and redacted fields (RFC 9537) — see below.

#### What the caching actually does against live registries

Worth stating bluntly, because it was measured rather than assumed. A successful domain
lookup against the two gTLD registries this toolkit is most likely to be pointed at —
Verisign's `.com` service and PIR's `.org` service — arrives with **no cache validators at
all**: no `ETag`, no `Last-Modified`, and no `Cache-Control`, `Expires`, or `Age` either.

So:

- conditional revalidation is implemented and tested against fixtures that do carry
  validators, but against these registries it never fires, because there is nothing to put
  in `If-None-Match` or `If-Modified-Since`;
- what actually bounds staleness is the local TTL (`max_age_seconds`, default 24 hours)
  together with the stale-response fallback;
- `force_refresh` skips the cache and refetches. It deliberately does not use the RFC 7480
  Appendix B cache-busting trick — a random extra parameter aimed at intermediaries — since
  these registries advertise no shared caching and the toolkit's own requests pass through
  no proxy we control. Deployed behind a caching proxy, that omission starts to matter and
  the parameter is the documented remedy.

### Extension awareness

`normalize_rdap()` maps the common RDAP data structures onto the normalized
record instead of leaving them as raw JSON:

| Record field | Source | Meaning |
|---|---|---|
| `conformance`, `supports()`, `context["extensions"]` | RFC 9083 §4.1 | `rdapConformance` is read from the topmost object only; identifiers other than `rdap_level_0` are reported as extension tokens. |
| `lang` | RFC 9083 §4.4 | Nearest enclosing `lang` wins; notices, remarks, and links carry the language that applies to them. |
| `notices` | RFC 9083 §4.3 | Notices and remarks normalized to `title`, `type`, `description` (always a list), `links`, `lang`, plus `scope`/`context` provenance. |
| `links` | RFC 9083 §4.2 | Normalized `value`/`rel`/`href`/`type`/`media`/`title`/`hreflang`, with `complete` marking links that omit a mandatory member. |
| `truncated`, `truncation`, `incomplete` | RFC 9083 §9, §10.2.1 | A typed notice or remark carrying one of the registered truncation types marks the response, or a single object inside it, as partial. |
| `redacted` | RFC 9537 §4.2 | Redacted fields with registered or unregistered name, method, path, and reason. |
| `subsetting` | RFC 8982 §2.1 | `subsetting_metadata` from a `fieldSet` partial response, including the field sets a server offers. |
| `referrals()` | RFC 9083 §4.2 | `related` links safe to follow: complete, and not repeating a `self` href. |
| `context["http"]` | RFC 7480 §9.3 | Transport context: URL, status, `Content-Type`, `Content-Language`, and `Link` header targets. |

Deliberate limits, so the shape of the data is never guessed at:

- `lang` is taken from the response body only. RFC 7480 §9.3 tells servers to
  ignore `Accept-Language` so that clients do not confuse it with body language
  tags, therefore `Content-Language` is recorded as context and never applied to
  `record.lang`.
- Truncation is detected in the body. There is no `groupId`/`linksWithRel` in
  RFC 9083 and no `Notice: 11100` partial-response header in RFC 7480 or
  RFC 9082, so neither is implemented; a `Notice` response header is kept as
  opaque context.
- JSONPath expressions in `redacted` are preserved, not evaluated.
- `record.incomplete` covers truncation and redaction only. A field set says which
  view the server applied, not necessarily that data was withheld, so
  `record.subsetting` has to be read separately.
- `incomplete` is therefore not the right thing to warn on. Redaction is the ordinary state of a
  modern gTLD record, so the CLI keeps the two apart: every `redacted` member is itemized, and the
  warning is reserved for `truncated`/`truncation`. Live PIR data for `example.org` redacts the
  registry domain id and truncates nothing; warning on that made a correct lookup look broken.
- Where RFC 9083 specifies an array, a single value is read as one item rather than
  iterated character by character, and a `secureDNS` value that is not an object is
  kept as `{"raw": ...}` so that the normalized record still validates.
- `normalize_rdap()` is the only place that reads these members; `from_rdap()`
  is the same normalization without HTTP context.

Partial responses can be requested explicitly with the RFC 8982 `fieldSet`
parameter:

```python
result = rdap.lookup_rdap("example.com", field_set="brief")
print(result.error_details())  # RFC 9083 §6 error body, when the answer is negative
```

## Unified lookup

```python
from registrata.experimental import lookup

result = lookup("example.com", skip_reserved=False, sources=["rdap", "whois"])
```

Status:

- combines experimental RDAP/WHOIS;
- can also include RWhois if server/port are supplied;
- normalized model is still unstable;
- `result.provenance()` exposes source and referral hop metadata;
- `result.as_dict()` includes provenance and circuit breaker snapshots when a breaker registry is supplied;
- failures are counted per endpoint so an open breaker can stop hammering a failing source.

## Bulk lookups

```python
import threading

from registrata.circuitbreaker import CircuitBreakerRegistry
from registrata.experimental import batch_lookup
from registrata.ratelimit import RateLimiterRegistry

cancel = threading.Event()
limiter = RateLimiterRegistry(default_rate_per_second=1, default_capacity=2)
breaker = CircuitBreakerRegistry(default_failure_threshold=3, default_recovery_timeout=30)

with open("domains.txt", encoding="utf-8") as handle:
    result = batch_lookup(
        handle,
        concurrency=4,
        sources=["rdap", "whois"],
        limiter=limiter,
        breaker=breaker,
        aggregate_rate_per_second=2,
        aggregate_burst=1,
        deadline_seconds=300,
        stop_on_open_circuit=True,
        cancel_event=cancel,
        rdap_field_set="brief",
        on_result=lambda item: print(item.resource, item.status, flush=True),
    )

print(result.counts())
print(result.summary()["source_errors"])
```

CLI:

```powershell
uv run registrata bulk domains.txt --concurrency 4 --aggregate-rate 2 --json
uv run registrata bulk - --sources rdap,whois --jsonl --deadline 300
uv run registrata bulk domains.txt --fail-fast --stop-on-open-circuit --field-set brief --records --json
```

Status:

- `registrata.experimental.batch` provides `batch_lookup()`, `batch_lookup_async()`,
  `BatchItem`, `BatchResult`, `DEFAULT_CONCURRENCY = 4`, and `MAX_CONCURRENCY = 32`;
- concurrency is a bounded `ThreadPoolExecutor`: the requested worker count defaults to
  4 and is clamped to 1-32, because registries begin refusing service well before a
  wider pool helps;
- the RDAP/WHOIS/RWhois transports are blocking stdlib sockets, so this is thread-based
  concurrency and there is no event loop in the run. `batch_lookup_async()` is an
  `asyncio.to_thread` offload that lets an asyncio caller await a batch without
  stalling its loop; it is not event-loop-native RDAP/WHOIS transport;
- safety state is shared deliberately: pass one `RateLimiterRegistry`, one
  `CircuitBreakerRegistry`, and one cache and the whole batch gets one token bucket per
  endpoint and one circuit per authority rather than one set per call. Those classes
  are lock-protected;
- items are always returned in input order, and `len(result.items)` equals the number of
  resources after cleaning — entries are stripped, blank lines and lines starting with
  `#` are dropped, and duplicates are kept because asking for the same resource twice is
  a legitimate way to observe caching;
- when a cache directory is configured, workers share the on-disk RDAP bootstrap
  cache. `load_bootstrap()` takes a per-file lock, so a cold cache costs one download
  per process rather than one per worker, and the cache file is replaced by rename
  instead of being truncated in place, so a concurrent reader never sees a
  half-written document;
- `rdap_field_set` (CLI `--field-set`) requests an RFC 8982 `fieldSet` partial response,
  so a sweep can ask a registry for a smaller answer;
- nothing here changes the RFC 2167 core: the runner calls the same experimental
  `lookup()` surface, and the RWhois wire parsing, client, and server are untouched.

Two rate-limit layers, because they answer different questions:

| Layer | API | CLI | Behaviour |
|---|---|---|---|
| Per endpoint | `limiter=RateLimiterRegistry(...)` | `--rate-limit`, `--burst` | One token bucket per RDAP/WHOIS/RWhois endpoint, shared by all workers. |
| Global | `aggregate_rate_per_second`, `aggregate_burst` (default 1) | `--aggregate-rate`, `--aggregate-burst` | One bucket across all endpoints, taken before the per-endpoint bucket so the global ceiling binds. Registries limit the querying address as a whole, so a batch spread over many endpoints can flood them while every individual bucket still looks polite. |

The global bucket waits instead of dropping work; if the wait exceeds `--timeout`, that
resource is reported `skipped` with a `global rate limit: ...` reason.

Stopping is at dispatch level and never abrupt. Four mechanisms, all of which leave
work already in flight alone:

| Mechanism | CLI | Trips when | `stopped_reason` |
|---|---|---|---|
| `fail_fast` | `--fail-fast` | a lookup raises, or a resource answers with no source result at all | `fail_fast` |
| `stop_on_open_circuit` | `--stop-on-open-circuit` | a source error carries `kind="circuit_open"` — a registry that is refusing service will not change its mind over the next thousand resources | `circuit open` |
| `deadline_seconds` | `--deadline` | the dispatch loop passes the deadline | `deadline exceeded` |
| `cancel_event` | Ctrl-C | the caller sets the `threading.Event`, or the run is interrupted | `cancelled` |

Because in-flight lookups are allowed to finish, a run can overrun `--deadline` by up
to one lookup. `KeyboardInterrupt` ends the run and still returns everything that
completed. Resources that were never dispatched come back as `skipped` with a reason,
and `BatchResult.stopped_reason` records why the run stopped.

Status per resource:

| Status | Meaning |
|---|---|
| `ok` | a source answered and something was found, and no source reported an error |
| `partial` | a source answered with data and at least one source reported an error — typically one registry had data and another failed, and calling that a clean success would hide it |
| `empty` | a source answered that there is nothing to return — the lookup worked and found nothing |
| `reserved` | the name cannot be registered by anyone (RFC 6761 special use, e.g. `example.com`), so nothing was asked. Registries *do* answer these — with a plausible fixture object — which is why reporting one as `ok` is the thing to prevent; neither a miss nor a fault, and no quota spent |
| `blocked` | no source answered and a source reported an open circuit: the endpoint refused service, which is deliberately not reported as "no such object" |
| `error` | nothing was found because asking failed: `lookup()` raised, or every source reported an error. An endpoint nobody can reach reads as `error`, never as `empty` |
| `skipped` | never dispatched, because a stop condition or the global rate limit got there first |

The RWhois error codes are banded, and the bands decide which status a reply produces.
`%error 230 No objects found` is a healthy registry answering "not here", so it yields `empty` and
contributes nothing to `source_errors`; recording it as an error made every negative answer in a
sweep indistinguishable from an outage, and contradicted the circuit breaker, which has always
treated 230 as the endpoint working. Codes from 300 up are genuine failures of that lookup and are
reported as errors — but only codes from 400 up count against a circuit, because a rejected query
(350 bad syntax, 341 unknown class) is our mistake rather than the endpoint's illness, and tripping
a breaker over it would stop a client from ever succeeding again.

Special-use names are settled before any socket opens. `lookup()` consults the
IANA registry that RFC 6761 establishes — the `.example`, `.invalid`,
`.localhost`, `.test`, `.local`, `.onion` and `.alt` subtrees, plus the
`example.com` / `example.net` / `example.org` documentation domains — and records
the outcome on `LookupResult.unqueryable` with the document that says so.

This is not because registries refuse these names. They do not: the recorded
Verisign response in `tests/fixtures/live/` answers `example.com` with handle
`2336799_DOMAIN_COM-VRSN`, three statuses, two name servers and an expiry date,
and PIR does the same for `example.org`. That is precisely why the guard exists —
the answer is indistinguishable from a real finding, for a name no one can ever
register, so a sweep reports a documentation fixture as data. Only domain-shaped
resources are judged: a bare `test` is also an ordinary keyword query, and a
server may answer that. Pass `skip_reserved=False` (CLI: `--query-reserved`) to
ask anyway, which is right for two cases — a private RWhois tree that holds
objects under `example.com`, and `example.com` as the conventional smoke test
that a client and a registry are still talking. A lookup that names any endpoint
explicitly (`--rdap-base-url`, `--whois-server`, or RWhois, which has no
bootstrap) is asked regardless: only sources that would reach a public registry
are refused. The table lives in `registrata.special_names` with a reference per
row, because the registry takes new entries and a refresh should be a deliberate
edit.

Output:

- `result.as_dict()` returns `{"summary", "items"}`; `result.jsonl()` returns one JSON
  object per resource for streaming large runs to a file; `result.records()` returns
  every normalized record in input order;
- `result.summary()` reports `counts`, `source_errors` per source, `circuit_open_errors`,
  `duration_ms`, `concurrency`, `stopped_reason` when a stop fired, and the
  `circuit_breakers` snapshot when a breaker was passed;
- `on_result` is called from the calling thread as each resource settles, in completion
  order rather than input order, which is what makes streaming a long run to disk
  possible. An exception raised by the hook is logged as `batch_hook_error` and ignored
  so a broken sink cannot lose results;
- `LookupErrorItem.kind` is machine-readable (`"circuit_open"`, `"disabled"`,
  `"configuration"`, or `None`), which is what `stop_on_open_circuit` keys on instead of
  matching on message text.

CLI behaviour:

- per-resource lines by default, `--json` for a single `{summary, items}` document,
  `--jsonl` to stream one object per resource as it finishes, and `--records` combined
  with `--json` to replace the per-item entries with the concatenated normalized
  records;
- the one-line `bulk: total=... ok=... partial=...` summary and any
  `bulk: stopped early: <reason>` note go to stderr so stdout stays parseable;
- exit code is `1` when at least one resource ended `error` or `blocked`, `2` when the
  resource file does not exist or every resource failed with a `configuration` or
  `disabled` source error — a command that could not have answered anything, which
  must not be mistaken for an empty answer — and `0` otherwise. `reserved` resources
  never move the exit code: a name that cannot exist is not a broken pipeline, and
  a script sweeping a list should not halt on it. `--fail-fast` likewise does not
  stop for one. A run that stopped at
  `--deadline` is reported on stderr but is not treated as a failure: it is a normal
  cron budget.

## Comparison

```python
from registrata.comparison import compare_lookup_result
from registrata.experimental import lookup

report = compare_lookup_result(lookup("example.com", skip_reserved=False, sources=["rdap", "whois"]))
print(report.report["differences"])
```

CLI:

```powershell
uv run registrata compare example.com --query-reserved --sources rdap,whois --json
```

Status:

- compares normalized records from multiple sources;
- normalizes case, trailing dots, list order, common date spellings, emails, and phone digits;
- reports matches, differences, missing/empty fields, and a match score;
- says `comparable: false` with a `reason` (and `score: null`) when nothing was actually
  cross-checked -- one source, no sources, or a `--fields` list that named nothing recognised.
  A single source is what a lookup returns when the other failed, and it used to report
  `score: 1.0` with eight `match` lines, which is indistinguishable from a healthy agreement.
- a field that is empty in every source is listed as both a match (the sources do agree) and in
  `missing_or_empty` (neither source said anything), because agreement and absence are
  different facts.

## Stable schema output

```python
from registrata.record_schema import REGISTRATION_RECORD_SCHEMA, record_to_schema, validate_record

schema = REGISTRATION_RECORD_SCHEMA
wrapped = record_to_schema(record)
errors = validate_record(record.as_dict())
```

CLI:

```powershell
uv run registrata record-schema --json
uv run registrata record-schema example.com --query-reserved --sources rdap,whois --json
```

## Circuit breaker

```python
from registrata.circuitbreaker import CircuitBreakerRegistry
from registrata.experimental import lookup

registry = CircuitBreakerRegistry(default_failure_threshold=3, default_recovery_timeout=30)
result = lookup("example.com", skip_reserved=False, sources=["rdap", "whois"], breaker=registry)
print(result.provenance()["circuit_breakers"])
```

CLI:

```powershell
uv run registrata lookup example.com --query-reserved --json --provenance --circuit-failure-threshold 3 --circuit-recovery-timeout 30
uv run registrata gateway --port 8080 --circuit-failure-threshold 3 --circuit-recovery-timeout 30 --api-key local-dev-secret
```

The gateway `/health` endpoint includes breaker state snapshots and metrics when
metrics are enabled. The `/metrics` endpoint reports request counts, response
status counts, request-duration observations, unauthorized/rate-limited counters,
and breaker snapshots. When an API key is configured, `/metrics` and lookup
endpoints require `X-API-Key` or `Authorization: Bearer`; `/health` remains open.

Reserved names (RFC 6761 registry) are refused on the endpoints that build a
unified result — `/lookup`, `/domain`, `/ip`, `/asn` — unless the request passes
`query_reserved=1`, and the reason travels as `unqueryable` in both the full and
`records=1` shapes. `/whois` and `/rdap` are not gated: they call the
per-protocol clients directly, and choosing a protocol client is itself the
opt-in. Same split in Python — `lookup()` refuses, `whois.lookup_whois()` and
`rdap.lookup_rdap()` do not.

TLS is optional: pass `tls_certfile` and `tls_keyfile` (CLI `--tls-certfile` /
`--tls-keyfile`) as a pair to wrap the listener with a server-side
`ssl.SSLContext` pinned to TLS 1.2+. `GatewayConfig.tls_enabled` and
`GatewayConfig.scheme` reflect the choice, `/health` reports `"tls": true`, and
incomplete or missing key material is rejected by `GatewayConfig.validate()`
before the socket is bound.


## Trace and doctor

`registrata.diagnostics` provides structured operator reports:

```python
from registrata.diagnostics import doctor_report, trace_report
from registrata.experimental import lookup

result = lookup("example.com", skip_reserved=False, sources=["rdap", "whois"])
print(trace_report(result))
print(doctor_report("example.com", result=result, cache_dir=".cache"))
```

CLI:

```powershell
uv run registrata trace example.com --query-reserved --sources rdap,whois --json
uv run registrata doctor example.com --query-reserved --sources rdap,whois --json
uv run registrata doctor example.com --no-lookup --cache-dir .cache --json
```

Status:

- `trace` reports source status, hop metadata, errors, RDAP cache mode/validators, and circuit snapshots;
- `doctor` reports feature flags, classification, record validation, comparison, bootstrap cache state, breaker state, and suggested commands;
- `doctor --no-lookup` performs no network requests.


## Recorded against live registries

`tests/fixtures/live/` holds payloads captured from running registry services — PIR, Verisign and
IANA over WHOIS, Verisign and PIR over RDAP — every one of them a query for an RFC 2606 reserved
documentation domain, which is what those domains exist to be used for. `tests/test_live_fixtures.py`
replays them offline by default, and exercises the same resources against the live services as well
when `REGISTRATA_RUN_LIVE=1` is set.

This is the only part of the corpus that can say anything about the world rather than about this
codebase's reading of the specifications, and it paid for itself on first use: three defects came
out of the initial pass, described in the fixture README. The RWhois side remains entirely
spec-derived, for the blunt reason that there is no longer a public RWhois server to record from;
see `ROADMAP.md`.

