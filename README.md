# registrata

`registrata` is a Python registration-data toolkit: first-class Referral Whois (RWhois)
with experimental classic WHOIS and RDAP compatibility, behind one structured lookup model.

It imports as `registrata`:

```python
import registrata
```

> **Renamed from `pyrwhois`.** The project used to be published as `pyrwhois` and imported
> as `rwhois`. It is now `registrata`, because it covers registration data across three
> protocols (RWhois, classic WHOIS, RDAP) rather than RWhois alone, and because `rda`/`rdap`
> style names were already taken or misleading ([`rdapy` on PyPI is redistricting
> analytics](https://pypi.org/project/rdapy/)). Install with `pip install registrata`.
> Compatibility seams for the old identity:
>
> - `import rwhois` still works, re-exports `registrata`, and emits `DeprecationWarning`;
> - the `rwhois` console script remains as an alias for `registrata`;
> - SQLite cache files written with the old `pyrwhois_cache` table are renamed in place;
> - log records that nest their payload under the legacy `pyrwhois` key are still formatted.
>
> Protocol-level names are unchanged on purpose: `--rwhois-server`/`--rwhois-port` flags,
> the `sources=["rwhois"]` lookup key, `rwhois://` referral URLs, and the `Rwhois*` classes.

The project is built from the [RFC 2167 RWhois protocol](https://www.rfc-editor.org/info/rfc2167), with a roadmap toward classic WHOIS ([RFC 3912](https://www.rfc-editor.org/info/rfc3912)) and RDAP ([RFC 9082](https://www.rfc-editor.org/info/rfc9082), [RFC 9083](https://www.rfc-editor.org/info/rfc9083), [RFC 9224](https://www.rfc-editor.org/info/rfc9224)) compatibility.

The long-term goal is not merely historical protocol support. It is to become a better registration-data toolkit than common WHOIS clients by offering:

- protocol-correct RWhois parsing and server tooling;
- structured normalized results;
- referral-aware discovery;
- modern WHOIS/RDAP compatibility;
- safe caching, rate limiting, and bulk behavior;
- server conformance reports and diagnostics.

## Project maturity

| Area | Status | Notes |
|---|---|---|
| RWhois wire parsing | Implemented | Banners, capability IDs, responses, referrals, errors. |
| RWhois TCP client | Implemented | Directives, queries, status, SOA, schema, register (`add`/`mod`/`del`) and password security. |
| RWhois TCP server | Partial | Threaded toolkit and memory backend, including `-register` with schema validation and per-fault Appendix C error codes; `-forward`, `-xfer` and notification policy remain partial. |
| Resolver | Partial | Follows referrals and dedupes same auth-area referrals. |
| Schema/SOA | Partial | Helpers and parsing exist; validation needs hardening. |
| Classic WHOIS | Experimental | Raw client, field extractor, registry adapters, referral following, response caching hooks. |
| RDAP | Experimental | Bootstrap TTL/conditional cache, query response TTL cache with ETag/Last-Modified revalidation and stale fallback, extension-aware normalization of notices/remarks, links, `rdapConformance`, `lang`, truncation, `redacted`, and `subsetting_metadata`, `fieldSet` partial responses, RFC 9083 error bodies, retry/limiter hooks. |
| Unified lookup | Experimental | `registrata.experimental.lookup()` can combine RDAP/WHOIS/RWhois, return normalized `RegistrationRecord` items, expose provenance, compare records, validate against a stable schema, track per-endpoint circuit state, and refuse RFC 2606/6761 special-use names before asking a public registry that could only answer "no such object". |
| Normalized model | Partial | Shared `registrata.model.RegistrationRecord` for RDAP, WHOIS, and RWhois data, plus stable schema metadata (version `0.2`) in `registrata.record_schema`. |
| Caching/rate limiting | Partial experimental implemented | TTL caches for bootstrap and responses, memory/file/SQLite cache backends, per-server token bucket, retry/backoff, and per-endpoint circuit breaker. |
| Reliability hardening | Partial | Protocol response-size limits, line-length limits, per-line and per-attempt read deadlines in the raw-socket clients against slow-drip peers (RDAP's HTTP read is bounded per syscall only), oversized HTTP/WHOIS response rejection, malformed-byte decoding tests, cache serialization tests, stale bootstrap fallback, and circuit-breaker integration; plus an RFC 2167 transcript corpus (45 cases) pinning parser structure, round-trips, and the hostile-input exception contract. |
| Observability | Partial | Structured logging helpers, JSON log formatter, cache/referral/retry diagnostics, CLI `--log-level` and `--log-json`. |
| Server conformance checker | Basic implemented | `registrata check-server` probes banner, advertised directives, classes, and a query response, and separates `skip` (capability not advertised, or an optional directive the server lawfully declines per RFC 2167 §3.3) from `fail`. |
| Gateway/bridge mode | Basic experimental implemented | Local HTTP endpoints for `/lookup`, `/domain`, `/ip`, `/asn`, `/whois`, `/rdap`, `/rwhois`, `/health`, and `/metrics`. Disabled by default, localhost-only unless explicitly allowed, optional API-key auth, optional TLS/HTTPS, metrics, cache, rate limits, and circuit breakers. |
| Bulk lookups | Done for experimental | `registrata.experimental.batch.batch_lookup()` and the `registrata bulk` command run the unified lookup over a file (or stdin) of resources with bounded thread-pool concurrency (default 4, ceiling `MAX_CONCURRENCY = 32`), a limiter, circuit breaker, and cache shared across the run, an optional global rate limit, and dispatch-level fail-fast / stop-on-open-circuit / deadline / cancel stop conditions. Concurrency is threads over blocking sockets, not event-loop I/O. |

See `ROADMAP.md`, `docs/roadmap.md`, `docs/research.md`, and `docs/compliance.md`.

## Install for development

```powershell
cd D:\code\pyrwhois
uv sync --group dev --all-extras
uv run pytest -q
uv run ruff check src tests
```

The lint rules are pinned in `pyproject.toml` (`[tool.ruff.lint]`), so the gate does
not drift with whatever ruff version happens to be installed globally.

`tests/test_docs_cli.py` reads the documentation and asserts that every `registrata`
command it shows parses against the real argument parser, and that every
`registrata.*` name the usage docs cite can be imported. Renaming a flag or a helper
without updating the prose fails the suite.

Most of the corpus is derived from RFC text, which can only ever show that the
implementation agrees with itself. `tests/fixtures/live/` is the exception: payloads
recorded from the running PIR, Verisign and IANA services, replayed offline by
`tests/test_live_fixtures.py`. Set `REGISTRATA_RUN_LIVE=1` to additionally run those
resources against the live registries.

## CLI

```powershell
uv run registrata query rs.example.com example.com --class domain
uv run registrata resolve example.com --root rs.example.com --class domain
uv run registrata schema rs.example.com example.com
uv run registrata soa rs.example.com example.com
uv run registrata status rs.example.com
uv run registrata banner rs.example.com
uv run registrata check-server rs.example.com 4321 --json

uv run registrata whois example.com --query-reserved --json
uv run registrata domain example.com --query-reserved --json --records-only
uv run registrata ip 8.8.8.8 --json --records-only
uv run registrata asn AS15169 --json --records-only
uv run registrata rdap example.com --query-reserved --json --record-only

uv run registrata lookup example.com --query-reserved --sources rdap,whois --json
uv run registrata lookup example.com --query-reserved --json --provenance
uv run registrata lookup example.com --query-reserved --rate-limit 1 --burst 2 --retries 2 --backoff-delay 0.5 --jitter --circuit-failure-threshold 3 --circuit-recovery-timeout 30
uv run registrata lookup example.com --query-reserved --sources rdap,whois --follow-referrals --cache-ttl 3600 --cache-backend file --cache-dir .cache --json
uv run registrata rdap example.com --query-reserved --cache-ttl 3600 --rdap-revalidation-ttl 604800 --cache-dir .cache --json
uv run registrata lookup example.com --query-reserved --sources rdap --cache-ttl 3600 --no-rdap-conditional --json
uv run registrata compare example.com --query-reserved --sources rdap,whois --fields identifier,statuses,nameservers --json
uv run registrata trace example.com --query-reserved --sources rdap,whois --json
uv run registrata doctor example.com --query-reserved --sources rdap,whois --json
uv run registrata doctor example.com --no-lookup --cache-dir .cache --json
uv run registrata bulk domains.txt --concurrency 4 --aggregate-rate 2 --deadline 300 --json
uv run registrata record-schema --json
uv run registrata serve --memory --auth-area example.com --port 0
```

JSON output:

```powershell
uv run registrata query rs.example.com example.com --class domain --json
```

## RWhois client example

```python
from registrata import RwhoisClient

with RwhoisClient.connect("rs.example.com", 4321) as client:
    result = client.query("domain", "example.com")

    for obj in result.objects:
        print(obj.class_name, obj.get("ID"), obj.get("Auth-Area"))

    for referral in result.referrals:
        print(referral.host, referral.port, referral.auth_area)
```

## Experimental unified lookup

Experimental features are importable from `registrata.experimental`.

```python
from registrata.experimental import lookup

result = lookup("example.com", skip_reserved=False, sources=["rdap", "whois"])
print(result.kind)
print(result.records)
print(result.normalized)
print(result.errors)
```

For RWhois:

```python
from registrata.experimental import lookup

result = lookup(
    "example.com",
    sources=["rwhois"],
    server="rs.example.com",
    port=4321,
    rwhois_class="domain",
)
print(result.results["rwhois"].objects)
```

## Unified provenance, comparison, and schema output

`lookup()` includes source provenance in its structured output:

```python
from registrata.experimental import lookup

result = lookup("example.com", skip_reserved=False, sources=["rdap", "whois"])
print(result.provenance())
```

CLI:

```powershell
uv run registrata lookup example.com --query-reserved --json --provenance
```

Compare normalized records across sources:

```python
from registrata.comparison import compare_lookup_result
from registrata.experimental import lookup

report = compare_lookup_result(lookup("example.com", skip_reserved=False, sources=["rdap", "whois"]))
print(report.as_dict())
```

CLI:

```powershell
uv run registrata compare example.com --query-reserved --sources rdap,whois --fields identifier,statuses,nameservers,contacts --json
```

The comparison normalizes case, trailing dots, status/name-server order,
common event date spellings, contact emails, and phone digits. It reports
matching fields, differing fields, fields that are empty or missing in one
source, and a simple match score.

Stable schema metadata:

```python
from registrata.record_schema import REGISTRATION_RECORD_SCHEMA, record_to_schema, validate_record

print(REGISTRATION_RECORD_SCHEMA)
errors = validate_record(result.records[0].as_dict())
```

CLI:

```powershell
uv run registrata record-schema --json
uv run registrata record-schema example.com --query-reserved --sources rdap,whois --json
```

## RDAP extension awareness

RDAP responses carry service and policy information in structures that a minimal
normalizer tends to drop. `registrata` keeps them, normalizes them, and labels
which object each one came from:

```python
from registrata.experimental import rdap

result = rdap.lookup_rdap("example.com")
record = rdap.normalize_rdap(result.data, headers=result.headers, url=result.url, status=result.status)

print(record.conformance)                 # rdapConformance, topmost object only (RFC 9083 §4.1)
print(record.supports("redacted"))        # is this response using the RFC 9537 extension?
print(record.lang)                        # nearest enclosing lang tag (RFC 9083 §4.4)
print(record.truncated, record.truncation)  # partial data, from typed notices/remarks (RFC 9083 §9)
print(record.redacted)                    # withheld fields with method and reason (RFC 9537)
print(record.subsetting)                  # field sets offered by the server (RFC 8982)
print(record.referrals())                 # related links safe to follow (RFC 9083 §4.2)
print(result.error_details())             # errorCode/title/description of a negative answer (RFC 9083 §6)
```

Language comes from the response body, never from `Content-Language`: RFC 7480
§9.3 tells servers to ignore `Accept-Language` precisely so that clients do not
conflate it with body language tags, so the header is kept as transport context
only. Truncation is likewise read from the body: `groupId`/`linksWithRel` are not
defined in RFC 9083 and no `Notice: 11100` partial-response header exists in
RFC 7480 or RFC 9082, so neither is implemented here.

CLI:

```powershell
uv run registrata rdap example.com --query-reserved --json
uv run registrata rdap example.com --query-reserved --field-set brief --json
uv run registrata doctor example.com --query-reserved --sources rdap
```

`doctor` flags a record whose response says it is incomplete, and `rdap` prints
the notices, redacted fields, and offered field sets that explain why.

## Resource-specific CLI commands

The CLI exposes resource-oriented wrappers around the experimental lookup and protocol clients:

```powershell
uv run registrata whois example.com --query-reserved --json
uv run registrata domain example.com --query-reserved --json --records-only
uv run registrata ip 8.8.8.8 --json --records-only
uv run registrata asn AS15169 --json --records-only
uv run registrata rdap example.com --query-reserved --json --record-only
```

Default behavior:

- `domain` uses `rdap,whois`;
- `ip` defaults to `rdap` because classic WHOIS often needs an explicit registry server;
- `asn` defaults to `rdap`;
- `whois` follows referral hints by default unless `--no-referrals` is supplied;
- `rdap` resolves through IANA bootstrap files unless `--rdap-base-url` is supplied.

## Bulk lookups

`registrata bulk` runs the unified lookup over many resources listed one per line
in a file, or piped in as `-`. Lines are stripped, blank lines and lines starting
with `#` are skipped, and duplicates are kept on purpose because asking for the
same resource twice is how you watch the cache.

Read a file and print one `{summary, items}` document:

```powershell
uv run registrata bulk domains.txt --sources rdap,whois --concurrency 4 --aggregate-rate 2 --json
```

Pipe resources from stdin and stream one JSON object per resource as it finishes:

```powershell
Get-Content domains.txt | uv run registrata bulk - --sources rdap,whois --jsonl
```

The Python API is the same runner, and passing one limiter and one breaker is the
point: every worker shares them, so the run gets one token bucket per endpoint and
one circuit per authority rather than one set per call.

```python
from registrata.circuitbreaker import CircuitBreakerRegistry
from registrata.experimental import batch_lookup
from registrata.ratelimit import RateLimiterRegistry

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
        deadline_seconds=300,
        stop_on_open_circuit=True,
        on_result=lambda item: print(item.resource, item.status, flush=True),
    )

print(result.counts())
print(result.summary()["source_errors"])
```

Items always come back in input order, one per resource, and each is reported as
`ok`, `partial`, `empty`, `blocked`, `error`, or `skipped`; see
`docs/experimental.md` for what each one means.

A batch sends real traffic to registries, so the politeness knobs matter:

- `--concurrency` defaults to 4 and is clamped to 1-32. Registries start refusing
  service long before 32 workers make a job finish 32 times faster;
- `--rate-limit`/`--burst` stay per endpoint, while `--aggregate-rate`/`--aggregate-burst`
  add a global bucket across every endpoint, because registries limit the querying
  address as a whole and a batch spread over many endpoints can flood them while each
  individual bucket still looks polite. The global bucket waits rather than dropping
  work;
- `--fail-fast`, `--stop-on-open-circuit`, `--deadline`, and a `cancel_event` stop
  *dispatching* new work instead of cutting running lookups off, so the wall clock can
  overrun `--deadline` by up to one lookup and whatever never started comes back
  `skipped`. Ctrl-C likewise ends the run and still returns what completed.

The one-line `bulk: total=... ok=... partial=...` summary and any
`bulk: stopped early: <reason>` note go to stderr, so stdout stays parseable. Exit
code is `1` when at least one resource ended `error` or `blocked`, and `2` when the
resource file does not exist or the command could not have answered anything — for
example `--sources rwhois` with no `--rwhois-server`, which would otherwise look like
an empty reply from the registries. Stopping at `--deadline` is reported but is not a
failure, because it is a normal cron budget.

Limits worth knowing: concurrency is a thread pool over blocking sockets, and
`batch_lookup_async()` is an `asyncio.to_thread` offload rather than event-loop-native
RDAP/WHOIS I/O. There is no queue, scheduler, or cross-process distribution, and
`MAX_CONCURRENCY = 32` is the ceiling inside one process. With a `--cache-dir`,
workers share the on-disk RDAP bootstrap cache: `load_bootstrap()` holds a per-file
lock, so a cold cache costs one download for the whole run rather than one per
worker, and it replaces the cache file by rename so a reader never sees a
half-written document.

## RDAP conditional caching

RDAP query responses can be revalidated with HTTP validators when a response cache
is enabled.

If an RDAP response includes:

```text
ETag
Last-Modified
```

`registrata` stores those validators with the cached response. After the fresh TTL
expires, it sends:

```text
If-None-Match
If-Modified-Since
```

If the server returns `304 Not Modified`, the cached response is reused without
re-downloading the full JSON body.

If revalidation fails with a transient transport/server error, the cached response
is returned as stale data when available. `RdapResult.cache_mode` reports the
cache path:

```text
hit
miss
revalidated
revalidated_fresh
stale
```

CLI:

```powershell
uv run registrata rdap example.com --query-reserved --cache-ttl 3600 --rdap-revalidation-ttl 604800 --cache-dir .cache --json
```

Disable conditional revalidation:

```powershell
uv run registrata lookup example.com --query-reserved --sources rdap --cache-ttl 3600 --no-rdap-conditional --json
```

Gateway:

```text
GET /rdap?resource=example.com&cache_ttl=3600&conditional=0
GET /rdap?resource=example.com&cache_ttl=3600&rdap_revalidation_ttl=604800
GET /rdap?resource=example.com&field_set=brief
```

`field_set` asks the server for an RFC 8982 partial response. Caching is keyed on
the request URL, so different field sets never share a cache entry, and the
`subsetting_metadata` the server returns is reported in `normalized.subsetting`.
A negative answer is decoded once and surfaced as `rdap_error`
(`errorCode`, `title`, `description`) instead of leaving clients to read the raw
RFC 9083 error body out of `data`.

## Operator trace and doctor commands

`trace` shows which sources were used, what servers were contacted, what referrals
were followed, and what cache/circuit state affected the lookup:

```powershell
uv run registrata trace example.com --query-reserved --sources rdap,whois --json
```

`doctor` runs a broader diagnostic bundle:

- feature flags;
- resource classification;
- source health;
- normalized record validation;
- cross-source comparison;
- RDAP bootstrap cache age and validator availability;
- circuit breaker state;
- suggested next commands.

```powershell
uv run registrata doctor example.com --query-reserved --sources rdap,whois --json
uv run registrata doctor example.com --no-lookup --cache-dir .cache --json
```

`doctor --no-lookup` is useful for local configuration checks without contacting
registration-data servers.

## Experimental gateway mode

Run a local HTTP gateway:

```powershell
uv run registrata gateway --port 8080 --api-key local-dev-secret --cache-ttl 3600 --rate-limit 2 --burst 4 --circuit-failure-threshold 3 --circuit-recovery-timeout 30
```

You can also use `REGISTRATA_GATEWAY_API_KEY` instead of putting the secret on the
command line (the pre-rename `RWHOIS_GATEWAY_API_KEY` is still read when the new
variable is unset).

The gateway is disabled by default unless the CLI command enables it, and it refuses
non-localhost binds unless `--allow-remote` is explicitly supplied.

### TLS

Serve HTTPS by passing a certificate and private key as a pair:

```powershell
uv run registrata gateway --port 8443 --tls-certfile .\certs\gateway.pem --tls-keyfile .\certs\gateway-key.pem --allow-remote
```

- Both flags are required together; supplying only one is a configuration error (exit code 2).
- Missing files are reported at startup instead of failing on the first handshake.
- The listener is pinned to TLS 1.2 or newer and the startup line prints `https://`.
- Certificates are never generated for you; use any CA-issued pair, or for local
  testing `openssl req -x509 -newkey rsa:2048 -days 1 -nodes -keyout key.pem -out cert.pem -subj /CN=localhost`.

Available endpoints:

```text
GET /health
GET /metrics
GET /lookup?resource=example.com&query_reserved=1
GET /lookup?resource=example.com&query_reserved=1&records=1
GET /domain?resource=example.com&query_reserved=1&records=1
GET /ip?resource=8.8.8.8&records=1
GET /asn?resource=AS15169&records=1
GET /whois?resource=example.com
GET /rdap?resource=example.com
GET /rwhois?resource=example.com&server=127.0.0.1&port=4321&class=domain
```

If `--api-key` or `REGISTRATA_GATEWAY_API_KEY` is set, all endpoints except `/health`
require one of:

```text
X-API-Key: <secret>
Authorization: Bearer <secret>
```

Python API:

```python
from registrata.experimental.gateway import GatewayConfig, GatewayServer

server = GatewayServer(
    GatewayConfig(
        bind="127.0.0.1",
        port=0,
        api_key="local-dev-secret",
        metrics_enabled=True,
        tls_certfile="certs/gateway.pem",  # optional: setting both enables HTTPS
        tls_keyfile="certs/gateway-key.pem",
    )
)
host, port = server.start()
try:
    print(f"listening on {server.config.scheme}://{host}:{port}")
finally:
    server.shutdown()
```

Gateway mode is intended for local operator workflows and testing rather than as a
public multi-tenant service. `/health` reports `"tls": true|false` and stays
unauthenticated so monitoring probes keep working with or without TLS.

`/rdap` mirrors the RDAP server's answer instead of always reporting success: a
negative answer comes back with the upstream HTTP status (for example 404) and a
decoded `rdap_error` member holding the RFC 9083 section 6 `errorCode`, `title`,
and `description`, while `normalized` carries the extension fields described in
`docs/experimental.md`.

## Experimental safety helpers

```python
from registrata.circuitbreaker import CircuitBreakerRegistry
from registrata.experimental import lookup
from registrata.cache import TTLCache
from registrata.ratelimit import RateLimiterRegistry
from registrata.retry import Backoff

cache = TTLCache(default_ttl=3600, max_size=256)
limiter = RateLimiterRegistry(default_rate_per_second=1, default_capacity=2)
breaker = CircuitBreakerRegistry(default_failure_threshold=3, default_recovery_timeout=30)
result = lookup(
    "example.com",
    sources=["rdap", "whois"],
    limiter=limiter,
    breaker=breaker,
    retries=2,
    backoff=Backoff(base_delay=0.5, jitter=True),
    cache=cache,
    cache_ttl=3600,
    follow_referrals=True,
)
```

File and SQLite caches are also available:

```python
from registrata.cache import JsonFileCache, SQLiteCache

file_cache = JsonFileCache(".cache", namespace="responses", default_ttl=3600)
sqlite_cache = SQLiteCache(".cache/registrata_cache.sqlite3", namespace="responses", default_ttl=3600)
```

## Server conformance checker

```python
from registrata.conformance import check_server

report = check_server("rs.example.com", 4321, query_class="domain", query_text="example.com")
print(report.score)
for item in report.items:
    print(item.status, item.name, item.detail)
```

## Response safety limits

Malformed or malicious registration-data servers can return unbounded responses.
`registrata` now applies conservative default limits:

- RWhois wire reader rejects excessively long single lines by default (`1 MiB`);
- `RwhoisClient` limits response lines (`100,000`) and total response bytes (`16 MiB`);
- RDAP HTTP responses default to a `4 MiB` cap;
- classic WHOIS responses default to a `4 MiB` cap.

CLI override:

```powershell
uv run registrata rdap example.com --query-reserved --max-bytes 1048576 --json
uv run registrata whois example.com --query-reserved --max-bytes 1048576 --json
uv run registrata domain example.com --query-reserved --max-bytes 1048576 --json --records-only
```

These limits are defensive defaults for public-network use; they are not a full
sandbox, and bulk scanning still requires explicit policy.

## Structured logging and diagnostics

Library diagnostics are emitted through Python's standard `logging` package and
are quiet by default.

CLI diagnostics can be enabled with:

```powershell
uv run registrata --log-level info domain example.com --json
uv run registrata --log-level debug --log-json rdap example.com --json
uv run registrata --log-level debug --log-json whois example.com --json
```

Useful JSON events include:

- `rdap_http_get`
- `rdap_retry`
- `rdap_cache_hit`
- `rdap_cache_miss`
- `rdap_cache_expired`
- `rdap_cache_store`
- `rdap_conditional_hit`
- `rdap_stale_cache`
- `whois_query`
- `whois_retry`
- `whois_referral_follow`
- `whois_cache_hit`
- `whois_cache_miss`
- `whois_cache_store`

Python API:

```python
import logging

from registrata.observability import configure_logging, get_logger, log_event

configure_logging("info", json=True)
logger = get_logger("myapp")
log_event(logger, logging.INFO, "lookup_finished", resource="example.com", source="rdap")
```

## Experimental feature flags

Environment variables:

```powershell
$env:REGISTRATA_ENABLE_EXPERIMENTAL = "1"
$env:REGISTRATA_ENABLE_EXPERIMENTAL_WHOIS = "1"
$env:REGISTRATA_ENABLE_EXPERIMENTAL_RDAP = "1"
$env:REGISTRATA_ENABLE_EXPERIMENTAL_GATEWAY = "0"
$env:REGISTRATA_GATEWAY_API_KEY = "local-dev-secret"
```

The pre-rename `RWHOIS_*` spellings of all five variables are still read; a
`REGISTRATA_*` value wins when both are set.

Default flags:

| Feature | Default |
|---|---|
| `whois` | enabled |
| `rdap` | enabled |
| `gateway` | disabled |

## Current intentional limitations

- RFC 2167 is Informational, but it is the latest RWhois protocol document. RFC 1714 is obsolete.
- TCP is the primary transport. RFC 2167 mentions UDP but defers details, so UDP is not implemented.
- PGP security is intentionally not implemented.
- RDAP and classic WHOIS support are experimental and should be treated as unstable API surface.
- Gateway mode is local-experimental only: optional API-key auth, optional TLS, and metrics are implemented, but richer authorization policies (roles, OAuth, per-client quotas) are not.
- Per-server rate limiting, retry/backoff, TTL caching, RDAP bootstrap and query-response conditional/stale caching, per-endpoint circuit breaking, WHOIS referral following, structured logging, and response-size limits are implemented, but proxy support, malicious-server fuzz corpora, and production bulk policy remain incomplete.
