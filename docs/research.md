# Competitive research: WHOIS, RWhois, and RDAP tooling

This document tracks existing tools and the features we need to beat.

## Primary standards

| Standard | Role | Importance for this project |
|---|---|---|
| [RFC 2167 — RWhois V1.5](https://www.rfc-editor.org/info/rfc2167) | Referral Whois protocol | Core protocol correctness |
| [RFC 3912 — WHOIS Protocol Specification](https://www.rfc-editor.org/info/rfc3912) | Legacy port 43 WHOIS text protocol | Practical compatibility |
| [RFC 9082 — RDAP Query Format](https://www.rfc-editor.org/info/rfc9082) | RDAP query URL semantics | Modern compatibility |
| [RFC 9083 — RDAP JSON Responses](https://www.rfc-editor.org/info/rfc9083) | RDAP JSON object model | Structured normalized records |
| [RFC 9224 — Finding Authoritative RDAP Service](https://www.rfc-editor.org/info/rfc9224) | IANA bootstrap discovery | Modern automatic server discovery |

## Existing tool categories

### Classic command-line WHOIS tools

Examples: GNU Inetutils `whois`, BSD-style `whois`.

Strengths:

- fast operator ergonomics;
- server hints;
- TLD-specific behavior;
- referral support in some environments;
- RPSL and registry-specific options;
- non-standard server/port support.

Weaknesses:

- output is often raw text;
- parsing is fragile;
- behavior varies across operating systems;
- protocol correctness is hard to audit;
- little structured data;
- no modern unified model.

### Python WHOIS libraries

Examples: `whois`, `whoisdomain`, related forks.

Strengths:

- Pythonic convenience;
- domain-focused lookup;
- common field extraction;
- TLD support and autodetection;
- some caching and CLI support;
- newer versions may prefer RDAP first.

Weaknesses:

- often regex or text-scraping based;
- server quirks handled by patchwork;
- weak protocol layering;
- generally not good for building registries or custom servers;
- usually no first-class RWhois support;
- structured model is often a loose dictionary.

### IP/RIR tools

Examples: `ipwhois`.

Strengths:

- strong IPv4/IPv6 and ASN behavior;
- RIR referrals;
- RDAP support;
- NIR support;
- proxies;
- recursive network hierarchy.

Weaknesses:

- domain support may be intentionally limited;
- specialized focus;
- less general registration-data framework;
- limited protocol toolkit extensibility.

### RDAP tools and services

Examples: RDAP.org, ICANN RDAP tooling, registry and RIR RDAP servers.

Strengths:

- JSON responses;
- IANA bootstrap;
- HTTP-based security and access control;
- pagination/sorting;
- notices/links;
- extensions;
- machine-readable registration objects.

Weaknesses:

- not focused on RWhois or legacy structured directory servers;
- adoption is uneven;
- GDPR/redaction changes availability;
- clients can abuse bootstrap/aggregator endpoints if poorly designed.

## Where `registrata` can win

### 1. Correct protocol implementation

Existing tools often parse raw text. We should implement and test protocol grammar directly.

Targets:

- RFC 2167 ABNF;
- RFC 3912 raw behavior;
- RDAP JSON structures;
- capability flags and error code semantics;
- referral and SOA semantics.

### 2. Strong typed model

A stable normalized model can outperform loose dictionaries:

```text
RegistrationRecord
  kind
  identifier
  status
  events
  contacts
  nameservers
  networks
  registrar
  dnssec
  refs
  raw
```

This makes the library useful for applications instead of just terminal users.

### 3. Unified multi-source lookup

A high-quality library should answer:

```python
lookup("example.com", sources=["rdap", "whois", "rwhois"])
```

Existing tools usually choose one source or hack around compatibility.

### 4. Server toolkit

Most WHOIS tools are client-only. A server toolkit is a differentiator:

- custom RWhois authority areas;
- schema validation;
- registration hooks;
- replication helpers;
- conformance tests;
- compliance reports.

### 5. Operator-friendly diagnostics

Good commands should help users understand why a lookup failed:

- `trace`
- `profile`
- `doctor`
- `check-server`
- `compare`

These do not need to exist in every tool today, but they would be very valuable.

## Feature comparison matrix

| Capability | GNU/BSD whois | Python whois libs | ipwhois | ICANN RDAP tools | `registrata` target |
|---|---:|---:|---:|---:|---:|
| Raw WHOIS client | yes | yes | yes | usually no | yes |
| Structured RWhois | rare | no | partial referral only | no | yes, core |
| RDAP | rare | some | yes | yes | yes |
| IANA RDAP bootstrap | rare | some | some | yes | yes |
| Typed records | no | partial | partial | JSON model | strong typed model |
| RWhois server toolkit | no | no | no | no | yes |
| Schema validation | no | no | no | some | yes |
| Fuzz/conformance tests | rare | rare | rare | good | strong |
| CLI ergonomics | strong | strong | strong | strong | strong |
| Rate limiting/caching | rare | partial | partial | yes | yes |
| Comparison/diff tools | no | no | no | partial | yes |
| Gateway/bridge mode | no | no | no | no | maybe later |

## Special-use domain names (checked against IANA, 2026-11-02)

`classify_resource` should recognise these before spending registry quota. The
authoritative list is the IANA "Special-Use Domain Names" registry that RFC 6761
establishes, not RFC 2606 alone: RFC 6761 describes the procedure and seeds the
registry, so the registry is the thing that changes over time.

Non-`.arpa` entries today:

| Name | Reference |
| --- | --- |
| `alt.` | RFC 9476 |
| `example.` | RFC 6761 |
| `example.com.` / `example.net.` / `example.org.` | RFC 6761 |
| `invalid.` | RFC 6761 |
| `local.` | RFC 6762 |
| `localhost.` | RFC 6761 |
| `onion.` | RFC 7686 |
| `test.` | RFC 6761 |

The remaining rows (about 35) are `.arpa` zones: reverse-mapping zones such as
`10.in-addr.arpa.` and `254.169.in-addr.arpa.`, plus special zones like
`home.arpa.` and `eap.arpa.`. Those matter only if IP lookups are added.

This corrects two earlier assumptions. First, RFC 2606 is not the whole
boundary: it reserves the three `example.*` second-level names and the
`invalid`/`test` TLDs, while `example.`, `localhost.`, `local.` and `onion.`
come from other documents. Second, the list is registry-maintained, so it should
travel with its references and be refreshable rather than hard-coded as eternal.

Consequence for the bulk status vocabulary: an unqueryable name is neither `ok`
nor `empty`. It needs its own outcome, so a bulk report never reads "no data"
for a name no registry can serve.

## Research backlog

Need deeper analysis of:

- registry-specific WHOIS field formats;
- RWhois server deployments today;
- RDAP profile conformance across registries;
- rate-limit policies;
- GDPR/redaction patterns;
- DNSSEC/status vocabulary differences;
- IANA bootstrap update cadence;
- real-world malformed server responses.
