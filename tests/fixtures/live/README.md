# Live registry recordings

Payloads captured from **real registry services**, not hand-written from the specifications.
Every other fixture in this repository is derived from RFC text, which means it can only ever
confirm that the implementation agrees with itself. These five confirm it agrees with servers
that are actually running.

Captured 2026-11-05 (UTC) with the toolkit's own client code against RFC 2606 reserved
documentation domains. They are reserved, and the registries answer them anyway, in full —
which is what makes them useful here and awkward in a sweep (see
*A claim these recordings killed* below).

| File | Endpoint | Protocol | Query |
|---|---|---|---|
| `whois_example_org_pir.txt` | `whois.pir.org:43` | WHOIS | `example.org` |
| `whois_example_com_verisign.txt` | `whois.verisign-grs.com:43` | WHOIS | `example.com` |
| `whois_org_iana.txt` | `whois.iana.org:43` | WHOIS | `ORG` (TLD record) |
| `rdap_example_com_verisign.json` | `https://rdap.verisign.com/com/v1/` | RDAP | `domain/example.com` |
| `rdap_example_org_pir.json` | `https://rdap.publicinterestregistry.org/rdap/` | RDAP | `domain/example.org` |

## What they caught

Three defects that no amount of spec-derived fixture work had surfaced:

1. **Prose fields.** Registrars print sentences containing URLs, and splitting on the first colon
   turned `For more information on Whois status codes, please visit https://icann.org/epp` into a
   field named `for more information on whois status codes, please visit https` holding
   `//icann.org/epp`. All three WHOIS payloads contain such a line.
2. **Redaction read as truncation.** PIR's RDAP response redacts the registry domain id
   (`redacted`, RFC 9537) and is not truncated at all, yet the CLI warned that the response was
   incomplete — for the ordinary case, on every lookup.
3. **No hop provenance.** Following referrals is on by default, and Verisign's reserved-domain
   record names `whois.iana.org` as the registrar service. IANA answers about the TLD, so a query
   for `example.com` ended with a record whose identifier is `Internet Assigned Numbers Authority`
   and nothing in the output said a hop had happened.

## A claim these recordings killed

The reserved-name guard was first justified as "don't ask a registry that can only
answer `no such object`". These files disprove that: Verisign answers `example.com`
with handle `2336799_DOMAIN_COM-VRSN`, three statuses, two name servers, a 1995
creation date and a 2027 expiry. PIR does the same for `example.org`.

The reason to skip reserved names is therefore the opposite, and stronger: the
answer is *complete and plausible*, for a name nobody can ever register. Reported
as `ok` with data, it is a fixture wearing the costume of a finding — which is
worse in a sweep than getting nothing at all.

## Re-recording

Reserved names are refused before a public registry is asked, so a re-record has to
say it means it. An explicitly named server (`--whois-server`, `--rdap-base-url`) is
asked regardless; `registrata rdap example.org` with no base URL is not.

```
registrata whois example.org --whois-server whois.pir.org
registrata whois example.com --whois-server whois.verisign-grs.com
registrata whois OR --whois-server whois.iana.org
registrata rdap example.com --rdap-base-url https://rdap.verisign.com/com/v1
registrata rdap example.org --query-reserved
```

## Writing assertions against these

Registries change dates, name servers, terms-of-use wording and status codes at any time, and a
test that fails because of that is testing nothing. Assert **structure** — which fields were found,
which fields must not have been invented, which members the normalizer produced — and leave the
values alone. Where a value is load-bearing for a defect (`REDACTED`, `$.handle`) it is part of
what the registry promises, and the test says so.
