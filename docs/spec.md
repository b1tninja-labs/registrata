# RWhois specification notes

This package is implemented against [RFC 2167, Referral Whois (RWhois) Protocol V1.5](https://www.rfc-editor.org/info/rfc2167). RFC 1714 is obsolete and is included here only as historical context.

## Primary sources used

- RFC 2167 §2.5 and §2.5.1: query routing, link referrals, punt referrals.
- RFC 2167 §3.1: directive, response, query, result, info, and banner semantics.
- RFC 2167 §3.2: required `-rwhois` directive.
- RFC 2167 §3.3: optional directives including `-class`, `-directive`, `-display`, `-forward`, `-holdconnect`, `-limit`, `-notify`, `-quit`, `-register`, `-schema`, `-security`, `-soa`, `-status`, `-xfer`, and `-X-`.
- RFC 2167 §3.4: query syntax, dump format, attribute type characters, and referrals.
- RFC 2167 §3.5: TCP connection model and port 4321.
- RFC 2167 Appendix B: consolidated ABNF.
- RFC 2167 Appendix C: error codes.
- RFC 2167 Appendix D: capability ID bits.
- RFC 2167 Appendix E: schema definitions and base class.

## Intentional limitations

- TCP is implemented. RFC 2167 mentions UDP but defers UDP details to another document, so UDP is not implemented.
- PGP security is parsed conceptually but not implemented with cryptographic operations.
- Registration and transfer are implemented against the in-memory backend and backend hooks. Production replication policy is intentionally backend-specific.
