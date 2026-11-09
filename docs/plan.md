# Plan

`registrata` is a registration-data toolkit: an RFC 2167 RWhois client and server, plus experimental
classic WHOIS (RFC 3912) and RDAP (RFC 7480, 9082, 9083, 9224) behind one normalized lookup model.

- **Directory:** `pyrwhois/` on the development machine, until it is renamed to `registrata/`. The portfolio
  tooling resolves the project through `DIRECTORIES` in `sdk-forge/roadmap.py`.
- **Repository:** <https://github.com/b1tninja-labs/registrata>.
- **Formerly:** `pyrwhois`, imported as `rwhois`. The old import, console script, cache table, log key and
  `RWHOIS_*` environment variables still work; `ROADMAP.md` lists each seam and when it goes.
- **Dependencies on other portfolio projects:** none. The package has no runtime dependencies.
- **Work queue:** the obligation matrix in `ROADMAP.md`. Nothing is blocked.
- **Source of truth for specifications:** `docs/rfc-map.md`.
