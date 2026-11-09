# Instructions for coding agents

`registrata` is a registration-data toolkit: an RFC 2167 RWhois client and server, plus experimental
classic WHOIS (RFC 3912) and RDAP behind one normalized lookup model. It was `pyrwhois` (imported as
`rwhois`); the old import, console script, cache table, log key and `RWHOIS_*` variables remain as
deprecated seams listed in `ROADMAP.md`.

Primary documents are in `docs/rfc-map.md` with statuses and known errata. The obligation matrix in
`ROADMAP.md` is the work queue. Read those two before changing anything. For any protocol question use the
`rfclib` MCP tools rather than memory.

## Finding work

If the person gave you a task, do that task.

If you arrived with nothing to do, run this from the workspace root (`D:\code`):

    python sdk-forge/loop.py pickup --who <your name> --project registrata

Its output is your assignment. `NO WORK` is a real answer: ask the person what to work on. Without the
workspace beside this repository, read `.forge/packet.md` if it exists, otherwise ask.

## Commands

    python -m pip install -e . pytest ruff
    python -m pytest -q
    python -m pytest -q tests/test_roadmap_rows.py
    python -O -m pytest -q
    python -m ruff check src tests tools
    python -m ruff format --check src tests tools

All of them must pass before a change is finished. The tests are offline; `REGISTRATA_RUN_LIVE=1` runs the
live-fixture suite against real registries.

## Rules

- A matrix row reads `[ok]` only when a named test would fail if the behaviour regressed. Update the row in
  the commit that changes the behaviour.
- The package has no runtime dependencies. Keep it that way.
- Python 3.12 or newer, `from __future__ import annotations`, `X | None`, and `datetime.UTC`.
- Commit messages carry no AI attribution trailer.
- Write scratch output outside the repository.

## Notes for other agent harnesses

- Never use a tool name called `edit_file`; the only supported file editing tool is `editor`.
- After drafting an edit, double-check the tool name before sending the tool call.
- Prefer actual tool calls over describing intended tool calls.
- When applying small source edits, use `editor` with `path`, `old_text`, and `new_text`.
- Split oversized edits into multiple smaller `editor` calls instead of sending invalid or oversized tool payloads.
