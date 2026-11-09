"""The interfaces the documentation shows must be the interfaces that exist.

Docs drift silently in exactly this way: a flag is renamed, an example keeps the old
spelling, a helper is cited by a path that was never importable, and nothing fails
until a reader types it. This walks the fenced shell blocks in the documentation and
parses every ``registrata`` invocation against the real parser, and checks that every
dotted ``registrata.*`` name the usage docs cite can actually be imported.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import re
import shlex
from pathlib import Path

import pytest

from registrata.cli import build_parser

ROOT = Path(__file__).resolve().parent.parent

DOCS = [
    ROOT / "README.md",
    ROOT / "docs" / "experimental.md",
    ROOT / "docs" / "compliance.md",
    ROOT / "docs" / "roadmap.md",
    ROOT / "docs" / "research.md",
    ROOT / "docs" / "spec.md",
]

# Only blocks that are meant to be typed. Python and JSON blocks legitimately mention
# "registrata" too -- `from registrata import RwhoisClient` is not a subcommand.
SHELL_LANGUAGES = {
    "powershell",
    "ps1",
    "pwsh",
    "bash",
    "sh",
    "shell",
    "console",
    "terminal",
    "",
}
NON_SHELL_LANGUAGES = {
    "python",
    "py",
    "json",
    "toml",
    "yaml",
    "ini",
    "abnf",
    "yang",
    "sql",
    "diff",
    "html",
    "xml",
}

FENCE = re.compile(r"^\s*(?:```|~~~)\s*(?P<lang>[A-Za-z0-9_+.-]+)?\s*$")
COMMAND = re.compile(r"(?:uv run )?registrata\s+(?P<args>\S.*)")


def documented_commands(path: Path) -> list[tuple[int, str]]:
    """Return (line_number, argument string) for shell examples in one markdown file."""
    found: list[tuple[int, str]] = []
    language: str | None = None
    for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        fence = FENCE.match(line)
        if fence:
            if language is None:
                language = (fence.group("lang") or "").lower()
            else:
                language = None
            continue
        if (
            language is None
            or language in NON_SHELL_LANGUAGES
            or language not in SHELL_LANGUAGES
        ):
            continue
        match = COMMAND.search(line.strip())
        if not match:
            continue
        command = match.group("args").strip()
        # A trailing backtick is a PowerShell line continuation: the example is split
        # across lines and cannot be judged on its first fragment.
        if command.endswith("`"):
            continue
        found.append((number, command))
    return found


CASES = [
    (path.name, number, command)
    for path in DOCS
    for number, command in documented_commands(path)
]


def test_documentation_exists():
    assert CASES, (
        "no registrata examples were found in the docs; the extractor is broken"
    )
    # A sanity floor: this repository documents dozens of invocations, so a count of
    # a handful means the fence handling stopped matching, not that the docs shrank.
    assert len(CASES) > 40, (
        f"only {len(CASES)} documented commands found; check the extractor"
    )


@pytest.mark.parametrize(
    "location,number,command",
    CASES,
    ids=[f"{name}:{number}" for name, number, _ in CASES],
)
def test_documented_command_line_parses(location: str, number: int, command: str):
    try:
        argv = shlex.split(command)
    except ValueError as exc:  # an example nobody can paste
        pytest.fail(
            f"{location}:{number}: {command!r} is not splittable shell text: {exc}"
        )

    errors = io.StringIO()
    with contextlib.suppress(SystemExit), contextlib.redirect_stderr(errors):
        build_parser().parse_args(argv)

    if errors.getvalue().strip():
        reason = errors.getvalue().strip().splitlines()[-1]
        pytest.fail(
            f"{location}:{number}: docs say `registrata {command}` but the parser rejects it\n     {reason}"
        )


# The API-name check covers usage documentation only. A roadmap may describe a name
# that does not exist yet; README and docs/ are what a reader copies into code.
API_DOCS = [
    ROOT / "README.md",
    ROOT / "docs" / "experimental.md",
    ROOT / "docs" / "compliance.md",
    ROOT / "docs" / "spec.md",
]

CITED_NAME = re.compile(r"\b(registrata(?:\.[A-Za-z_][A-Za-z0-9_]*)+)(?:\(\))?")


def resolves(dotted: str) -> bool:
    """True when the name is a module, or a module followed by reachable attributes."""
    parts = dotted.split(".")
    for split in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:split]))
        except Exception:
            continue
        try:
            for attribute in parts[split:]:
                obj = getattr(obj, attribute)
        except AttributeError:
            continue
        return True
    return False


def cited_api_names() -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for path in API_DOCS:
        for match in CITED_NAME.finditer(path.read_text(encoding="utf-8")):
            found.setdefault(match.group(1), path.name)
    return sorted(found.items())


@pytest.mark.parametrize(
    "dotted,location",
    cited_api_names(),
    ids=[name for name, _ in cited_api_names()],
)
def test_documented_api_name_exists(dotted: str, location: str):
    assert resolves(dotted), (
        f"{location} documents {dotted!r}, which cannot be imported"
    )


def test_documented_api_names_were_found():
    assert len(cited_api_names()) > 5, (
        "the API-name extractor matched almost nothing; check the regex"
    )
