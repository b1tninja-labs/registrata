"""Parsing helpers for RWhois server messages."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .banner import Banner, parse_banner
from .errors import RwhoisParseError, parse_error_line
from .records import AttributeLine, ObjectRecord, Referral, parse_referral_line
from .schema import AttributeDefinition, SchemaClass
from .soa import SOARecord

_PREFIXES = (
    "%ok",
    "%error",
    "%info",
    "%rwhois",
    "%referral",
    "%status",
    "%soa",
    "%schema",
    "%class",
    "%directive",
    "%display",
    "%register",
    "%notify",
    "%xfer",
)


@dataclass
class ServerResponse:
    raw_lines: list[str] = field(default_factory=list)
    ok: bool = False
    error_code: int | None = None
    error_text: str | None = None
    info_messages: list[str] = field(default_factory=list)
    banners: list[Banner] = field(default_factory=list)
    objects: list[ObjectRecord] = field(default_factory=list)
    referrals: list[Referral] = field(default_factory=list)
    status: list[tuple[str, str]] = field(default_factory=list)
    soa: list[SOARecord] = field(default_factory=list)
    schema_groups: list[dict[str, str]] = field(default_factory=list)
    class_groups: list[dict[str, str]] = field(default_factory=list)
    directive_groups: list[dict[str, str]] = field(default_factory=list)
    display_groups: list[dict[str, str]] = field(default_factory=list)
    register: list[tuple[str, str]] = field(default_factory=list)
    xfer_objects: list[ObjectRecord] = field(default_factory=list)
    xfer_groups: list[list[AttributeLine]] = field(default_factory=list)
    other_lines: list[str] = field(default_factory=list)

    @property
    def status_dict(self) -> dict[str, str]:
        return dict(self.status)

    @property
    def schema_classes(self) -> list[SchemaClass]:
        return schema_classes_from_groups(self.schema_groups)

    @property
    def class_classes(self) -> list[SchemaClass]:
        out: dict[str, SchemaClass] = {}
        for group in self.class_groups:
            class_name = group.get("class")
            if not class_name:
                continue
            cls = out.setdefault(class_name, SchemaClass(class_name))
            if "description" in group:
                cls.description = group["description"]
            if "version" in group:
                cls.version = group["version"]
        return list(out.values())

    def raise_for_error(self) -> None:
        if self.error_code is not None:
            from .errors import error_from_code

            raise error_from_code(self.error_code, self.error_text)


@dataclass
class QueryResult(ServerResponse):
    pass


def _is_terminator(line: str) -> bool:
    return line == "%ok" or line.startswith("%error ")


def _split_prefix(line: str, prefix: str) -> str:
    if line.startswith(prefix + " "):
        return line[len(prefix) + 1 :]
    if line.startswith(prefix):
        return line[len(prefix) :].strip()
    raise RwhoisParseError(f"expected {prefix}: {line!r}")


def _parse_grouped_simple(
    lines: list[str], prefix: str
) -> tuple[list[dict[str, str]], int]:
    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == prefix:
            if current:
                records.append(current)
            current = None
            i += 1
            continue
        if line.startswith(prefix + " "):
            payload = line[len(prefix) + 1 :]
            key, sep, value = payload.partition(":")
            if sep:
                if current is None:
                    current = {}
                current[key] = value
            i += 1
        else:
            if line.startswith(prefix):
                raise RwhoisParseError(f"invalid {prefix} line: {line!r}")
            break
    if current:
        records.append(current)
    return records, i


def _parse_grouped_two_level(
    lines: list[str], prefix: str
) -> tuple[list[dict[str, str]], int]:
    """Parse `%class domain:field:value` and `%schema class:field:value` groups."""
    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == prefix:
            if current:
                records.append(current)
            current = None
            i += 1
            continue
        if line.startswith(prefix + " "):
            payload = line[len(prefix) + 1 :]
            parts = payload.split(":", 2)
            if len(parts) != 3:
                raise RwhoisParseError(f"invalid {prefix} line: {line!r}")
            name, key, value = parts
            if current is None:
                current = {"class": name}
            current[key] = value
            i += 1
        else:
            if line.startswith(prefix):
                raise RwhoisParseError(f"invalid {prefix} line: {line!r}")
            break
    if current:
        records.append(current)
    return records, i


def _parse_info_block(lines: list[str], start: int) -> tuple[list[str], int]:
    """Collect an RFC 2167 ``%info on`` ... ``%info off`` message block.

    Strictly (RFC 2167 section 3.1.9) an info block may contain any octet
    1..255 except CR/LF, so a line that looks like ``%ok`` is legal *text* as long
    as the block is properly closed with ``%info off``. When the block is never
    closed, however, the terminator must not be swallowed: a truncated or hostile
    response would otherwise leave the client waiting for ``%ok`` forever.
    """
    first = lines[start]
    if first != "%info on":
        raise RwhoisParseError(f"invalid info block start: {first!r}")
    closed = "%info off" in lines[start + 1 :]
    messages: list[str] = []
    i = start + 1
    while i < len(lines):
        line = lines[i]
        if line == "%info off":
            return messages, i + 1
        if not closed and _is_terminator(line):
            return messages, i
        messages.append(line)
        i += 1
    return messages, len(lines)


def schema_classes_from_groups(groups: list[dict[str, str]]) -> list[SchemaClass]:
    by_class: dict[str, SchemaClass] = {}
    for group in groups:
        class_name = group.get("class")
        if not class_name:
            continue
        if class_name not in by_class:
            by_class[class_name] = SchemaClass(class_name)
        if any(k in group for k in ("attribute", "name")):
            by_class[class_name].add(AttributeDefinition.from_schema_group(group))
    return list(by_class.values())


def _grouped_advance(consumed: int, line: str, prefix: str) -> int:
    """How far a grouped handler moved, refusing to let the cursor stall.

    Grouped handlers stop at the first line they do not recognize, which is correct
    inside a group and fatal at the start of one: ``%classdomain:x`` carries the prefix
    but not the ``space`` the grammar requires (``class-line = "%class" space ...``), so
    neither branch matches, the handler reports zero lines consumed, and ``i += 0`` spins
    forever on input a hostile server controls. Nothing is raised, so no caller timeout
    can rescue it either.

    A prefix glued to its payload is malformed rather than ambiguous, and every other
    grouped keyword already answers that shape with a typed error, so this makes the five
    grouped prefixes behave like the three strict ones instead of inventing new policy.
    """
    if consumed < 1:
        raise RwhoisParseError(f"invalid {prefix} line: {line!r}")
    return consumed


def parse_response(
    lines: Iterable[str], *, parse_objects: bool = False
) -> ServerResponse | QueryResult:
    raw = [line.rstrip("\r\n") for line in lines]
    if parse_objects:
        return parse_query_result(raw)
    resp = ServerResponse(raw_lines=raw)
    i = 0
    while i < len(raw):
        line = raw[i]
        if line == "":
            i += 1
            continue
        if line == "%ok":
            resp.ok = True
            i += 1
            continue
        if line.startswith("%error"):
            resp.error_code, resp.error_text = parse_error_line(line)
            i += 1
            continue
        if line.startswith("%rwhois"):
            resp.banners.append(parse_banner(line))
            i += 1
            continue
        if line.startswith("%info"):
            messages, i = _parse_info_block(raw, i)
            resp.info_messages.extend(messages)
            continue
        if line.startswith("%referral"):
            resp.referrals.append(parse_referral_line(line))
            i += 1
            continue
        if line.startswith("%status"):
            payload = _split_prefix(line, "%status")
            key, sep, value = payload.partition(":")
            if not sep:
                raise RwhoisParseError(f"invalid status line: {line!r}")
            resp.status.append((key, value))
            i += 1
            continue
        if line.startswith("%soa"):
            j = i + 1
            while (
                j < len(raw)
                and raw[j] != "%soa"
                and raw[j] != "%ok"
                and not raw[j].startswith("%error ")
            ):
                j += 1
            group = raw[i:j]
            if j < len(raw) and raw[j] == "%soa":
                group = raw[i : j + 1]
                j += 1
            resp.soa.append(SOARecord.from_lines(group))
            i = j
            continue

        if line.startswith("%class"):
            groups, j = _parse_grouped_two_level(raw[i:], "%class")
            resp.class_groups.extend(groups)
            i += _grouped_advance(j, line, "%class")
            continue
        if line.startswith("%schema"):
            groups, j = _parse_grouped_two_level(raw[i:], "%schema")
            resp.schema_groups.extend(groups)
            i += _grouped_advance(j, line, "%schema")
            continue
        if line.startswith("%directive"):
            groups, j = _parse_grouped_simple(raw[i:], "%directive")
            resp.directive_groups.extend(groups)
            i += _grouped_advance(j, line, "%directive")
            continue
        if line.startswith("%display"):
            groups, j = _parse_grouped_simple(raw[i:], "%display")
            resp.display_groups.extend(groups)
            i += _grouped_advance(j, line, "%display")
            continue
        if line.startswith("%register"):
            payload = _split_prefix(line, "%register")
            key, sep, value = payload.partition(":")
            if not sep:
                raise RwhoisParseError(f"invalid register line: {line!r}")
            resp.register.append((key, value))
            i += 1
            continue
        if line.startswith("%notify"):
            resp.other_lines.append(line)
            i += 1
            continue
        if line.startswith("%xfer"):
            groups, j = _parse_xfer_group(raw[i:])
            resp.xfer_groups.extend([attrs for _, attrs in groups])
            resp.xfer_objects.extend(
                ObjectRecord(class_name, attrs) for class_name, attrs in groups
            )
            i += _grouped_advance(j, line, "%xfer")
            continue
        resp.other_lines.append(line)
        i += 1
    return resp


def _parse_xfer_group(
    lines: list[str],
) -> tuple[list[tuple[str, list[AttributeLine]]], int]:
    groups: list[tuple[str, list[AttributeLine]]] = []
    current_class: str | None = None
    current: list[AttributeLine] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == "%xfer":
            if current:
                groups.append((current_class or "unknown", current))
            current_class = None
            current = []
            i += 1
            continue
        if line.startswith("%xfer "):
            payload = line[len("%xfer") + 1 :]
            class_name, attr = AttributeLine.parse(payload)
            current_class = current_class or class_name
            current.append(attr)
            i += 1
            continue
        if line.startswith("%xfer"):
            raise RwhoisParseError(f"invalid %xfer line: {line!r}")
        break
    if current:
        groups.append((current_class or "unknown", current))
    return groups, i


def parse_query_result(lines: Iterable[str]) -> QueryResult:
    raw = [line.rstrip("\r\n") for line in lines]
    resp = QueryResult(raw_lines=raw)
    current: list[str] = []

    def flush() -> None:
        if current:
            resp.objects.append(ObjectRecord.from_lines(current))
            current.clear()

    i = 0
    while i < len(raw):
        line = raw[i]
        if line == "":
            flush()
            i += 1
            continue
        if line == "%ok":
            flush()
            resp.ok = True
            break
        if line.startswith("%error"):
            flush()
            resp.error_code, resp.error_text = parse_error_line(line)
            break
        if line.startswith("%referral"):
            flush()
            resp.referrals.append(parse_referral_line(line))
            i += 1
            continue
        if line.startswith("%info"):
            flush()
            messages, i = _parse_info_block(raw, i)
            resp.info_messages.extend(messages)
            continue
        current.append(line)
        i += 1
    flush()
    return resp


def parse_directive_response(lines: Iterable[str]) -> ServerResponse:
    return parse_response(lines, parse_objects=False)


__all__ = [
    "QueryResult",
    "ServerResponse",
    "parse_directive_response",
    "parse_query_result",
    "parse_response",
    "schema_classes_from_groups",
]
