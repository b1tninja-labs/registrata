"""Result records and referral objects."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Iterable

from .errors import RwhoisParseError, RwhoisProtocolError

_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_REFERRAL_RE = re.compile(r"^%referral[ \t]+(?P<url>.*)$")


def validate_id(value: str, *, label: str) -> str:
    if not _ID_RE.match(value):
        raise RwhoisParseError(f"invalid {label}: {value!r}")
    return value


def validate_no_line_break(value: str, *, label: str = "value") -> str:
    if "\r" in value or "\n" in value:
        raise RwhoisProtocolError(f"{label} must not contain CR or LF: {value!r}")
    return value


@dataclass(frozen=True)
class AttributeLine:
    name: str
    value: str
    type: str = "T"

    def __post_init__(self) -> None:
        validate_id(self.name, label="attribute name")
        if self.type not in {"T", "I", "S"}:
            raise RwhoisParseError(f"invalid attribute type character: {self.type!r}")
        validate_no_line_break(self.value, label="attribute value")

    def to_wire(self, class_name: str) -> str:
        validate_id(class_name, label="class name")
        if self.type == "T":
            return f"{class_name}:{self.name}:{self.value}"
        return f"{class_name}:{self.name};{self.type}:{self.value}"

    @classmethod
    def parse(
        cls, line: str, *, expected_class: str | None = None
    ) -> tuple[str, "AttributeLine"]:
        if not line:
            raise RwhoisParseError("empty attribute line")
        if ":" not in line:
            raise RwhoisParseError(f"attribute line missing class separator: {line!r}")
        class_name, rest = line.split(":", 1)
        validate_id(class_name, label="class name")
        if expected_class is not None and class_name.lower() != expected_class.lower():
            raise RwhoisParseError(
                f"object class mismatch: expected {expected_class!r}, got {class_name!r}"
            )
        if ":" not in rest:
            raise RwhoisParseError(
                f"attribute line missing attribute separator: {line!r}"
            )
        attr_part, value = rest.split(":", 1)
        if ";" in attr_part:
            attr_name, type_char = attr_part.split(";", 1)
            if len(type_char) != 1:
                raise RwhoisParseError(f"invalid attribute type suffix: {attr_part!r}")
        else:
            attr_name, type_char = attr_part, "T"
        return class_name, cls(attr_name, value, type_char)


@dataclass
class ObjectRecord:
    class_name: str
    attributes: list[AttributeLine] = field(default_factory=list)

    def __post_init__(self) -> None:
        validate_id(self.class_name, label="class name")

    def add(self, name: str, value: str, type: str = "T") -> "ObjectRecord":
        self.attributes.append(AttributeLine(name, value, type))
        return self

    def extend(self, lines: Iterable[AttributeLine]) -> "ObjectRecord":
        self.attributes.extend(lines)
        return self

    def get(self, name: str) -> str | None:
        lowered = name.lower()
        for attr in self.attributes:
            if attr.name.lower() == lowered:
                return attr.value
        return None

    def getall(self, name: str) -> list[str]:
        lowered = name.lower()
        return [attr.value for attr in self.attributes if attr.name.lower() == lowered]

    def as_dict(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for attr in self.attributes:
            out.setdefault(attr.name, []).append(attr.value)
        return out

    @property
    def id(self) -> str | None:
        return self.get("ID")

    @property
    def auth_area(self) -> str | None:
        return self.get("Auth-Area")

    @property
    def updated(self) -> str | None:
        return self.get("Updated")

    @property
    def class_attribute(self) -> str | None:
        return self.get("Class-Name")

    def to_wire_lines(self) -> list[str]:
        return [attr.to_wire(self.class_name) for attr in self.attributes]

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "ObjectRecord":
        current_class: str | None = None
        obj: ObjectRecord | None = None
        for line in lines:
            if not line:
                continue
            class_name, attr = AttributeLine.parse(line, expected_class=current_class)
            if obj is None:
                current_class = class_name
                obj = cls(class_name)
            obj.attributes.append(attr)
        if obj is None:
            raise RwhoisParseError("no object attributes found")
        return obj

    @classmethod
    def from_mapping(
        cls,
        class_name: str,
        attrs: dict[str, str | list[str] | tuple[str, str]],
    ) -> "ObjectRecord":
        obj = cls(class_name)
        for name, value in attrs.items():
            if isinstance(value, tuple):
                type_char, single = value
                obj.add(name, single, type_char)
            elif isinstance(value, list):
                for item in value:
                    obj.add(name, item)
            else:
                obj.add(name, value)
        return obj


@dataclass(frozen=True)
class Referral:
    host: str
    port: int
    auth_area: str

    def __post_init__(self) -> None:
        if not self.host:
            raise RwhoisParseError("referral host must not be empty")
        try:
            port_number = int(self.port)
        except (TypeError, ValueError) as exc:
            raise RwhoisParseError(f"invalid referral port: {self.port!r}") from exc
        if not (1 <= port_number <= 65535):
            raise RwhoisParseError(f"invalid referral port: {self.port!r}")
        if not self.auth_area:
            raise RwhoisParseError("referral authority area must not be empty")

    @property
    def url(self) -> str:
        return f"rwhois://{self.host}:{self.port}/auth-area={self.auth_area}"

    def to_wire(self) -> str:
        return f"%referral {self.url}"

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.host.lower(), int(self.port), self.auth_area.lower())

    @property
    def area_key(self) -> str:
        return self.auth_area.lower()

    @classmethod
    def parse_url(cls, url: str) -> "Referral":
        prefix = "rwhois://"
        marker = "/auth-area="
        if not url.startswith(prefix):
            raise RwhoisParseError(f"referral URL must start with {prefix!r}: {url!r}")
        rest = url[len(prefix) :]
        host_port, sep, auth_area = rest.partition(marker)
        if not sep:
            raise RwhoisParseError(f"referral URL missing {marker!r}: {url!r}")
        host, port_sep, port = host_port.rpartition(":")
        if not port_sep:
            raise RwhoisParseError(f"referral URL missing port: {url!r}")
        if not auth_area:
            raise RwhoisParseError(f"referral URL missing authority area: {url!r}")
        try:
            port_number = int(port)
        except ValueError as exc:
            raise RwhoisParseError(f"referral port must be numeric: {url!r}") from exc
        return cls(host, port_number, auth_area)


def parse_referral_line(line: str) -> Referral:
    match = _REFERRAL_RE.match(line.rstrip("\r\n"))
    if not match:
        raise RwhoisParseError(f"invalid referral line: {line!r}")
    return Referral.parse_url(match.group("url").strip())


__all__ = [
    "AttributeLine",
    "ObjectRecord",
    "Referral",
    "parse_referral_line",
]
