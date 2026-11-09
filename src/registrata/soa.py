"""SOA record helpers."""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

from .errors import RwhoisParseError

_TIMESTAMP_RE = re.compile(r"^\d{17}$")


def parse_timestamp(value: str) -> dt.datetime:
    if not _TIMESTAMP_RE.match(value):
        raise RwhoisParseError(f"invalid RWhois timestamp: {value!r}")
    return dt.datetime.strptime(value, "%Y%m%d%H%M%S%f")


def format_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is not None:
        value = value.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return value.strftime("%Y%m%d%H%M%S") + f"{value.microsecond // 1000:03d}"


@dataclass
class SOARecord:
    authority: str
    ttl: int = 86400
    serial: str = field(default_factory=lambda: "19700101000000000")
    refresh: int = 86400
    increment: int = 3600
    retry: int = 1800
    tech_contact: str = "admin@example.invalid"
    admin_contact: str = "admin@example.invalid"
    hostmaster: str = "hostmaster@example.invalid"
    primary: str = "localhost:4321"
    extra: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.authority:
            raise RwhoisParseError("SOA authority must not be empty")
        self.ttl = int(self.ttl)
        self.refresh = int(self.refresh)
        self.increment = int(self.increment)
        self.retry = int(self.retry)

    @classmethod
    def from_lines(cls, lines: list[str]) -> "SOARecord":
        payload: dict[str, str] = {}
        for line in lines:
            if not line.startswith("%soa"):
                continue
            if line.strip() == "%soa":
                continue
            data = line[len("%soa") :].strip()
            key, sep, value = data.partition(":")
            if not sep:
                raise RwhoisParseError(f"invalid SOA line: {line!r}")
            payload[key.lower()] = value
        if "authority" not in payload:
            raise RwhoisParseError("SOA record missing authority")
        standard = {
            "authority",
            "ttl",
            "serial",
            "refresh",
            "increment",
            "retry",
            "tech-contact",
            "admin-contact",
            "hostmaster",
            "primary",
        }
        record = cls(
            authority=payload["authority"],
            ttl=int(payload.get("ttl", 86400)),
            serial=payload.get("serial", "19700101000000000"),
            refresh=int(payload.get("refresh", 86400)),
            increment=int(payload.get("increment", 3600)),
            retry=int(payload.get("retry", 1800)),
            tech_contact=payload.get("tech-contact", "admin@example.invalid"),
            admin_contact=payload.get("admin-contact", "admin@example.invalid"),
            hostmaster=payload.get("hostmaster", "hostmaster@example.invalid"),
            primary=payload.get("primary", "localhost:4321"),
            extra={k: v for k, v in payload.items() if k not in standard},
        )
        return record

    def to_lines(self) -> list[str]:
        lines = [
            f"%soa authority:{self.authority}",
            f"%soa ttl:{int(self.ttl)}",
            f"%soa serial:{self.serial}",
            f"%soa refresh:{int(self.refresh)}",
            f"%soa increment:{int(self.increment)}",
            f"%soa retry:{int(self.retry)}",
            f"%soa tech-contact:{self.tech_contact}",
            f"%soa admin-contact:{self.admin_contact}",
            f"%soa hostmaster:{self.hostmaster}",
            f"%soa primary:{self.primary}",
        ]
        lines.extend(f"%soa {key}:{value}" for key, value in self.extra.items())
        lines.append("%soa")
        return lines


__all__ = ["SOARecord", "format_timestamp", "parse_timestamp"]
