"""RWhois banner parsing and serialization."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .capabilities import Capability, decode_capability_id, encode_capability_id
from .errors import RwhoisParseError

VERSION_RE = re.compile(r"^V-(?P<major>\d+)\.(?P<minor>\d+)$")


@dataclass(frozen=True)
class Version:
    number: str
    capability: Capability | None = None

    @property
    def name(self) -> str:
        return self.number if self.number.startswith("V-") else f"V-{self.number}"

    @property
    def numeric(self) -> tuple[int, int]:
        match = VERSION_RE.match(self.name)
        if not match:
            raise RwhoisParseError(f"invalid version number: {self.number!r}")
        return int(match.group("major")), int(match.group("minor"))

    def __str__(self) -> str:
        if self.capability is None:
            return self.name
        return f"{self.name}:{encode_capability_id(self.capability)}"

    @classmethod
    def parse(cls, token: str) -> "Version":
        token = token.strip()
        if not token:
            raise RwhoisParseError("empty version token")
        if ":" in token:
            number, cap = token.split(":", 1)
        else:
            number, cap = token, None
        normalized = number[2:] if number.startswith("V-") else number
        return cls(normalized, decode_capability_id(cap) if cap else None)


@dataclass(frozen=True)
class Banner:
    versions: tuple[Version, ...]
    host: str
    implementation: str = ""
    raw: str = ""

    @property
    def version_numbers(self) -> tuple[str, ...]:
        return tuple(v.name for v in self.versions)

    @property
    def capabilities(self) -> set[Capability]:
        caps = set()
        for version in self.versions:
            if version.capability is None:
                continue
            caps.update(
                flag
                for flag in Capability
                if int(flag) and int(flag) & int(version.capability)
            )
        return caps

    def supports_version(self, version: str | Version) -> bool:
        name = version.name if isinstance(version, Version) else version
        if not name.startswith("V-"):
            name = f"V-{name}"
        return any(v.name == name for v in self.versions)

    def best_version(self) -> Version:
        if not self.versions:
            raise RwhoisParseError("banner has no versions")
        return sorted(self.versions, key=lambda v: v.numeric)[-1]


def parse_banner(line: str) -> Banner:
    raw = line.rstrip("\r\n")
    if not raw.startswith("%rwhois"):
        raise RwhoisParseError(f"not a banner line: {line!r}")
    rest = raw[len("%rwhois") :].strip()
    if not rest:
        raise RwhoisParseError(f"banner missing version list and host: {line!r}")
    parts = rest.split(" ", 2)
    version_list = parts[0]
    host = parts[1] if len(parts) > 1 else ""
    implementation = parts[2] if len(parts) > 2 else ""
    if not host:
        raise RwhoisParseError(f"banner missing host: {line!r}")
    versions = tuple(Version.parse(token) for token in version_list.split(","))
    if not versions:
        raise RwhoisParseError(f"banner missing versions: {line!r}")
    return Banner(versions, host, implementation, raw)


def serialize_banner(
    versions: Version | list[Version] | tuple[Version, ...],
    host: str,
    *,
    implementation: str = "",
    capability: Capability | None = None,
) -> str:
    if isinstance(versions, Version):
        version_seq: tuple[Version, ...] = (versions,)
    else:
        version_seq = tuple(versions)
    if not version_seq:
        raise ValueError("at least one version is required")

    rendered_versions: list[str] = []
    for version in version_seq:
        if version.capability is not None or capability is None:
            rendered_versions.append(str(version))
        else:
            rendered_versions.append(str(Version(version.name, capability)))

    version_list = ",".join(rendered_versions)
    if implementation:
        return f"%rwhois {version_list} {host} {implementation}"
    return f"%rwhois {version_list} {host}"


__all__ = ["Banner", "Version", "parse_banner", "serialize_banner"]
