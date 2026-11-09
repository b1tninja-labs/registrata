"""RFC 2167 Appendix D capability bits."""

from __future__ import annotations

from enum import IntFlag
import re

from .errors import RwhoisParseError

CAPABILITY_RE = re.compile(r"^([0-9a-fA-F]{6}):([0-9a-fA-F]{2})$")


class Capability(IntFlag):
    NONE = 0
    CLASS = 0x000001
    DIRECTIVE = 0x000002
    DISPLAY = 0x000004
    FORWARD = 0x000008
    HOLDCONNECT = 0x000010
    LIMIT = 0x000020
    NOTIFY = 0x000040
    QUIT = 0x000080
    REGISTER = 0x000100
    SCHEMA = 0x000200
    SECURITY = 0x000400
    SOA = 0x000800
    STATUS = 0x001000
    XFER = 0x002000
    X = 0x004000


def encode_capability_id(value: int | Capability) -> str:
    bits = int(value)
    if bits < 0 or bits > 0xFFFFFFFF:
        raise ValueError("capability id must fit in 32 bits")
    return f"{bits & 0x00FFFFFF:06x}:{(bits >> 24) & 0xFF:02x}"


def decode_capability_id(value: str) -> Capability:
    match = CAPABILITY_RE.match(value.strip())
    if not match:
        raise RwhoisParseError(f"invalid capability id: {value!r}")
    bits = int(match.group(1), 16) | (int(match.group(2), 16) << 24)
    return Capability(bits)


def directive_name_for_bit(capability: Capability) -> str | None:
    return {
        Capability.CLASS: "class",
        Capability.DIRECTIVE: "directive",
        Capability.DISPLAY: "display",
        Capability.FORWARD: "forward",
        Capability.HOLDCONNECT: "holdconnect",
        Capability.LIMIT: "limit",
        Capability.NOTIFY: "notify",
        Capability.QUIT: "quit",
        Capability.REGISTER: "register",
        Capability.SCHEMA: "schema",
        Capability.SECURITY: "security",
        Capability.SOA: "soa",
        Capability.STATUS: "status",
        Capability.XFER: "xfer",
        Capability.X: "X",
    }.get(capability)


__all__ = [
    "Capability",
    "decode_capability_id",
    "directive_name_for_bit",
    "encode_capability_id",
]
