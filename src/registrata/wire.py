"""Low-level CRLF wire helpers."""

from __future__ import annotations

import socket
import time
from typing import Iterator

from .errors import RwhoisProtocolError

CRLF = "\r\n"
LINE_ENCODING = "latin-1"
DEFAULT_MAX_LINE_BYTES = 1_048_576  # 1 MiB per wire line


def validate_wire_text(value: str, *, label: str = "value") -> str:
    if "\r" in value or "\n" in value:
        raise RwhoisProtocolError(f"{label} must not contain CR or LF: {value!r}")
    return value


def encode_line(line: str, *, validate: bool = True) -> bytes:
    if validate:
        validate_wire_text(line, label="line")
    return line.encode(LINE_ENCODING) + CRLF.encode(LINE_ENCODING)


def strip_line_ending(raw: bytes) -> str:
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    return raw.decode(LINE_ENCODING)


class LineReader:
    """Read CRLF/LF terminated RWhois lines from a socket."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        buffer_size: int = 65536,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        line_deadline_seconds: float | None = None,
    ):
        """``line_deadline_seconds`` bounds how long one line may take to arrive.

        A socket timeout is a per-syscall promise, so a server that dribbles a byte at a time
        with no line ending keeps resetting it and the read never expires; the size ceilings
        cannot help either, because one byte per second does not reach 1 MiB before the caller
        gives up. This is the elapsed ceiling those ceilings assume. It is per line rather than
        per response so a legitimately slow bulk transfer is not cut off -- a server that keeps
        completing lines is bounded by the response budget instead.
        """
        self._sock = sock
        self._buffer = bytearray()
        self._buffer_size = buffer_size
        self.max_line_bytes = int(max_line_bytes)
        self.line_deadline_seconds = (
            None if line_deadline_seconds is None else float(line_deadline_seconds)
        )

    def readline(self) -> str:
        started = None if self.line_deadline_seconds is None else time.monotonic()
        while True:
            newline = self._buffer.find(b"\n")
            if newline != -1:
                if newline + 1 > self.max_line_bytes:
                    raise RwhoisProtocolError("response line exceeds maximum length")
                line = bytes(self._buffer[: newline + 1])
                del self._buffer[: newline + 1]
                return strip_line_ending(line)
            if (
                started is not None
                and time.monotonic() - started > self.line_deadline_seconds  # type: ignore[operator]
            ):
                # TimeoutError, matching what recv raises when a silent server's socket timeout
                # fires, so callers that already handle one handle the other.
                raise TimeoutError(
                    f"line not completed within {self.line_deadline_seconds}s of continuous input"
                )
            chunk = self._sock.recv(self._buffer_size)
            if not chunk:
                raise ConnectionError("connection closed")
            self._buffer.extend(chunk)
            if len(self._buffer) > self.max_line_bytes:
                raise RwhoisProtocolError("response line exceeds maximum length")

    def read_until(self, terminators: tuple[str, ...] = ("%ok",)) -> Iterator[str]:
        while True:
            line = self.readline()
            yield line
            if any(line.startswith(term) for term in terminators):
                return

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


__all__ = [
    "CRLF",
    "DEFAULT_MAX_LINE_BYTES",
    "LINE_ENCODING",
    "LineReader",
    "encode_line",
    "strip_line_ending",
    "validate_wire_text",
]
