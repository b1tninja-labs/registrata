"""Synchronous TCP client for RFC 2167 RWhois."""

from __future__ import annotations

import socket
from typing import Any, Iterable

from .banner import Banner, parse_banner
from .errors import InvalidLimit, RwhoisError, RwhoisProtocolError
from .protocol import QueryResult, ServerResponse, parse_response
from .query import Query
from .wire import CRLF, DEFAULT_MAX_LINE_BYTES, LineReader

DEFAULT_MAX_RESPONSE_LINES = 100_000
DEFAULT_MAX_RESPONSE_BYTES = 16_777_216  # 16 MiB per protocol response


class RwhoisClient:
    """TCP RWhois client.

    The client follows the session model in RFC 2167 §3.1.6: connect, read the server banner,
    send directives, send a query, then close. Because §3.3.5 makes ``off`` the default state for
    every connection, ``__enter__`` sends ``-holdconnect on`` first and records the answer in
    ``session_held``; pass ``hold_connect=False`` to skip that, which is what the conformance
    checker does so it can probe the directive itself.
    """

    def __init__(
        self,
        host: str,
        port: int = 4321,
        *,
        timeout: float | None = 10.0,
        implementation: str = "registrata 0.1.0",
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        max_response_lines: int = DEFAULT_MAX_RESPONSE_LINES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        hold_connect: bool = True,
    ):
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.implementation = implementation
        self.max_line_bytes = int(max_line_bytes)
        self.max_response_lines = int(max_response_lines)
        self.max_response_bytes = int(max_response_bytes)
        # Section 3.3.5 makes "off" the default state for every connection, so a client that
        # intends more than one query has to ask for it. False here means "do not ask", which is
        # what the conformance checker passes so it can probe the directive honestly.
        self.hold_connect = hold_connect
        self.session_held: bool | None = None
        self._sock: socket.socket | None = None
        self._reader: LineReader | None = None
        self.banner: Banner | None = None

    @classmethod
    def connect(cls, host: str, port: int = 4321, **kwargs: Any) -> "RwhoisClient":
        client = cls(host, port, **kwargs)
        client.__enter__()
        return client

    def __enter__(self) -> "RwhoisClient":
        # Idempotent, because `with RwhoisClient.connect(...) as client` is the pattern used
        # throughout this codebase: connect() has already entered, and entering again would open a
        # second socket and silently abandon the first. Harmless against a server that accepts
        # anything, and a doubled connection count against a server that limits them -- which is
        # exactly the politeness this library is supposed to observe.
        if self._sock is not None:
            return self
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock = sock
        self._reader = LineReader(
            sock,
            max_line_bytes=self.max_line_bytes,
            line_deadline_seconds=self.timeout,
        )
        try:
            first_line = self._reader.readline()
        except TimeoutError as exc:
            # The socket is closed here rather than left for the garbage collector: this raises out
            # of __enter__, so __exit__ never runs, and a client that has been pointed at a wrong
            # endpoint a few hundred times should not accumulate half-open connections.
            self.close()
            raise RwhoisProtocolError(
                f"no banner from {self.host}:{self.port} within {self.timeout}s; a server sends a "
                "%rwhois V-1.5:... line as soon as the connection opens (RFC 2167 3.1.6), so an "
                "endpoint that stays silent is not speaking RWhois. Plain WHOIS on this port is the "
                "usual cause: rwhois.arin.net:4321 behaves exactly this way."
            ) from exc
        self.banner = parse_banner(first_line)
        if self.hold_connect:
            self.session_held = self._request_held_session()
        return self

    def _request_held_session(self) -> bool:
        """Ask the server to keep this connection open, and report whether it agreed.

        The server's default is "close after each query" because that is what section 3.3.5
        specifies, so asking is the only way to get a session. Negotiating here rather than
        lazily is not a choice: with the specified default, the socket is already gone by the
        time a caller wants a second query.

        A refusal is recorded, not raised. ``400 Directive not available``, ``401 Not authorized
        for directive`` and ``338 Invalid directive syntax`` all describe a server that is
        following the protocol, and the single query that connection was opened for still works;
        so does one against a server that answers nothing, since the read deadline raises
        ``TimeoutError``, which is an ``OSError``.
        """
        try:
            response = self.send_command("-holdconnect on", raise_errors=False)
        except (OSError, RwhoisError):
            return False
        return getattr(response, "error_code", None) is None

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._reader = None

    def _send_line(self, line: str) -> None:
        if self._sock is None:
            raise ConnectionError("client is not connected")
        if "\r" in line or "\n" in line:
            raise RwhoisError("command must not contain CR or LF")
        self._sock.sendall(line.encode("latin-1") + CRLF.encode("latin-1"))

    def _read_until_end(self) -> list[str]:
        if self._reader is None:
            raise ConnectionError("client is not connected")
        lines: list[str] = []
        total_bytes = 0
        while True:
            try:
                line = self._reader.readline()
            except ConnectionError:
                if lines:
                    return lines
                raise
            total_bytes += len(line.encode("latin-1")) + 2
            if (
                len(lines) >= self.max_response_lines
                or total_bytes > self.max_response_bytes
            ):
                raise RwhoisError("server response exceeded configured limits")
            lines.append(line)
            if line == "%ok" or line.startswith("%error"):
                return lines

    def send_command(
        self, command: str, *, parse_objects: bool = False, raise_errors: bool = True
    ):
        self._send_line(command)
        lines = self._read_until_end()
        parsed = parse_response(lines, parse_objects=parse_objects)
        if raise_errors:
            parsed.raise_for_error()
        return parsed

    def send_query(
        self, query: str | Query, *, raise_errors: bool = True
    ) -> QueryResult:
        command = query.to_wire() if isinstance(query, Query) else query
        self._send_line(command)
        lines = self._read_until_end()
        parsed = parse_response(lines, parse_objects=True)
        if not isinstance(parsed, QueryResult):
            raise RwhoisError("expected query result")
        if raise_errors:
            parsed.raise_for_error()
        return parsed

    def query(
        self,
        class_name: str | None,
        value_or_query: str | Query,
        *,
        raise_errors: bool = True,
    ) -> QueryResult:
        if isinstance(value_or_query, Query):
            query = value_or_query
            if class_name is not None:
                query = Query(query.expression, class_name=class_name)
        else:
            query = (
                Query.class_restricted(class_name, value_or_query)
                if class_name
                else Query.unrestricted(value_or_query)
            )
        return self.send_query(query, raise_errors=raise_errors)

    def query_attribute(
        self, class_name: str | None, attribute: str, value: str, **kwargs: Any
    ) -> QueryResult:
        return self.send_query(Query.attribute(class_name, attribute, value), **kwargs)

    def limit(self, value: int) -> ServerResponse:
        if int(value) < 0:
            raise InvalidLimit("limit must not be negative")
        return self.send_command(f"-limit {int(value)}")

    def holdconnect(self, value: bool) -> ServerResponse:
        return self.send_command(f"-holdconnect {'on' if value else 'off'}")

    def forward(self, value: bool) -> ServerResponse:
        return self.send_command(f"-forward {'on' if value else 'off'}")

    def display(self, name: str | None = None) -> ServerResponse:
        if name is None:
            return self.send_command("-display")
        return self.send_command(f"-display {name}")

    def status(self) -> ServerResponse:
        return self.send_command("-status")

    def soa(self, *authority_areas: str) -> ServerResponse:
        if authority_areas:
            return self.send_command("-soa " + " ".join(authority_areas))
        return self.send_command("-soa")

    def schema(self, authority_area: str, *class_names: str) -> ServerResponse:
        parts = [authority_area, *class_names]
        return self.send_command("-schema " + " ".join(parts))

    def classes(self, authority_area: str, *class_names: str) -> ServerResponse:
        parts = [authority_area, *class_names]
        return self.send_command("-class " + " ".join(parts))

    def directives(self, *names: str) -> ServerResponse:
        command = "-directive"
        if names:
            command += " " + " ".join(names)
        return self.send_command(command)

    def rwhois(self, version: str = "V-1.5") -> ServerResponse:
        return self.send_command(f"-rwhois {version} {self.implementation}")

    def quit(self) -> ServerResponse:
        try:
            return self.send_command("-quit")
        finally:
            self.close()

    def security_password(
        self, password: str, *, direction: str = "request"
    ) -> ServerResponse:
        return self.send_command(f"-security on {direction} password {password}")

    def register(
        self, mode: str, maintainer: str, lines: Iterable[str]
    ) -> ServerResponse:
        if mode not in {"add", "mod", "del"}:
            raise RwhoisError("register mode must be add, mod, or del")
        self.send_command(f"-register on {mode} {maintainer}")
        for line in lines:
            self._send_line(line)
        return self.send_command("-register off")


__all__ = ["RwhoisClient"]
