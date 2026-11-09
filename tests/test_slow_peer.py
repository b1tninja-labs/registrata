"""A peer that dribbles bytes, and the ceiling that stops it.

The hostile-server suite covers silence, mid-response disconnects, floods and oversized lines.
The gap was the slow one: a server that holds the connection open and sends one byte at a time
triggers no socket timeout, because a socket timeout bounds a single syscall and every arriving
byte resets it, and it reaches no size ceiling, because a line per second does not fill a
megabyte. Both clients assumed the per-operation bound they had was a total one, so a lookup
could outlast any caller's patience and, because the batch runner deliberately waits for
in-flight work, so could a whole run.

These tests pin the total. A test here that only asserted "an error came back" would pass after
ten minutes, so every one of them also asserts on elapsed time.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Callable

import pytest

from registrata.client import RwhoisClient
from registrata.experimental import whois
from registrata.wire import LineReader

BANNER = b"%rwhois V-1.5:000000:00 slow.test registrata 1.0\r\n"
RESPONSE = [
    b"domain:Domain-Name:example.com\r\n",
    b"domain:Registrar:Test\r\n",
    b"%ok\r\n",
]

#: The bound under test.
DEADLINE = 0.5
#: Each line of the honest response lands well inside DEADLINE, but the exchange as a whole
#: runs past it -- which is the point. A total budget would kill this transfer; a per-line
#: budget cannot tell it apart from a healthy one.
SLOW_LINE_GAP = 0.35
#: Loose against DEADLINE so a loaded machine cannot make the ceiling look broken, and tiny
#: against "never", which is the thing actually being asserted.
BOUND = 6.0

Feed = Callable[[socket.socket, threading.Event], None]


def serve(feed: Feed) -> tuple[socket.socket, threading.Thread, threading.Event]:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    stop = threading.Event()

    def loop() -> None:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(0.5)
                try:
                    feed(conn, stop)
                except OSError:
                    pass  # the client gave up, which is the point of the test

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return listener, thread, stop


def drain_request(conn: socket.socket) -> None:
    try:
        conn.recv(4096)
    except OSError:
        pass


def answer_negotiation(conn: socket.socket) -> None:
    """Consume the client's ``-holdconnect on`` and answer it, so the next read is the real query.

    The client negotiates a held session at connect time, because the server's default closes
    after one query. A feed that skipped this would answer the negotiation with response lines and
    the test would measure something else entirely.
    """
    try:
        request = conn.recv(4096)
    except OSError:
        return
    if b"-holdconnect" in request:
        conn.sendall(b"%ok\r\n")


def dribbles_banner_then_bytes(conn: socket.socket, stop: threading.Event) -> None:
    """A well-formed banner, then a response line that never ends."""
    conn.sendall(BANNER)
    answer_negotiation(conn)
    while not stop.is_set():
        conn.sendall(b"x")
        time.sleep(0.02)


def dribbles_bytes(conn: socket.socket, stop: threading.Event) -> None:
    drain_request(conn)
    while not stop.is_set():
        conn.sendall(b":")
        time.sleep(0.02)


def answers_slowly(conn: socket.socket, stop: threading.Event) -> None:
    """Slow in aggregate, honest line by line -- what the per-line bound must not break."""
    conn.sendall(BANNER)
    answer_negotiation(conn)
    for line in RESPONSE:
        if stop.is_set():
            return
        conn.sendall(line)
        time.sleep(SLOW_LINE_GAP)


def call_within(seconds: float, fn: Callable[[], object]) -> object:
    """Run ``fn`` off the main thread so a missing bound fails the test instead of hanging it.

    This matters more than it looks. Deleting the deadline from the client does not, by itself,
    make the tests below fail: nothing raises, so ``pytest.raises`` waits forever and CI hangs
    on a green-looking test instead of reporting. The watchdog turns "never returned" into an
    ordinary assertion failure, and does it inside the caller so the server is still cleaned up.
    """
    box: dict[str, object] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the main thread below
            box["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise AssertionError(
            f"call did not return within {seconds}s; the bound is not enforced"
        )
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return box["value"]


def with_server(feed: Feed, body):
    listener, thread, stop = serve(feed)
    try:
        return body(listener.getsockname()[1])
    finally:
        stop.set()
        listener.close()
        thread.join(2)


def test_a_dribbled_response_line_is_abandoned() -> None:
    def body(port: int) -> float:
        def attempt() -> None:
            with pytest.raises(TimeoutError):
                with RwhoisClient("127.0.0.1", port=port, timeout=DEADLINE) as client:
                    client.query("domain", "example.com")

        started = time.monotonic()
        call_within(BOUND, attempt)
        return time.monotonic() - started

    elapsed = with_server(dribbles_banner_then_bytes, body)
    assert elapsed < BOUND, f"the read ran {elapsed:.1f}s against a {DEADLINE}s timeout"


def test_a_dribbled_whois_response_is_abandoned_and_reports_why() -> None:
    def body(port: int) -> tuple[float, whois.WhoisResult]:
        started = time.monotonic()
        result = call_within(
            BOUND,
            lambda: whois.whois_query(
                "example.com", "127.0.0.1", port=port, timeout=DEADLINE
            ),
        )
        return time.monotonic() - started, result

    elapsed, result = with_server(dribbles_bytes, body)
    assert elapsed < BOUND, f"the read ran {elapsed:.1f}s against a {DEADLINE}s timeout"
    assert not result.ok
    assert "exceeded" in (result.error or ""), result.error


def test_a_slow_server_that_finishes_its_lines_still_answers() -> None:
    """The positive control, and it is built to bite.

    Each line arrives inside the deadline while the exchange as a whole runs past it, so this
    passes under a per-line bound and would fail under a per-response total. Without that
    property the cheapest way to satisfy the dribble tests would be a total budget tight enough
    to fail real transfers, and the suite would stay green while the client stopped working
    against slow-but-honest servers.
    """

    def body(port: int) -> tuple[float, object]:
        started = time.monotonic()
        with RwhoisClient("127.0.0.1", port=port, timeout=DEADLINE) as client:
            result = client.query("domain", "example.com", raise_errors=False)
        return time.monotonic() - started, result

    elapsed, result = with_server(answers_slowly, body)
    assert elapsed > DEADLINE, (
        f"the exchange finished in {elapsed:.2f}s, inside one line budget, so this test no "
        "longer distinguishes a per-line bound from a per-response total"
    )
    assert elapsed < BOUND
    assert getattr(result, "ok", False) is True, (
        f"slow-but-valid response rejected: {result!r}"
    )


class DribblingSocket:
    """Stands in for a peer whose recv always returns something and never an EOF."""

    def recv(self, size: int) -> bytes:
        return b"x"


def test_a_reader_without_a_deadline_imposes_none() -> None:
    """The server side shares LineReader and keeps its own idle-timeout policy instead."""
    assert LineReader(DribblingSocket()).line_deadline_seconds is None  # type: ignore[arg-type]


def test_a_reader_with_a_deadline_stops_waiting_for_a_line() -> None:
    reader = LineReader(DribblingSocket(), line_deadline_seconds=0.05)  # type: ignore[arg-type]

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        reader.readline()
    assert time.monotonic() - started < 2.0
