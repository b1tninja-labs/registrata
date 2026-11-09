"""Framing integrity: what the server writes must be the lines it meant to write.

The grammar tests stop at ``parse_response(lines)``. That skips the layer where protocol
identity actually lives. An RWhois response is a sequence of CRLF-terminated octet lines, so
a value carrying a CR or LF turns one intended line into two, and the injected line is
parsed by the client as if the server had sent it deliberately. The payload that can carry
it is *registry data being served* -- a zone import, a database row, an operator-supplied
banner -- not the client's request, which the wire reader has already line-delimited.

The worst case is not a garbled record but an early ``%ok``: ``read_until`` ends on the first
line beginning with the terminator, so injecting one truncates the response and lets what
follows be attributed to a different query.

These tests drive the server's own emission path and read the bytes back through the
client-side ``LineReader``, because the property worth having is "what went out is what
comes back", not "the parser tolerates a list of strings".
"""

from __future__ import annotations

import random
import socket

import pytest

from registrata import RwhoisClient
from registrata.backends.memory import MemoryBackend
from registrata.errors import (
    RwhoisError,
    format_error_line,
    parse_error_line,
)
from registrata.records import AttributeLine
from registrata.schema import SchemaClass
from registrata.server import RwhoisRequestHandler, RwhoisServer
from registrata.wire import LineReader

# The alphabets and generators live with the grammar properties so there is one transcription
# of each production, not a second one here to drift. pytest puts this directory on sys.path
# for test modules, which is what makes the import work without packaging tests/.
from test_rwhois_property import (
    gen_attribute_value,
    gen_id,
    seeded,
)


class Recorder:
    """A stand-in peer that keeps whatever the handler writes and reports whether it wrote."""

    def __init__(self) -> None:
        self.buffers: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.buffers.append(bytes(data))

    @property
    def payload(self) -> bytes:
        return b"".join(self.buffers)


class FakeSocket:
    """Just enough socket for ``LineReader``: recv() drains a buffer, then reports EOF.

    Deliberately small reads, so the reader has to reassemble a line across chunks the way
    it would off a real connection; a framing bug that only appears when a CRLF straddles a
    recv boundary is still a framing bug.
    """

    def __init__(self, payload: bytes, *, chunk: int = 7) -> None:
        self._pending = bytearray(payload)
        self._chunk = chunk

    def recv(self, _size: int) -> bytes:
        if not self._pending:
            return b""
        take = bytes(self._pending[: self._chunk])
        del self._pending[: self._chunk]
        return take

    def close(self) -> None:
        self._pending.clear()


def emit(lines: list[str]) -> Recorder:
    """Send ``lines`` through the handler's real emission path, no socket involved.

    ``__new__`` rather than ``__init__``: BaseRequestHandler's constructor accepts a
    connection and runs setup/handle/finish immediately, which would want a live socket and a
    thread for a test that only needs to know what bytes come out.
    """
    handler = RwhoisRequestHandler.__new__(RwhoisRequestHandler)
    handler.request = Recorder()
    handler.send_lines(lines)
    return handler.request


def read_lines(payload: bytes) -> list[str]:
    reader = LineReader(FakeSocket(payload))  # type: ignore[arg-type]
    out: list[str] = []
    try:
        while True:
            out.append(reader.readline())
    except ConnectionError:
        pass
    finally:
        reader.close()
    return out


# --------------------------------------------------------------- the round trip ------


@pytest.mark.parametrize("seed", range(40))
def test_what_the_server_writes_is_what_the_client_reads(seed: int) -> None:
    """Line count and line content survive emission plus the wire reader, byte for byte.

    This is the interop property the grammar tests skip: the client should reassemble exactly
    the sequence the server intended, including 8-bit octets, tabs, colons and percent signs
    inside values, which is what ``any-char`` actually permits.
    """
    rng = seeded("framing", seed)
    class_name = gen_id(rng)
    lines = [
        AttributeLine(gen_id(rng), gen_attribute_value(rng), rng.choice("TIS")).to_wire(
            class_name
        )
        for _ in range(rng.randint(1, 4))
    ]

    payload = emit(lines).payload

    assert payload.endswith(b"\r\n")
    assert read_lines(payload) == lines


@pytest.mark.parametrize("seed", range(20))
def test_eight_bit_octets_survive_the_wire(seed: int) -> None:
    """RFC 2167 section 3.1.9 makes the protocol 8-bit, so latin-1 must be lossless.

    An encoder that substituted or dropped high octets would silently corrupt names from
    every non-ASCII registry, and the corruption would be invisible to a parser reading the
    same bytes back.
    """
    rng = seeded("eight-bit", seed)
    value = "".join(chr(rng.randint(0x80, 0xFF)) for _ in range(rng.randint(1, 12)))
    line = f"domain:{gen_id(rng)}:{value}"

    payload = emit([line]).payload

    assert b"?" not in payload
    assert read_lines(payload) == [line]


def test_record_separator_and_terminator_keep_their_positions() -> None:
    """A blank line stays a blank line, and ``%ok`` stays the last line.

    Object boundaries are blank lines, so a framing change that swallowed or duplicated one
    would merge two objects into one, and no parser could notice.
    """
    lines = ["domain:Name:one", "domain:Name:two", "", "network:Name:three", "%ok"]

    read_back = read_lines(emit(lines).payload)

    assert read_back == lines
    assert read_back.index("%ok") == len(read_back) - 1


def test_an_injected_terminator_truncates_a_client_read() -> None:
    """Why the guard below matters, demonstrated rather than asserted.

    ``read_until`` stops at the first line beginning with a terminator, so a ``%ok`` that
    arrives early ends the response there and everything after it is attributed to the next
    query. Hand-building the bytes shows the consequence at the reader, independent of whether
    the server can currently produce them.
    """
    smuggled = b"domain:Name:real\r\n%ok\r\ndomain:Name:stolen\r\n"

    collected = list(LineReader(FakeSocket(smuggled)).read_until(("%ok",)))  # type: ignore[arg-type]

    assert collected == ["domain:Name:real", "%ok"]
    assert "domain:Name:stolen" not in collected


# ------------------------------------------------------------- framing integrity -----

BREAKERS = [
    "\r\n%ok",
    "\r\n",
    "\n",
    "\r",
    "x\r\n%error 200 forged",
    "\n\n",
]


@pytest.mark.parametrize("breaker", BREAKERS)
def test_a_line_break_in_a_served_line_is_refused_before_anything_is_written(
    breaker: str,
) -> None:
    """No accepted call may add a line to the response.

    The guard belongs at emission rather than in each caller: the values reaching
    ``send_lines`` come from backends, directive descriptions and operator configuration, and
    asking every one of them to remember the rule is how the rule gets missed.
    """
    with pytest.raises(RwhoisError):
        emit([f"domain:Name:{breaker}"])


@pytest.mark.parametrize("breaker", BREAKERS)
def test_refusal_leaves_nothing_on_the_socket(breaker: str) -> None:
    """Nothing may be written before the refusal either.

    A partial write followed by an exception leaves the peer holding a response that looks
    complete right up to the point where it is not -- the failure mode this file exists for, so
    the good line in the same batch must not escape either.
    """
    handler = RwhoisRequestHandler.__new__(RwhoisRequestHandler)
    handler.request = Recorder()

    with pytest.raises(RwhoisError):
        handler.send_lines(["domain:Name:good", f"domain:Name:{breaker}"])

    assert handler.request.payload == b""


@pytest.mark.parametrize("field", ["server_name", "implementation"])
def test_operator_supplied_banner_fields_are_validated_at_construction(
    field: str,
) -> None:
    """Bad configuration fails at startup, not on the first connection.

    Both fields land in the banner, which is written during ``setup()``. Before this check they
    produced a server that accepted a client and then hung up -- which looks like a network fault
    or an attack, and never points at the config line responsible.
    """
    with pytest.raises(RwhoisError):
        RwhoisServer(object(), **{field: "host.example.net\r\n%error 200 forged"})  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["server_name", "implementation"])
def test_a_banner_field_that_bypassed_construction_still_cannot_inject(
    field: str,
) -> None:
    """The emission guard stays the backstop, so the constructor is not load-bearing.

    Attributes can be set after ``__init__`` by anything holding the server -- a test fixture, a
    reload path, a subclass -- and a wire rule enforced only in a constructor is not enforced.
    """
    app = RwhoisServer(object(), server_name="ok.example.net")  # type: ignore[arg-type]
    setattr(app, field, "host.example.net\r\n%error 200 forged")

    with pytest.raises(RwhoisError):
        emit([app.banner_line()])


def test_error_text_cannot_inject_a_line_either() -> None:
    """``send_error`` interpolates text onto the wire, frequently an exception message."""
    handler = RwhoisRequestHandler.__new__(RwhoisRequestHandler)
    handler.request = Recorder()

    with pytest.raises(RwhoisError):
        handler.send_error(230, "no objects\r\n%ok forged")

    assert handler.request.payload == b""


# ---------------------------------------------------------------- parity of copies ---


@pytest.mark.parametrize("code", [30, 99, 100, 230, 999])
def test_server_error_lines_match_the_public_formatter(code: int) -> None:
    """The server must format errors with ``format_error_line``, not its own copy.

    It used to interpolate the code inline, which meant the zero-padding fix made
    ``%error 030`` parseable in the library but not on the server: answering with a code below
    100 still emitted a line no client, including this one, could parse. Two copies of a wire
    format drift, so the copy is asserted against the original.
    """
    handler = RwhoisRequestHandler.__new__(RwhoisRequestHandler)
    handler.request = Recorder()

    handler.send_error(code, "detail text")

    expected = format_error_line(code, "detail text") + "\r\n"
    assert handler.request.payload.decode("latin-1") == expected
    assert parse_error_line(format_error_line(code, "detail text"))[0] == code


def test_emission_actually_terminates_lines() -> None:
    """Anti-vacuity: the guard must not be satisfied by writing nothing at all.

    A ``send_lines`` that raised unconditionally, or that dropped the CRLF, would keep every
    refusal test above green while serving nothing.
    """
    assert emit(["%ok"]).payload == b"%ok\r\n"


# ------------------------------------------------------ end to end, over a real socket ---


def hostile_value(rng: random.Random) -> str:
    """A registry value that is legal per ``any-char`` and awkward on the wire.

    These are the bytes that break a naive implementation: a value that reads like the
    terminator, high octets that an encoder might mangle, and separators that a splitter
    might consume. None of them may change what the peer parses.
    """
    pick = rng.random()
    if pick < 0.15:
        return "%ok"
    if pick < 0.30:
        return "%error 200 forged"
    if pick < 0.45:
        return "".join(chr(rng.randint(0x80, 0xFF)) for _ in range(rng.randint(2, 8)))
    if pick < 0.60:
        return 'a\tb:c;d%e"f'
    if pick < 0.75:
        return " " + gen_id(rng) + " "
    return gen_attribute_value(rng).replace("\r", "").replace("\n", "") or "x"


@pytest.fixture(scope="module")
def served():
    """A real listening server holding one generated awkward value per seed.

    Module scoped: a thread and a socket per test would dominate the runtime of a suite that
    is already slow, and every case below reads through the same server.
    """
    backend = MemoryBackend("example.com")
    backend.add_soa("example.com", primary="127.0.0.1:4321")
    handles: dict[str, str] = {}
    for index in range(24):
        value = hostile_value(seeded("loopback", index))
        handle = f"handle-{index}.example.com"
        backend.add_object(
            "domain",
            {
                "Class-Name": "domain",
                "Auth-Area": "example.com",
                "ID": handle,
                "Domain-Name": value,
            },
            auth_area="example.com",
        )
        handles[handle] = value

    # Added explicitly rather than left to chance: without one of these the terminator test
    # below would quietly have nothing to assert about.
    for index, value in enumerate(("%ok", "%ok forged", "%okay")):
        handle = f"terminator-{index}.example.com"
        backend.add_object(
            "domain",
            {
                "Class-Name": "domain",
                "Auth-Area": "example.com",
                "ID": handle,
                "Domain-Name": value,
            },
            auth_area="example.com",
        )
        handles[handle] = value

    app = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=5
    )
    host, port = app.start()
    try:
        yield host, port, handles
    finally:
        app.shutdown()


def test_generated_values_survive_a_real_round_trip(served) -> None:
    """Insert a value, serve it, read it back through the client: byte for byte.

    This is the whole chain at once -- backend, record serialization, framing, socket, wire
    reader, parser -- which is where an 8-bit value or a tab would actually get mangled, and
    no single-layer test would notice.
    """
    host, port, handles = served
    problems: list[str] = []

    with RwhoisClient.connect(host, port, timeout=10) as client:
        for handle, expected in sorted(handles.items()):
            result = client.query_attribute("domain", "ID", handle, raise_errors=False)
            got = result.objects[0].get("Domain-Name") if result.objects else None
            if not result.ok:
                problems.append(
                    f"{handle}: not ok, error={result.error_code} {result.error_text!r}"
                )
            elif got != expected:
                problems.append(f"{handle}: sent {expected!r} received {got!r}")

    assert not problems, "\n".join(problems)


def test_values_that_read_like_the_terminator_end_exactly_one_response(served) -> None:
    """An object whose value starts with ``%ok`` must not end the response early.

    ``read_until`` matches on ``startswith``, and an attribute line always begins with the
    class name, so the prefix is what protects the protocol here. Worth pinning: a serializer
    that ever emitted a bare value, or trimmed the class prefix first, would turn a registry
    value into a response terminator, and the client would see a short answer rather than an
    error.
    """
    host, port, handles = served
    targets = sorted(
        handle for handle, value in handles.items() if value.startswith("%ok")
    )
    assert targets, "the fixture stopped serving a value that reads like the terminator"

    with RwhoisClient.connect(host, port, timeout=10) as client:
        for target in targets:
            result = client.query_attribute("domain", "ID", target, raise_errors=False)

            assert result.ok, (
                f"{target}: error {result.error_code} {result.error_text!r}"
            )
            assert len(result.objects) == 1, (
                f"{target}: value {handles[target]!r} produced "
                f"{len(result.objects)} objects, so the response was split or truncated"
            )
            assert result.objects[0].get("Domain-Name") == handles[target]


@pytest.mark.parametrize("breaker", BREAKERS)
def test_a_backend_row_cannot_carry_a_line_break(breaker: str) -> None:
    """The chain has two guards, and the first one is construction.

    A row containing CR or LF is refused before it can be stored, so nothing downstream has to
    trust it; ``send_lines`` refusing to emit one is the second guard for data that arrives as
    raw strings. Either alone leaves a way through.
    """
    with pytest.raises(RwhoisError):
        MemoryBackend("example.net").add_object(
            "domain",
            {"ID": "x.example.net", "Domain-Name": f"a{breaker}b"},
            auth_area="example.net",
        )


# ------------------------------------------------- operator extensions, over sockets ---


def raw_exchange(
    host: str, port: int, commands: list[str], *, timeout: float = 5.0
) -> list[str]:
    """Send commands on a plain socket and return every line the server sends back.

    Raw rather than through ``RwhoisClient`` deliberately: the claim is about *which lines
    arrive*, and a client that stops at an injected terminator would hide the very injection
    being tested. The banner is included as the first element.
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        reader = sock.makefile("rb")
        lines = [reader.readline().rstrip(b"\r\n").decode("latin-1")]
        for command in commands:
            sock.sendall(command.encode("latin-1") + b"\r\n")
            while True:
                raw = reader.readline()
                if not raw:
                    return lines
                line = raw.rstrip(b"\r\n").decode("latin-1")
                lines.append(line)
                if line == "%ok" or line.startswith("%error"):
                    break
        return lines
    finally:
        sock.close()


BENIGN_LINES = ["x-note:caf\xc3\xa9", 'x-note:a\tb:c;d%e"f', "x-note:%ok"]

EVIL_LINES = ["x-note:legit", "forged\r\n%error 200 pwned"]


@pytest.fixture(scope="module")
def extension_server():
    """A conforming server whose `-x-` extensions return unvalidated operator strings.

    This is the path the emission guard exists for: an x handler is arbitrary operator code
    handed a ``list[str]`` that is written to the socket as-is, with no record, no
    ``AttributeLine``, and therefore no construction-time check in front of it.
    """
    backend = MemoryBackend("example.com")
    backend.add_soa("example.com", primary="127.0.0.1:4321")

    def benign(rest: str, state: object) -> list[str]:
        return list(BENIGN_LINES)

    def evil(rest: str, state: object) -> list[str]:
        return list(EVIL_LINES)

    app = RwhoisServer(
        backend,
        host="127.0.0.1",
        port=0,
        server_name="127.0.0.1",
        idle_timeout=5,
        x_handlers={"benign": benign, "evil": evil},
    )
    host, port = app.start()
    try:
        yield host, port
    finally:
        app.shutdown()


def test_extension_output_survives_the_wire_when_well_formed(extension_server) -> None:
    """Extension lines reach the peer unchanged, including the awkward ones."""
    host, port = extension_server

    lines = raw_exchange(host, port, ["-x-benign"])

    assert "%ok" in lines
    for expected in BENIGN_LINES:
        assert expected in lines, f"{expected!r} did not arrive intact: {lines}"


def test_extension_output_cannot_inject_a_line_into_a_real_session(
    extension_server,
) -> None:
    """A line break in operator output forges nothing, and the session survives to say so.

    Three separate claims, because the failure modes differ:

    - the forged line never arrives -- that is the injection itself;
    - the batch's first line never arrives either, since ``send_lines`` encodes everything
      before writing anything, so a refusal cannot leave a partial response behind;
    - the client gets ``%error 402``, which is Appendix C's "Unidentified error". Without a
      refusal the peer would simply see a reset: safe, but indistinguishable from a network
      fault, and the operator's bug would be invisible to whoever hit it.

    The follow-up ``-status`` proves the connection was not torn down by the refusal.
    """
    host, port = extension_server

    lines = raw_exchange(host, port, ["-x-evil", "-status"])

    assert "%error 200 pwned" not in lines, f"forged line reached the client: {lines}"
    assert "x-note:legit" not in lines, f"partial batch reached the client: {lines}"
    assert any(line.startswith("%error 402") for line in lines), lines
    assert any(line.startswith("%status") for line in lines), (
        "the session did not survive"
    )
    assert "%ok" in lines, "the surviving session should still terminate a response"


def test_unknown_extension_reports_directive_not_available(extension_server) -> None:
    """Appendix C's "400 Directive not available", pinned so the code cannot drift silently."""
    host, port = extension_server

    lines = raw_exchange(host, port, ["-x-nosuchhandler"])

    assert any(line.startswith("%error 400") for line in lines), lines


@pytest.fixture(scope="module")
def poisoned_soa_server():
    """A server whose SOA record arrived through the backend rather than an extension.

    ``add_soa`` stores the authority string as given and ``_do_soa`` renders the record with
    f-strings before handing the lines to ``send_lines``, so this is a second raw path. It exists
    to prove the refusal policy is central rather than something only the extension route
    remembers.
    """
    backend = MemoryBackend("example.com")
    backend.add_soa("example.com\r\n%error 200 forged", primary="127.0.0.1:4321")
    app = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=5
    )
    host, port = app.start()
    try:
        yield host, port
    finally:
        app.shutdown()


def test_backend_data_cannot_inject_a_line_either(poisoned_soa_server) -> None:
    """The same refusal, on a path that never touches operator extension code.

    Nothing forged arrives, and the client is told why in a form it can act on -- Appendix C's
    402 -- rather than being left with a closed connection. ``-status`` afterwards shows the
    session survived the refusal, which is what makes this recoverable for a resolver with
    several zones to walk rather than a dead socket per bad record.
    """
    host, port = poisoned_soa_server

    lines = raw_exchange(host, port, ["-soa", "-status"])

    assert "%error 200 forged" not in lines, f"forged line reached the client: {lines}"
    assert not any(line.startswith("%soa") for line in lines), (
        f"partial SOA group sent: {lines}"
    )
    assert any(line.startswith("%error 402") for line in lines), lines
    assert any(line.startswith("%status") for line in lines), (
        "the session did not survive"
    )


@pytest.fixture(scope="module")
def poisoned_schema_server():
    """A class whose description arrived through the schema, not through an extension.

    ``SchemaClass.to_class_lines`` is f-strings over ``description`` and ``extra``, neither of
    which is validated, so this is a third source of raw strings reaching the wire.
    """
    backend = MemoryBackend("example.com")
    backend.add_soa("example.com", primary="127.0.0.1:4321")
    backend.add_class(
        "example.com",
        SchemaClass(class_name="domain", description="domain\r\n%error 200 forged"),
    )
    app = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=5
    )
    host, port = app.start()
    try:
        yield host, port
    finally:
        app.shutdown()


def test_schema_descriptions_cannot_inject_a_line_either(
    poisoned_schema_server,
) -> None:
    """Three different data sources, one policy: extension output, SOA rows, schema text.

    Asserted per source rather than trusting that the central handler makes them equivalent,
    because what varies between them is whether anything validates the value on the way in --
    and a path that looks safe usually is only until someone adds a field.
    """
    host, port = poisoned_schema_server

    # "-class" takes the authority area first: with no argument it is refused as 338, and with
    # only a class name as 340 Invalid authority area. Both fail before any send happens, which
    # would leave this test passing while proving nothing, so the area is named properly.
    lines = raw_exchange(host, port, ["-class example.com domain", "-status"])

    assert "%error 200 forged" not in lines, f"forged line reached the client: {lines}"
    assert not any(line.startswith("%class") for line in lines), (
        f"partial class group: {lines}"
    )
    assert any(line.startswith("%error 402") for line in lines), lines
    assert any(line.startswith("%status") for line in lines), (
        "the session did not survive"
    )
