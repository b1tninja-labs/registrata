import socket
import threading
import time

import pytest

from registrata import RwhoisClient, RwhoisServer
from registrata.backends.memory import MemoryBackend


@pytest.fixture
def backend():
    backend = MemoryBackend("example.com")
    backend.add_soa("example.com", primary="127.0.0.1:4321")
    backend.add_object(
        "domain",
        {
            "Class-Name": "domain",
            "Auth-Area": "example.com",
            "ID": "dom-1.example.com",
            "Updated": "19970107201111000",
            "Domain-Name": "example.com",
            "Server": ("I", "hst-1.example.com"),
        },
        auth_area="example.com",
    )
    return backend


@pytest.fixture
def server(backend):
    server = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=5
    )
    host, port = server.start()
    yield host, port, server
    server.shutdown()


def test_server_returns_banner(server):
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        assert client.banner is not None
        assert client.banner.host == "127.0.0.1"


def test_query_objects(server):
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        result = client.query("domain", "example.com")
    assert result.ok
    assert result.objects[0].id == "dom-1.example.com"
    assert result.objects[0].getall("Server") == ["hst-1.example.com"]


def test_no_objects_error(server):
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        result = client.query("domain", "not-here.com", raise_errors=False)
    assert result.error_code == 230
    assert not result.objects


def test_a_query_naming_an_unknown_class_is_refused_as_invalid_class(server):
    """341 for a class the server has never heard of, 230 for one it has and no match in.

    Section 4 lists 341 among the errors a query may return. Both of these used to answer 230,
    which made a typo in a class name indistinguishable from a resource that does not exist -- and
    the client treats 230 as an answer and 341 as a failure, so the server was reporting a broken
    query as information about the world.
    """
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        unknown_class = client.query("nosuchclass", "example.com", raise_errors=False)
        absent = client.query("domain", "nosuch.example.com", raise_errors=False)

    assert unknown_class.error_code == 341
    assert absent.error_code == 230, "an empty answer has to stay an answer"


def test_a_refused_query_closes_the_connection_like_any_other(server):
    """The default close applies to error answers too, not only to a successful one.

    Both early exits from query handling -- a syntactically invalid query and a refused class --
    answered and then held the socket open, because only the fall-through path armed the close. A
    client that never asked to hold the session should not wait for the idle timeout to learn it
    was refused.
    """
    host, port, _ = server
    for request in ("domain=", "nosuchclass domain=example.com"):
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.recv(4096)  # the banner, which the server owes us on connect
            answer = _ask(sock, request)
            assert answer.startswith(b"%error"), request
            assert _wait_for_close(sock), f"{request!r} was answered and then left the socket open"


def test_limit_exceeded_error(server):
    host, port, server_obj = server
    server_obj.backend.add_object(
        "domain",
        {
            "Class-Name": "domain",
            "Auth-Area": "example.com",
            "ID": "dom-2.example.com",
            "Updated": "19970107201111000",
            "Domain-Name": "example2.com",
        },
        auth_area="example.com",
    )
    with RwhoisClient.connect(host, port, timeout=5) as client:
        client.limit(1)
        result = client.query("domain", "example*", raise_errors=False)
    assert result.error_code == 330
    assert len(result.objects) == 1


def test_status_soa_and_schema_directives(server):
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        status = client.status()
        # "on": RFC 2167 section 3.1.4 holds the connection open for further queries unless the
        # client asks otherwise, so this is the session default rather than something a client
        # has to request. It read "OFF" while the server closed after every query.
        assert status.status_dict["holdconnect"] == "ON"

        soa = client.soa("example.com")
        assert soa.soa[0].authority == "example.com"

        schema = client.schema("example.com", "domain")
        assert schema.schema_classes[0].class_name == "domain"


def test_holdconnect_allows_multiple_queries(server):
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        client.holdconnect(True)
        first = client.query("domain", "example.com")
        client.limit(5)
        second = client.query_attribute("domain", "Domain-Name", "example.com")
        client.quit()
    assert first.ok
    assert second.ok


def _ask(sock: socket.socket, request: str) -> bytes:
    sock.sendall(request.encode() + b"\r\n")
    try:
        return sock.recv(65536)
    except (TimeoutError, OSError):
        return b""


def _wait_for_close(sock: socket.socket, timeout: float = 3.0) -> bool:
    """True if the peer ended the connection, False if it stayed open.

    Drains rather than reading once: a response can arrive split across reads, and treating the
    second chunk as "still open" would fail on correct behaviour.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(65536)
        except ConnectionError:
            return True  # Windows reports a reset where others report a clean EOF
        except TimeoutError:
            return False  # quiet, but open: this is the failure the test is looking for
        if chunk == b"":
            return True
    return False


def test_the_server_closes_after_one_query_by_default(server):
    """Section 3.3.5: "By default, the holdconnect state must be set to off for each connection."

    Raw sockets, deliberately. ``RwhoisClient`` now asks for a held session on the caller's
    behalf, so a client-based test cannot observe what the server does when nobody asks -- which
    is precisely how the previous wrong default survived.
    """
    host, port, _ = server
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(3)
        assert sock.recv(4096).startswith(b"%rwhois")

        # Directives do not arm the close, so the state is readable before the query consumes it.
        assert b"holdconnect:OFF" in _ask(sock, "-status")

        _ask(sock, "domain:Domain-Name:example.com")
        assert _wait_for_close(sock), (
            "the server kept a connection open nobody asked it to hold"
        )


def test_a_client_session_survives_multiple_queries(server):
    """The ergonomics the old default bought, now earned by asking rather than overriding the spec."""
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        assert client.session_held is True
        first = client.query("domain", "example.com")
        second = client.query_attribute("domain", "Domain-Name", "example.com")

    assert first.ok and second.ok
    assert first.objects[0].id == second.objects[0].id


def test_a_client_that_declines_to_negotiate_gets_the_specified_default(server):
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5, hold_connect=False) as client:
        assert client.session_held is None
        assert client.status().status_dict["holdconnect"] == "OFF"
        assert client.query("domain", "example.com").ok
        with pytest.raises(ConnectionError):
            client.query("domain", "example.com")


def test_a_server_that_refuses_holdconnect_still_serves_one_query() -> None:
    """400 is a lawful answer, so the client records the refusal instead of failing the session."""
    banner = b"%rwhois V-1.5:000000:00 127.0.0.1 refusing 1.0\r\n"
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        with conn:
            conn.sendall(banner)
            conn.settimeout(3)
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        return
                    if b"-holdconnect" in data:
                        conn.sendall(b"%error 400 Directive not available\r\n")
                    else:
                        conn.sendall(b"%ok\r\n")
            except OSError:
                return

    threading.Thread(target=serve, daemon=True).start()
    try:
        with RwhoisClient.connect(
            "127.0.0.1", listener.getsockname()[1], timeout=3
        ) as client:
            assert client.session_held is False
            response = client.status()
        assert response.ok
    finally:
        listener.close()


def test_holdconnect_off_closes_after_the_next_response(server):
    """The opt-out has to actually opt out, not merely report a different status."""
    host, port, _ = server
    client = RwhoisClient.connect(host, port, timeout=5)
    try:
        # ON here is the client's own negotiation at connect time, not the server's default --
        # test_a_client_that_declines_to_negotiate_gets_the_specified_default pins the other case.
        assert client.status().status_dict["holdconnect"] == "ON"

        client.holdconnect(False)
        # Directives never arm the close, so status is still readable here; it is the next query
        # that consults the flag and closes.
        assert client.status().status_dict["holdconnect"] == "OFF"

        # This response is the last thing the server sends.
        assert client.query("domain", "example.com").ok
        with pytest.raises(ConnectionError):
            client.query("domain", "example.com")
    finally:
        client.close()


@pytest.fixture
def idle_server():
    """A server that gives up quickly, so the idle path is testable in about a second."""
    backend = MemoryBackend("example.com")
    backend.add_soa("example.com", primary="127.0.0.1:4321")
    app = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=1
    )
    host, port = app.start()
    try:
        yield host, port
    finally:
        app.shutdown()


def test_idle_timeout_is_reported_then_the_connection_closed(idle_server):
    """A silent client gets ``%error 115``, unprompted and then nothing at all.

    Read on a raw socket rather than through RwhoisClient because the interesting message is
    server-initiated: every client method writes a command before it reads, and the point is
    that the server speaks first when its timer expires.
    """
    host, port = idle_server
    sock = socket.create_connection((host, port), timeout=8)
    try:
        reader = sock.makefile("rb")
        assert reader.readline().startswith(b"%rwhois ")

        line = reader.readline()

        # 503 per RFC 2167 Appendix C ("503  Idle time exceeded"), not a code the implementation
        # picked.
        assert line.startswith(b"%error 503"), line
        assert reader.readline() == b"", "the server should close after idle timeout"
    finally:
        sock.close()
