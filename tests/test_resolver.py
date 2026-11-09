import pytest

from registrata import RwhoisResolver, RwhoisServer
from registrata.backends.memory import MemoryBackend


@pytest.fixture
def child_server():
    backend = MemoryBackend("child.example.com")
    backend.add_soa("child.example.com", primary="127.0.0.1:4323")
    backend.add_object(
        "domain",
        {
            "Class-Name": "domain",
            "Auth-Area": "child.example.com",
            "ID": "dom.child.example.com",
            "Updated": "19970107201111000",
            "Domain-Name": "child.example.com",
        },
        auth_area="child.example.com",
    )
    server = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=5
    )
    host, port = server.start()
    yield host, port, server
    server.shutdown()


def test_resolver_follows_link_referrals(child_server):
    _, child_port, _ = child_server
    parent_backend = MemoryBackend("example.com")
    parent_backend.add_soa("example.com", primary="127.0.0.1:4321")
    parent_backend.add_referral(
        "child.example.com", "127.0.0.1", child_port, auth_area="child.example.com"
    )
    parent = RwhoisServer(
        parent_backend,
        host="127.0.0.1",
        port=0,
        server_name="127.0.0.1",
        idle_timeout=5,
    )
    host, port = parent.start()
    try:
        result = RwhoisResolver(host, port, timeout=5).resolve(
            "child.example.com", class_name="domain"
        )
        assert result.objects[0].id == "dom.child.example.com"
        assert any(referral.port == child_port for referral, _ in result.path)
    finally:
        parent.shutdown()
