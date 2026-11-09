import pytest

from registrata import RwhoisClient, RwhoisServer
from registrata.backends.memory import MemoryBackend


@pytest.fixture
def child_server():
    backend = MemoryBackend("child.example.com")
    backend.add_soa("child.example.com", primary="127.0.0.1:4322")
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


def test_link_referral_from_parent_to_child(child_server):
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
        with RwhoisClient.connect(host, port, timeout=5) as client:
            result = client.query("domain", "child.example.com", raise_errors=False)
        assert result.ok
        assert len(result.referrals) == 1
        assert result.referrals[0].host == "127.0.0.1"
        assert result.referrals[0].port == child_port
        assert result.referrals[0].auth_area == "child.example.com"
    finally:
        parent.shutdown()
