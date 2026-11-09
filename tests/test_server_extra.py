import pytest

from registrata import RwhoisClient, RwhoisServer
from registrata.backends.memory import MemoryBackend


@pytest.fixture
def server():
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
        },
        auth_area="example.com",
    )
    backend.add_password("secret")
    app = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=5
    )
    host, port = app.start()
    yield host, port, app
    app.shutdown()


def test_register_add_object(server):
    host, port, app = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        # This backend has a password, so it can authenticate, and registration is
        # refused with 401 until the session does. See tests/test_register.py.
        client.security_password("secret")
        reg = client.register(
            "add",
            "maintainer@example.com",
            [
                "Class-Name:domain",
                "Auth-Area:example.com",
                "Domain-Name:added.example.com",
            ],
        )
        assert reg.ok
        assert reg.register
        response = client.query("domain", "added.example.com")
    assert response.objects[0].get("Domain-Name") == "added.example.com"
    assert any(
        obj.get("Domain-Name") == "added.example.com"
        for obj in app.backend.all_objects()
    )


def test_security_password(server):
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        ok = client.security_password("secret")
        assert ok.ok
        bad = client.send_command(
            "-security on request password wrong", raise_errors=False
        )
    assert bad.error_code == 353


def test_xfer_export(server):
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        response = client.send_command(
            "-xfer example.com class=domain attribute=Domain-Name"
        )
    assert response.ok
    assert len(response.xfer_objects) == 1
    assert response.xfer_objects[0].get("Domain-Name") == "example.com"


def test_directive_catalog(server):
    host, port, _ = server
    with RwhoisClient.connect(host, port, timeout=5) as client:
        response = client.directives("limit", "quit")
    names = {group.get("directive") for group in response.directive_groups}
    assert {"limit", "quit"} <= names
