import pytest

from registrata.backends.memory import MemoryBackend
from registrata.capabilities import Capability
from registrata.conformance import check_server


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
        },
        auth_area="example.com",
    )
    return backend


def test_check_server_reports_ok_on_local_memory_server(backend):
    from registrata import RwhoisServer

    server = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=5
    )
    host, port = server.start()
    try:
        report = check_server(
            host, port, timeout=5, query_class="domain", query_text="example.com"
        )
    finally:
        server.shutdown()

    assert report.ok
    assert report.score > 0.8
    assert report.banner is not None
    assert report.capabilities & Capability.STATUS
    assert report.capabilities & Capability.SOA
    statuses = {item.name: item.status for item in report.items}
    assert statuses["banner"] == "pass"
    assert statuses["directive:status"] == "pass"
    assert statuses["directive:soa"] == "pass"
    assert statuses["query"] == "pass"
    assert report.as_dict()["items"]


def test_check_server_records_connection_failure():
    report = check_server("127.0.0.1", 1, timeout=0.2)
    assert not report.ok
    assert report.fatal
