from registrata.backends.json_store import load_memory_backend, save_memory_backend
from registrata.backends.memory import MemoryBackend


def test_save_and_load_memory_backend(tmp_path):
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
    path = tmp_path / "rwhois.json"
    save_memory_backend(backend, path)

    loaded = load_memory_backend(path)
    assert loaded.list_authority_areas() == ["example.com"]
    objs = loaded.all_objects()
    assert len(objs) == 1
    assert objs[0].id == "dom-1.example.com"
    assert objs[0].getall("Server") == ["hst-1.example.com"]
