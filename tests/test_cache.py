import time

from registrata.cache import JsonFileCache, SQLiteCache, TTLCache, make_cache, make_key


def test_ttl_cache_expires_values(tmp_path=None):
    cache = TTLCache(default_ttl=0.01)
    cache.set("a", {"value": 1})
    assert cache.get("a") == {"value": 1}
    time.sleep(0.02)
    assert cache.get("a") is None


def test_ttl_cache_evicts_lru_entries():
    cache = TTLCache(max_size=2)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.get("a")
    cache.set("c", 3)
    assert cache.get("b") is None
    assert cache.get("a") == 1
    assert cache.get("c") == 3


def test_json_file_cache_roundtrip(tmp_path):
    cache = JsonFileCache(tmp_path, namespace="test")
    key = make_key("whois", "example.com", "whois.example", 43)
    cache.set(key, {"hello": "world"}, ttl=60)
    assert cache.get(key) == {"hello": "world"}
    assert cache.path_for(key).exists()
    assert cache.clear() == 1


def test_sqlite_cache_roundtrip(tmp_path):
    cache = SQLiteCache(tmp_path / "cache.sqlite", namespace="test")
    cache.set("a", {"x": [1, 2]}, ttl=60)
    assert cache.get("a") == {"x": [1, 2]}
    cache.set("b", "expired", ttl=-1)
    assert cache.get("b") is None
    assert cache.clear() == 1


def test_make_cache_backends(tmp_path):
    assert isinstance(make_cache("memory", default_ttl=1), TTLCache)
    assert isinstance(make_cache("file", path=tmp_path), JsonFileCache)
    assert isinstance(make_cache("sqlite", path=tmp_path), SQLiteCache)


def test_json_and_sqlite_caches_serialize_unusual_values(tmp_path):
    class Weird:
        def __str__(self):
            return "weird"

    file_cache = JsonFileCache(tmp_path, namespace="weird")
    file_cache.set("a", {"obj": Weird(), "tuple": (1, 2)})
    assert file_cache.get("a")["obj"] == "weird"
    assert file_cache.get("a")["tuple"] == [1, 2]

    sqlite_cache = SQLiteCache(tmp_path / "cache.sqlite", namespace="weird")
    sqlite_cache.set("b", {"obj": Weird()})
    assert sqlite_cache.get("b") == {"obj": "weird"}
