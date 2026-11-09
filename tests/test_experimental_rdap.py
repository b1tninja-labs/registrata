from registrata.experimental import rdap


def test_resolve_domain_base_longest_match():
    data = {
        "services": [
            [["com"], ["https://rdap.example.com/"]],
            [["foo"], ["https://rdap.foo.invalid/"]],
        ]
    }
    assert rdap.resolve_domain_base(data, "a.b.foo.com") == "https://rdap.example.com/"


def test_resolve_cidr_base_longest_prefix():
    data = {
        "services": [
            [["192.0.0.0/8"], ["https://rdap.big.invalid/"]],
            [["192.0.2.0/24"], ["https://rdap.small.invalid/"]],
        ]
    }
    assert rdap.resolve_cidr_base(data, "192.0.2.5/32") == "https://rdap.small.invalid/"


def test_resolve_autnum_base():
    data = {
        "services": [
            [["0-64511"], ["https://rdap.iana.example/"]],
            [["64496-64500"], ["https://rdap.example.test/"]],
        ]
    }
    assert rdap.resolve_autnum_base(data, 64496) == "https://rdap.example.test/"


def test_normalize_rdap():
    normalized = rdap.normalize_rdap(
        {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "handle": "2",
            "status": ["active"],
            "nameservers": [{"ldhName": "ns1.example.com"}],
            "secureDNS": {"delegationSigned": True},
            "port43": "whois.example.com",
        }
    )
    assert normalized.kind == "domain"
    assert normalized.identifier == "example.com"
    assert normalized.statuses == ["active"]
    assert normalized.nameservers == ["ns1.example.com"]
    assert normalized.port43 == "whois.example.com"


def test_lookup_rdap_no_entry_offline(tmp_path):
    def fake_opener(req, timeout):
        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self):
                return b'{"services":[[["com"],["https://rdap.example/"]]]}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return Resp()

    result = rdap.lookup_rdap(
        "missing.test", cache_dir=tmp_path, timeout=1, opener=fake_opener
    )
    assert result.error is not None
    assert "bootstrap" in result.error


def test_http_get_json_retries_transient_oserror():
    from registrata.retry import Backoff

    calls = []

    class Resp:
        status = 200
        headers = {"Content-Type": "application/json"}

        def read(self):
            return b'{"hello":"world"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("temporary")
        return Resp()

    result = rdap.http_get_json(
        "https://example.test/rdap",
        opener=opener,
        retries=1,
        backoff=Backoff(base_delay=0),
    )
    assert result.ok
    assert calls == [1, 1]


def test_http_get_json_retries_429_status():
    from registrata.retry import Backoff

    calls = []

    class Resp:
        def __init__(self, status):
            self.status = status
            self.headers = {"Content-Type": "application/json"}

        def read(self):
            return (
                b'{"hello":"world"}' if self.status == 200 else b'{"error":"slow down"}'
            )

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(len(calls) + 1)
        return Resp(429 if len(calls) == 1 else 200)

    result = rdap.http_get_json(
        "https://example.test/rdap",
        opener=opener,
        retries=1,
        backoff=Backoff(base_delay=0),
    )
    assert result.ok
    assert calls == [1, 2]


def test_query_rdap_uses_response_cache():
    from registrata.cache import TTLCache

    calls = []

    class Resp:
        status = 200
        headers = {"Content-Type": "application/rdap+json"}

        def read(self):
            return b'{"objectClassName":"domain","ldhName":"example.com"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(req.full_url)
        return Resp()

    cache = TTLCache(default_ttl=60)
    first = rdap.query_rdap(
        "https://rdap.example/", "/domain/example.com", opener=opener, cache=cache
    )
    second = rdap.query_rdap(
        "https://rdap.example/", "/domain/example.com", opener=opener, cache=cache
    )
    assert first.ok
    assert second.data == first.data
    assert len(calls) == 1


def test_query_rdap_force_refresh_bypasses_response_cache():
    from registrata.cache import TTLCache

    calls = []

    class Resp:
        status = 200
        headers = {"Content-Type": "application/rdap+json"}

        def read(self):
            return b'{"objectClassName":"domain","ldhName":"example.com"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(req.full_url)
        return Resp()

    cache = TTLCache(default_ttl=60)
    rdap.query_rdap(
        "https://rdap.example/", "/domain/example.com", opener=opener, cache=cache
    )
    rdap.query_rdap(
        "https://rdap.example/",
        "/domain/example.com",
        opener=opener,
        cache=cache,
        force_refresh=True,
    )
    assert len(calls) == 2


def test_http_get_json_rejects_invalid_json():
    class Resp:
        status = 200
        headers = {"Content-Type": "application/json"}

        def read(self, size=None):
            return b"not-json"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    result = rdap.http_get_json(
        "https://example.test/rdap", opener=lambda req, timeout: Resp()
    )
    assert result.status == 200
    assert result.error is not None
    assert "invalid JSON" in result.error


def test_http_get_json_rejects_oversized_response():
    class Resp:
        status = 200
        headers = {"Content-Type": "application/json"}

        def read(self, size=None):
            size = size or 1024
            return b"x" * size

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    result = rdap.http_get_json(
        "https://example.test/rdap", opener=lambda req, timeout: Resp(), max_bytes=32
    )
    assert result.error == "RDAP response exceeds maximum size"
    assert not result.ok


def test_http_get_json_retry_logs_event(caplog):
    import logging
    from registrata.retry import Backoff

    calls = []

    class Resp:
        status = 200
        headers = {"Content-Type": "application/json"}

        def read(self):
            return b'{"hello":"world"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("temporary")
        return Resp()

    with caplog.at_level(logging.INFO, logger="registrata.experimental.rdap"):
        result = rdap.http_get_json(
            "https://example.test/rdap",
            opener=opener,
            retries=1,
            backoff=Backoff(base_delay=0),
        )

    assert result.ok
    events = [
        getattr(record, "registrata", {}).get("event") for record in caplog.records
    ]
    assert "rdap_retry" in events


def test_load_bootstrap_conditional_refresh_returns_stale_on_304(tmp_path):
    calls: list[str | None] = []
    services = {"services": [[["com"], ["https://rdap.example/"]]]}

    class Resp200:
        status = 200
        headers = {"Content-Type": "application/json", "ETag": "abc"}

        def read(self):
            return b'{"services": [[["com"], ["https://rdap.example/"]]]}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class Resp304:
        status = 304
        headers = {}

        def read(self):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(req.headers.get("If-none-match"))
        if len(calls) == 1:
            return Resp200()
        return Resp304()

    first = rdap.load_bootstrap(
        "domain",
        cache_dir=tmp_path,
        url="https://bootstrap.invalid/dns.json",
        max_age_seconds=0,
        opener=opener,
    )
    second = rdap.load_bootstrap(
        "domain",
        cache_dir=tmp_path,
        url="https://bootstrap.invalid/dns.json",
        max_age_seconds=0,
        opener=opener,
    )

    assert first == services
    assert second == services
    assert calls == [None, "abc"]


def test_load_bootstrap_falls_back_to_stale_cache_on_fetch_failure(tmp_path):
    calls: list[int] = []
    services = {"services": [[["net"], ["https://rdap.net.invalid/"]]]}

    class Resp200:
        status = 200
        headers = {"Content-Type": "application/json", "Last-Modified": "today"}

        def read(self):
            return b'{"services": [[["net"], ["https://rdap.net.invalid/"]]]}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(1)
        if len(calls) == 1:
            return Resp200()
        raise OSError("offline")

    first = rdap.load_bootstrap(
        "domain",
        cache_dir=tmp_path,
        url="https://bootstrap.invalid/dns.json",
        max_age_seconds=0,
        opener=opener,
    )
    second = rdap.load_bootstrap(
        "domain",
        cache_dir=tmp_path,
        url="https://bootstrap.invalid/dns.json",
        max_age_seconds=0,
        opener=opener,
    )

    assert first == services
    assert second == services
    assert len(calls) == 2


def test_query_rdap_stores_etag_and_revalidates_on_304():
    from registrata.cache import TTLCache

    calls: list[str | None] = []
    data = {"objectClassName": "domain", "ldhName": "example.com"}

    class Resp200:
        status = 200
        headers = {"Content-Type": "application/rdap+json", "ETag": "v1"}

        def read(self):
            return b'{"objectClassName":"domain","ldhName":"example.com"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class Resp304:
        status = 304
        headers = {}

        def read(self):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(req.headers.get("If-none-match"))
        if len(calls) == 1:
            return Resp200()
        return Resp304()

    cache = TTLCache(default_ttl=60)
    first = rdap.query_rdap(
        "https://rdap.example/",
        "/domain/example.com",
        opener=opener,
        cache=cache,
        cache_ttl=0,
        revalidation_ttl=60,
    )
    second = rdap.query_rdap(
        "https://rdap.example/",
        "/domain/example.com",
        opener=opener,
        cache=cache,
        cache_ttl=0,
        revalidation_ttl=60,
    )

    assert first.ok
    assert second.ok
    assert first.data == data
    assert second.data == data
    assert second.cache_mode == "revalidated"
    assert second.status == 200
    assert calls == [None, "v1"]


def test_query_rdap_falls_back_to_stale_response_on_transient_error():
    from registrata.cache import TTLCache

    calls: list[int] = []
    data = {"objectClassName": "domain", "ldhName": "example.com"}

    class Resp200:
        status = 200
        headers = {"Content-Type": "application/rdap+json"}

        def read(self):
            return b'{"objectClassName":"domain","ldhName":"example.com"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(1)
        if len(calls) == 1:
            return Resp200()
        raise OSError("offline")

    cache = TTLCache(default_ttl=60)
    rdap.query_rdap(
        "https://rdap.example/",
        "/domain/example.com",
        opener=opener,
        cache=cache,
        cache_ttl=0,
        revalidation_ttl=60,
    )
    second = rdap.query_rdap(
        "https://rdap.example/",
        "/domain/example.com",
        opener=opener,
        cache=cache,
        cache_ttl=0,
        revalidation_ttl=60,
    )

    assert second.ok
    assert second.stale is True
    assert second.cache_mode == "stale"
    assert second.data == data
    assert len(calls) == 2


def test_query_rdap_force_refresh_bypasses_conditional_revalidation():
    from registrata.cache import TTLCache

    calls: list[str | None] = []

    class Resp200:
        status = 200
        headers = {"Content-Type": "application/rdap+json", "ETag": "v1"}

        def read(self):
            return b'{"objectClassName":"domain","ldhName":"example.com"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(req, timeout):
        calls.append(req.headers.get("If-none-match"))
        return Resp200()

    cache = TTLCache(default_ttl=60)
    rdap.query_rdap(
        "https://rdap.example/",
        "/domain/example.com",
        opener=opener,
        cache=cache,
        cache_ttl=0,
        revalidation_ttl=60,
    )
    rdap.query_rdap(
        "https://rdap.example/",
        "/domain/example.com",
        opener=opener,
        cache=cache,
        cache_ttl=0,
        revalidation_ttl=60,
        force_refresh=True,
    )

    assert calls == [None, None]
