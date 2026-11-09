from registrata.experimental import whois


def test_classify_resources():
    assert whois.classify_resource("example.com") == "domain"
    assert whois.classify_resource("8.8.8.8") == "ipv4"
    assert whois.classify_resource("2001:db8::1") == "ipv6"
    assert whois.classify_resource("192.0.2.0/24") == "cidr"
    assert whois.classify_resource("AS64496") == "autnum"
    assert whois.classify_resource("example widget") == "keyword"


def test_parse_whois_fields():
    text = """
Domain Name: EXAMPLE.COM
Registrar: Test Registrar
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Registrar WHOIS Server: whois.example.com
"""
    fields = whois.parse_whois_fields(text)
    assert fields["domain name"] == ["EXAMPLE.COM"]
    assert fields["name server"] == ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]
    assert whois.parse_whois_referrals(text) == ["whois.example.com"]


def test_whois_result_from_bytes():
    result = whois.result_from_response(
        "example.com", "whois.test", b"Domain Name: EXAMPLE.COM\r\n"
    )
    assert result.get("Domain Name") == "EXAMPLE.COM"
    assert result.encoding == "utf-8"


def test_discover_next_whois_server_from_refer():
    result = whois.WhoisResult(
        query="example.com",
        server="whois.iana.org",
        raw="Refer: whois.verisign-grs.com\n",
        fields={"refer": ["whois.verisign-grs.com"]},
        referrals=whois.parse_whois_referrals("Refer: whois.verisign-grs.com"),
    )
    assert (
        whois.discover_next_whois_server(result, current_server="whois.iana.org")
        == "whois.verisign-grs.com"
    )


def test_lookup_whois_follow_referrals_and_caches(monkeypatch):
    from registrata.cache import TTLCache

    calls = []

    def fake_whois_query(query, server, **kwargs):
        calls.append((query, server))
        if server == "whois.iana.org":
            return whois.WhoisResult(
                query=query,
                server=server,
                raw="Refer: whois.example\n",
                fields={"refer": ["whois.example"]},
                referrals=["whois.example"],
            )
        return whois.WhoisResult(
            query=query,
            server=server,
            raw="Domain Name: EXAMPLE.COM\n",
            fields={"domain name": ["EXAMPLE.COM"]},
        )

    monkeypatch.setattr(whois, "whois_query", fake_whois_query)
    cache = TTLCache(default_ttl=60)
    result = whois.lookup_whois(
        "example.com",
        server="whois.iana.org",
        follow_referrals=True,
        max_hops=2,
        cache=cache,
    )
    assert result.server == "whois.example"
    assert calls == [
        ("example.com", "whois.iana.org"),
        ("example.com", "whois.example"),
    ]

    calls.clear()
    cached = whois.lookup_whois(
        "example.com",
        server="whois.iana.org",
        follow_referrals=True,
        max_hops=2,
        cache=cache,
    )
    assert cached.server == "whois.example"
    assert calls == []


def test_whois_query_rejects_oversized_response(monkeypatch):
    class FakeSock:
        def __init__(self):
            self.sent = False

        def sendall(self, data):
            self.sent = True

        def recv(self, size):
            return b"x" * size

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        whois.socket, "create_connection", lambda addr, timeout=None: FakeSock()
    )
    result = whois.whois_query("example.com", "whois.test", timeout=1, max_bytes=32)
    assert not result.ok
    assert "maximum size" in result.error


def test_whois_result_from_malformed_bytes_does_not_crash():
    result = whois.result_from_response(
        "example.com", "whois.test", b"\xff\xfeDomain Name: EXAMPLE.COM\r\n"
    )
    assert result.ok
    assert "Domain Name" in result.raw


def test_lookup_whois_referral_logging(monkeypatch, caplog):
    import logging

    def fake_whois_query(query, server, **kwargs):
        if server == "whois.iana.org":
            return whois.WhoisResult(
                query=query,
                server=server,
                raw="Refer: whois.example\n",
                fields={"refer": ["whois.example"]},
                referrals=["whois.example"],
            )
        return whois.WhoisResult(
            query=query,
            server=server,
            raw="Domain Name: EXAMPLE.COM\n",
            fields={"domain name": ["EXAMPLE.COM"]},
        )

    monkeypatch.setattr(whois, "whois_query", fake_whois_query)
    with caplog.at_level(logging.INFO, logger="registrata.experimental.whois"):
        result = whois.lookup_whois(
            "example.com",
            server="whois.iana.org",
            follow_referrals=True,
            max_hops=1,
        )

    assert result.server == "whois.example"
    events = [
        getattr(record, "registrata", {}).get("event") for record in caplog.records
    ]
    assert "whois_referral_follow" in events
