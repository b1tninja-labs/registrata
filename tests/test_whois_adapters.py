from registrata.experimental.whois_adapters import (
    detect_whois_profile,
    normalize_whois_fields,
)


def test_detect_whois_profiles():
    assert (
        detect_whois_profile(
            {
                "Domain Name": ["example.com"],
                "Registrar WHOIS Server": ["whois.example.com"],
            }
        )
        == "verisign"
    )
    assert (
        detect_whois_profile({"NetName": ["TEST-NET-1"]}, server="whois.arin.net")
        == "arin"
    )
    assert (
        detect_whois_profile(
            {"inetnum": ["192.0.2.0 - 192.0.2.255"]}, server="whois.ripe.net"
        )
        == "ripe"
    )


def test_arin_profile_normalizes_network_and_abuse_contact():
    record = normalize_whois_fields(
        {
            "NetworkName": ["EXAMPLE-NET"],
            "NetName": ["EXAMPLE-NET"],
            "StartRange": ["192.0.2.1"],
            "EndRange": ["192.0.2.254"],
            "OrgName": ["Example Org"],
            "OrgId": ["EO-1"],
            "OrgAbuseEmail": ["abuse@example.com"],
            "OrgAbusePhone": ["+1.5555550100"],
        },
        resource="192.0.2.5",
        kind="ipv4",
        server="whois.arin.net",
    )
    assert record.kind == "ipv4"
    assert record.identifier == "EXAMPLE-NET"
    assert record.networks[0]["start"] == "192.0.2.1"
    abuse = next(contact for contact in record.contacts if "abuse" in contact["roles"])
    assert abuse["emails"] == ["abuse@example.com"]


def test_ripe_profile_normalizes_inetnum():
    record = normalize_whois_fields(
        {
            "inetnum": ["192.0.2.0 - 192.0.2.255"],
            "org": ["ORG-EXAMPLE1"],
            "tech-c": ["TP1-RIPE"],
        },
        resource="192.0.2.5",
        kind="ipv4",
        server="whois.ripe.net",
    )
    assert record.identifier == "192.0.2.0 - 192.0.2.255"
    assert record.networks == [{"name": "192.0.2.0 - 192.0.2.255"}]
    assert "technical" in {
        role for contact in record.contacts for role in contact["roles"]
    }
