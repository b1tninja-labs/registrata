from registrata.banner import parse_banner, serialize_banner
from registrata.banner import Version
from registrata.capabilities import (
    Capability,
    decode_capability_id,
    encode_capability_id,
)


def test_banner_parse_rfc_example():
    banner = parse_banner(
        "%rwhois V-1.5:00ffff:00 master.rwhois.net (Network Solutions V-1.5)"
    )
    assert banner.host == "master.rwhois.net"
    assert banner.version_numbers == ("V-1.5",)
    assert Capability.LIMIT in banner.best_version().capability


def test_banner_parse_multiple_versions():
    banner = parse_banner(
        "%rwhois V-1.0,V-1.5:00ffff:00 rs.internic.net (NSI Server 1.5.4)"
    )
    assert banner.version_numbers == ("V-1.0", "V-1.5")
    assert banner.best_version().number == "1.5"


def test_serialize_banner_single_version():
    line = serialize_banner(
        Version("1.5"),
        "example.test",
        capability=Capability.LIMIT | Capability.HOLDCONNECT,
    )
    assert line == "%rwhois V-1.5:000030:00 example.test"


def test_capability_roundtrip():
    bits = Capability.CLASS | Capability.SCHEMA | Capability.STATUS
    assert decode_capability_id(encode_capability_id(bits)) == bits
