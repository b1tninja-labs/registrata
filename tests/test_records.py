import pytest

from registrata.protocol import parse_query_result
from registrata.records import AttributeLine, ObjectRecord, parse_referral_line


def test_parse_referral():
    ref = parse_referral_line(
        "%referral rwhois://master.b.rwhois.net:4321/auth-area=b.rwhois.net"
    )
    assert ref.host == "master.b.rwhois.net"
    assert ref.port == 4321
    assert ref.auth_area == "b.rwhois.net"


def test_object_to_wire_uses_type_suffix():
    obj = ObjectRecord("domain", [AttributeLine("Server", "ns1.example.com", "I")])
    assert obj.to_wire_lines() == ["domain:Server;I:ns1.example.com"]


def test_parse_query_result_from_rfc_example():
    result = parse_query_result(
        [
            "domain:ID:dom-1.rwhois.net",
            "domain:Auth-Area:rwhois.net",
            "domain:Class-Name:domain",
            "domain:Server;I:hst-1.rwhois.net",
            "",
            "%ok",
        ]
    )
    assert result.ok
    assert len(result.objects) == 1
    assert result.objects[0].id == "dom-1.rwhois.net"
    assert result.objects[0].getall("Server") == ["hst-1.rwhois.net"]


def test_parse_query_result_error_after_limit():
    result = parse_query_result(
        [
            "domain:ID:1.example.com",
            "",
            "%error 330 Exceeded maximum objects limit",
        ]
    )
    assert result.error_code == 330
    assert len(result.objects) == 1


def test_attribute_line_rejects_crlf_in_value():
    with pytest.raises(Exception):
        AttributeLine("ID", "bad\rvalue")
