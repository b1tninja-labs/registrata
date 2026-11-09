from registrata.protocol import parse_response


def test_parse_soa_group():
    response = parse_response(
        [
            "%soa authority:com",
            "%soa ttl:604800",
            "%soa serial:19970103101232000",
            "%soa refresh:86400",
            "%soa increment:3600",
            "%soa retry:1800",
            "%soa tech-contact:joeblo@internic.net",
            "%soa admin-contact:joeblo@internic.net",
            "%soa hostmaster:hostmaster@internic.net",
            "%soa primary:rs.internic.net:4321",
            "%soa",
            "%ok",
        ]
    )
    assert response.ok
    assert len(response.soa) == 1
    assert response.soa[0].authority == "com"
    assert response.soa[0].serial == "19970103101232000"


def test_parse_status_group():
    response = parse_response(
        [
            "%status limit:20",
            "%status holdconnect:OFF",
            "%status forward:OFF",
            "%status objects:12345",
            "%status display:dump",
            "%status contact:joe@rwhois.net",
            "%ok",
        ]
    )
    assert response.status_dict["objects"] == "12345"
    assert response.status_dict["contact"] == "joe@rwhois.net"
