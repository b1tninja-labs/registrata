from registrata.model import from_rdap, from_rwhois_object, from_whois_fields
from registrata.records import ObjectRecord


def test_from_rdap_extracts_contacts_registrar_and_events():
    record = from_rdap(
        {
            "objectClassName": "domain",
            "ldhName": "example.com",
            "handle": "dom-1",
            "status": ["client transfer prohibited"],
            "port43": "whois.example.com",
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            ],
            "secureDNS": {"delegationSigned": True},
            "entities": [
                {
                    "handle": "reg-1",
                    "roles": ["registrar"],
                    "publicIds": [{"type": "IANA Registrar ID", "identifier": "1234"}],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Example Registrar"],
                        ],
                    ],
                },
                {
                    "handle": "contact-1",
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Jane Doe"],
                            ["email", {}, "text", "jane@example.com"],
                            ["tel", {"type": "voice"}, "uri", "tel:+1.5551212"],
                        ],
                    ],
                },
            ],
        }
    )
    assert record.kind == "domain"
    assert record.identifier == "example.com"
    assert record.statuses == ["client transfer prohibited"]
    assert record.events[0]["action"] == "registration"
    assert record.events[0]["eventAction"] == "registration"
    assert record.events[0]["date"].endswith("+00:00")
    assert record.registrar["name"] == "Example Registrar"
    assert record.registrar["iana_id"] == "1234"
    registrant = next(
        contact for contact in record.contacts if "registrant" in contact["roles"]
    )
    assert registrant["name"] == "Jane Doe"
    assert registrant["emails"] == ["jane@example.com"]
    assert registrant["phones"] == ["tel:+1.5551212"]


def test_from_whois_fields_normalizes_common_domain_record():
    record = from_whois_fields(
        {
            "Domain Name": ["EXAMPLE.COM"],
            "Registrar": ["Example Registrar, Inc."],
            "Registrar IANA ID": ["1234"],
            "Registrar WHOIS Server": ["whois.example.com"],
            "Domain Status": ["clientTransferProhibited updateProhibited"],
            "Name Server": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
            "Registry Expiry Date": ["2030-01-01T00:00:00Z"],
            "Updated Date": ["2024-01-01T00:00:00Z"],
            "Creation Date": ["2020-01-01T00:00:00Z"],
            "DNSSEC": ["signed"],
            "Abuse Contact Email": ["abuse@example.com"],
            "Abuse Contact Phone": ["+1.5551212"],
        },
        resource="example.com",
        kind="domain",
    )
    assert record.kind == "domain"
    assert record.identifier == "EXAMPLE.COM"
    assert record.statuses == ["clientTransferProhibited", "updateProhibited"]
    assert record.nameservers == ["ns1.example.com", "ns2.example.com"]
    assert record.registrar["iana_id"] == "1234"
    assert record.port43 == "whois.example.com"
    assert record.dnssec["signed"] is True
    assert [event["action"] for event in record.events] == [
        "registration",
        "expiration",
        "last changed",
    ]
    abuse = next(contact for contact in record.contacts if "abuse" in contact["roles"])
    assert abuse["emails"] == ["abuse@example.com"]


def test_from_rwhois_object_normalizes_ids_and_contacts():
    obj = ObjectRecord("domain")
    obj.add("Class-Name", "domain")
    obj.add("ID", "dom-1.example.com")
    obj.add("Updated", "19970107201111000")
    obj.add("Admin-Contact", "adm-1.example.com")
    obj.add("Tech-Contact", "tech-1.example.com")
    obj.add("Server", "hst-1.example.com", type="I")
    record = from_rwhois_object(obj)
    assert record.kind == "domain"
    assert record.identifier == "dom-1.example.com"
    assert record.nameservers == ["hst-1.example.com"]
    roles = {role for contact in record.contacts for role in contact["roles"]}
    assert roles == {"administrative", "technical"}
