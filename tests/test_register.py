"""`-register` against a live server, where the Appendix C code is the contract.

The code is what a client acts on: 320 says the attribute is not in the class, 321
that the value does not fit it, 322 that something required is absent, 324 that the
key is taken, 325 that the record moved underneath the client. None of it was
reachable. `finish_register` ended in one `except Exception` that answered 402
unidentified error for every problem, including the client's own mistakes, and the
backend's `create_object` called `ensure_class(area, class, obj)`, extending the
class definition to fit whatever had just been sent, so nothing could fail
validation. Simple objects *were* stored -- what no test covered was every way a
registration can be wrong, and each of those is a different code.
"""

import pytest

from registrata import RwhoisClient, RwhoisServer
from registrata.backends.memory import MemoryBackend
from registrata.errors import RwhoisError
from registrata.schema import (
    AttributeDefinition,
    SchemaClass,
    base_attributes,
    standard_classes,
)

AREA = "example.com"


def contact_class() -> SchemaClass:
    return SchemaClass(
        "contact",
        description="contact information",
        attributes=[
            *base_attributes(),
            AttributeDefinition("Name", "Contact name", required=True),
            AttributeDefinition("Email", "Contact email", type="EMAIL", required=True),
            AttributeDefinition("Nickname", "Nickname", primary=True),
            AttributeDefinition("See-Also", "Linked server", type="SEE-ALSO"),
            AttributeDefinition("Count", "Widget count", type="NUMBER"),
            AttributeDefinition("Alias", "Alias", repeatable=True),
        ],
    )


@pytest.fixture
def backend():
    store = MemoryBackend(AREA)
    store.add_class(AREA, contact_class())
    return store


@pytest.fixture
def server(backend):
    instance = RwhoisServer(
        backend, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=10
    )
    host, port = instance.start()
    yield host, port, instance
    instance.shutdown()


def object_lines(**overrides):
    """A valid contact, with `None` removing an attribute and other keys adding one."""
    attrs = {
        "Class-Name": "contact",
        "Auth-Area": AREA,
        "Name": "Williamson, Scott",
        "Email": "scottw@a.com",
    }
    attrs.update(overrides)
    return [f"{key}:{value}" for key, value in attrs.items() if value is not None]


def register(host, port, lines, *, mode="add", maintainer="joe@netsol.com"):
    with RwhoisClient.connect(host, port, timeout=5) as client:
        return client.register(mode, maintainer, lines)


def register_error(host, port, lines, *, mode="add"):
    with pytest.raises(RwhoisError) as excinfo:
        register(host, port, lines, mode=mode)
    assert excinfo.value.code is not None, "a refusal must carry an Appendix C code"
    return int(excinfo.value.code), excinfo.value.error_text


def stored_assigned_id(response) -> tuple[str, str]:
    lowered = {key.lower(): value for key, value in response.register}
    return lowered["id"], lowered["updated"]


def test_add_stores_the_object_and_assigns_id_and_updated(server, backend):
    serial_before = backend.get_soa(AREA).serial
    host, port, _ = server
    response = register(host, port, object_lines())

    assigned_id, assigned_updated = stored_assigned_id(response)
    assert assigned_id.endswith(f".{AREA}")
    assert len(assigned_updated) == 17 and assigned_updated.isdigit()

    stored = backend.objects[AREA][0]
    assert stored.class_name == "contact"
    assert stored.get("Name") == "Williamson, Scott"
    assert stored.id == assigned_id
    # Section 3.3.9: a registration has to advance the SOA serial, because a slave
    # decides whether to re-transfer by reading exactly that number.
    assert backend.get_soa(AREA).serial != serial_before


def test_add_refuses_an_id_the_client_tried_to_assign(server):
    host, port, _ = server
    code, text = register_error(host, port, object_lines(ID="mine-1.example.com"))
    assert code == 320
    assert "assigned by the server" in text


def test_add_refuses_an_undeclared_attribute(server):
    host, port, _ = server
    code, text = register_error(host, port, object_lines(Telefax="555-1212"))
    assert code == 320
    assert "Telefax" in text


def test_add_reports_a_missing_required_attribute_as_322_not_402(server):
    host, port, _ = server
    code, text = register_error(host, port, object_lines(Name=None))
    assert code == 322
    assert "Name" in text


def test_a_blank_value_on_a_required_attribute_is_322(server):
    # Nothing after the colon supplies no more than an absent line would, and the
    # attribute is required, so 322 is the code that names the client's problem.
    host, port, _ = server
    code, text = register_error(host, port, object_lines(Email=" "))
    assert code == 322
    assert "Email" in text


def test_a_blank_value_on_an_optional_attribute_is_321(server):
    # Appendix B wants at least one character after the colon whatever the
    # attribute; here nothing is missing, the value is simply malformed.
    host, port, _ = server
    code, _text = register_error(host, port, object_lines(Count=" "))
    assert code == 321


@pytest.mark.parametrize(
    "attribute,value",
    [("See-Also", "not-a-url"), ("Count", "twelve")],
)
def test_add_checks_value_form_against_the_declared_type(server, attribute, value):
    host, port, _ = server
    code, text = register_error(host, port, object_lines(**{attribute: value}))
    assert code == 321
    assert attribute in text


def test_a_declared_see_also_value_is_accepted(server):
    host, port, _ = server
    register(host, port, object_lines(**{"See-Also": "127.0.0.1:4321:example.com"}))


def test_a_repeatable_attribute_may_repeat_and_another_may_not(server, backend):
    host, port, _ = server
    register(host, port, object_lines() + ["Alias:scott", "Alias:sw"])
    assert len(backend.objects[AREA][0].getall("Alias")) == 2

    code, text = register_error(host, port, object_lines() + ["Name:second name"])
    assert code == 321
    assert "Name" in text


def test_unknown_class_is_refused_as_341(server):
    host, port, _ = server
    code, text = register_error(host, port, object_lines(**{"Class-Name": "widget"}))
    assert code == 341
    assert "widget" in text


def test_unknown_authority_area_is_refused_as_340(server):
    host, port, _ = server
    code, _text = register_error(host, port, object_lines(**{"Auth-Area": "other.net"}))
    assert code == 340


def test_a_duplicate_primary_key_is_refused_as_324(server):
    host, port, _ = server
    register(host, port, object_lines(Nickname="scottw"))
    code, text = register_error(host, port, object_lines(Nickname="SCOTTW"))
    assert code == 324
    assert "Nickname" in text


def test_a_line_with_no_colon_is_a_syntax_error_not_a_dropped_line(server, backend):
    # Dropping it silently used to store half an object and answer %ok.
    host, port, _ = server
    code, _text = register_error(host, port, object_lines() + ["no colon here"])
    assert code == 338
    assert not backend.objects[AREA]


def test_a_malformed_attribute_name_is_reported_as_the_clients_syntax_error(server):
    # AttributeLine rejects it, which used to surface as 402, a server fault code,
    # for what is plainly the client's malformed line.
    host, port, _ = server
    code, _text = register_error(host, port, object_lines() + ["Not An Attribute:x"])
    assert code == 338


def test_class_name_arriving_last_still_files_the_object_under_that_class(
    server, backend
):
    # Previously the object became class "unknown" whenever Class-Name was not the
    # first line of the block.
    host, port, _ = server
    lines = [
        f"Auth-Area:{AREA}",
        "Name:Williamson, Scott",
        "Email:scottw@a.com",
        "Class-Name:contact",
    ]
    register(host, port, lines)
    assert backend.objects[AREA][0].class_name == "contact"


def mod_lines(object_id, updated, **overrides):
    """The pre-`_NEW_` identifying half, the separator, then the replacement."""
    identifying = [
        "Class-Name:contact",
        f"Auth-Area:{AREA}",
        f"ID:{object_id}",
        f"Updated:{updated}",
    ]
    return identifying + ["_NEW_"] + object_lines(ID=object_id, **overrides)


def test_mod_replaces_the_record_and_refreshes_updated(server, backend):
    host, port, _ = server
    object_id, updated = stored_assigned_id(register(host, port, object_lines()))

    response = register(
        host, port, mod_lines(object_id, updated, Name="New Name"), mode="mod"
    )

    new_id, new_updated = stored_assigned_id(response)
    assert new_id == object_id
    assert new_updated != updated
    stored = backend.objects[AREA][0]
    assert stored.get("Name") == "New Name"
    assert len(backend.objects[AREA]) == 1


def test_mod_without_the_separator_is_refused(server):
    host, port, _ = server
    object_id, _updated = stored_assigned_id(register(host, port, object_lines()))
    code, _text = register_error(host, port, object_lines(ID=object_id), mode="mod")
    assert code == 338


def test_mod_requires_id_and_updated_in_the_identifying_half(server):
    host, port, _ = server
    object_id, _updated = stored_assigned_id(register(host, port, object_lines()))
    lines = [
        "Class-Name:contact",
        f"Auth-Area:{AREA}",
        f"ID:{object_id}",
        "_NEW_",
    ] + object_lines(ID=object_id)
    code, text = register_error(host, port, lines, mode="mod")
    assert code == 322
    assert "Updated" in text


def test_mod_refuses_when_the_two_halves_describe_different_objects(server):
    host, port, _ = server
    object_id, updated = stored_assigned_id(register(host, port, object_lines()))
    lines = [
        "Class-Name:contact",
        f"Auth-Area:{AREA}",
        f"ID:{object_id}",
        f"Updated:{updated}",
        "_NEW_",
    ] + object_lines(ID="00000002.example.com")
    code, text = register_error(host, port, lines, mode="mod")
    assert code == 323
    assert "ID" in text


def test_mod_refuses_to_overwrite_a_record_that_moved_underneath_it(server):
    host, port, _ = server
    object_id, _updated = stored_assigned_id(register(host, port, object_lines()))
    code, text = register_error(
        host, port, mod_lines(object_id, "19970101000000000"), mode="mod"
    )
    assert code == 325
    assert "updated" in text.lower()


def identifying_lines(object_id, updated):
    return [
        "Class-Name:contact",
        f"Auth-Area:{AREA}",
        f"ID:{object_id}",
        f"Updated:{updated}",
    ]


def test_del_removes_the_object_it_identifies(server, backend):
    host, port, _ = server
    object_id, updated = stored_assigned_id(register(host, port, object_lines()))
    serial_before = backend.get_soa(AREA).serial

    register(host, port, identifying_lines(object_id, updated), mode="del")

    assert backend.objects[AREA] == []
    # A deletion changes the zone, so the serial has to move or a slave would
    # keep serving the object it already holds.
    assert backend.get_soa(AREA).serial != serial_before


def test_del_requires_the_identifying_attributes(server):
    host, port, _ = server
    object_id, _updated = stored_assigned_id(register(host, port, object_lines()))
    lines = [
        "Class-Name:contact",
        f"Auth-Area:{AREA}",
        f"ID:{object_id}",
    ]
    code, text = register_error(host, port, lines, mode="del")
    assert code == 322
    assert "Updated" in text


def test_del_of_an_unknown_id_reports_336(server):
    host, port, _ = server
    lines = identifying_lines("does-not-exist.example.com", "19970101000000000")
    code, _text = register_error(host, port, lines, mode="del")
    assert code == 336


def test_registration_needs_no_authentication_when_the_backend_cannot_authenticate(
    server,
):
    host, port, _ = server
    register(host, port, object_lines())  # no -security here, and that is allowed


def test_registration_requires_authentication_when_the_backend_can(backend, server):
    backend.add_password("s3cret")
    host, port, _ = server

    code, text = register_error(host, port, object_lines())
    assert code == 401
    assert "authenticated" in text

    with RwhoisClient.connect(host, port, timeout=5) as client:
        client.security_password("s3cret")
        response = client.register("add", "joe@netsol.com", object_lines())
    assert stored_assigned_id(response)[0].endswith(f".{AREA}")


def test_a_read_only_backend_reports_the_directive_as_unavailable():
    class ReadOnly(MemoryBackend):
        @property
        def support_register(self) -> bool:
            return False

    instance = RwhoisServer(
        ReadOnly(AREA), host="127.0.0.1", port=0, server_name="127.0.0.1"
    )
    host, port = instance.start()
    try:
        with pytest.raises(RwhoisError) as excinfo:
            register(host, port, object_lines())
        assert int(excinfo.value.code) == 400
    finally:
        instance.shutdown()


# --- Guardians (section 2.3.6) and maintenance deferral (120) -------------------
#
# Section 2.3.6 says an object is guarded by carrying a pointer to a guardian object,
# that the guardian's authentication scheme must be satisfied "to modify, delete, or
# possibly view" it, and that guardians have no rank -- satisfying any one is enough.
# Guard-Scheme names the methodology and Guard-Info holds the data it verifies, whose
# RFC-given example is a password. None of this was reachable: the guardian class did not
# declare either attribute, and a Guardian value was free to name an object that does not
# exist.


def guardian_server(*, scheme="password", info="guarder", deferred=False):
    """A server with both a contact class and the standard guardian class registered.

    Two session passwords are always valid -- `svc` for an ordinary registration service
    account and `guarder` for the one a password guardian can name. `info` only feeds the
    guardian's Guard-Info, so a test can put something there that no session presents.
    """
    store = MemoryBackend(AREA)
    store.add_class(AREA, contact_class())
    store.add_class(
        AREA, next(cls for cls in standard_classes() if cls.class_name == "guardian")
    )
    store.add_password("svc")
    store.add_password("guarder")
    instance = RwhoisServer(
        store,
        host="127.0.0.1",
        port=0,
        server_name="127.0.0.1",
        idle_timeout=10,
        registration_deferred=deferred,
    )
    host, port = instance.start()
    return instance, host, port


def register_as(host, port, password, lines, *, mode="add"):
    with RwhoisClient.connect(host, port, timeout=5) as client:
        client.security_password(password)
        return client.register(mode, "joe@netsol.com", lines)


def guardian_lines(*, scheme="password", info="guarder"):
    return [
        "Class-Name:guardian",
        f"Auth-Area:{AREA}",
        f"Guarded-Auth-Area:{AREA}",
        "Type:object",
        f"Guard-Scheme:{scheme}",
        f"Guard-Info:{info}",
    ]


def test_a_guardian_that_names_nothing_is_refused_as_323():
    """Section 2.3.6: the value of Guardian is the ID of a guardian object."""
    instance, host, port = guardian_server()
    try:
        register_as(host, port, "svc", guardian_lines())
        with pytest.raises(RwhoisError) as excinfo:
            register_as(host, port, "svc", object_lines(Guardian="0.nope.example.com"))
        assert int(excinfo.value.code) == 323
        assert "guardian" in excinfo.value.error_text.lower()
    finally:
        instance.shutdown()


def test_an_ordinary_service_account_is_not_the_guardian():
    """Being allowed to register at all is not the same as being the guardian."""
    instance, host, port = guardian_server()
    try:
        guardian_id = stored_assigned_id(
            register_as(host, port, "svc", guardian_lines())
        )[0]
        object_id, updated = stored_assigned_id(
            register_as(host, port, "svc", object_lines(Guardian=guardian_id))
        )
        with pytest.raises(RwhoisError) as excinfo:
            register_as(
                host,
                port,
                "svc",
                identifying_lines(object_id, updated)
                + ["_NEW_"]
                + object_lines(ID=object_id, Name="Changed"),
                mode="mod",
            )
        assert int(excinfo.value.code) == 420
        # Delete is gated the same way, for the same reason.
        with pytest.raises(RwhoisError) as excinfo:
            register_as(
                host, port, "svc", identifying_lines(object_id, updated), mode="del"
            )
        assert int(excinfo.value.code) == 420
    finally:
        instance.shutdown()


def test_the_guardians_own_password_satisfies_it():
    instance, host, port = guardian_server()
    try:
        guardian_id = stored_assigned_id(
            register_as(host, port, "svc", guardian_lines())
        )[0]
        object_id, updated = stored_assigned_id(
            register_as(host, port, "svc", object_lines(Guardian=guardian_id))
        )
        response = register_as(
            host,
            port,
            "guarder",
            identifying_lines(object_id, updated)
            + ["_NEW_"]
            + object_lines(ID=object_id, Name="Changed by the guardian"),
            mode="mod",
        )
        new_id, new_updated = stored_assigned_id(response)
        assert new_id == object_id
        assert new_updated != updated
    finally:
        instance.shutdown()


def test_a_scheme_this_server_does_not_implement_is_a_refusal_not_a_pass():
    """Section 2.3.6 requires a scheme be understood by both ends.

    A guardian that names PGP cannot be satisfied here, so what it guards is not
    modifiable -- which is the safe reading. Treating "I cannot check this" as "allowed"
    would make declaring a stronger guardian a way to bypass protection.
    """
    instance, host, port = guardian_server(scheme="pgp", info="KEYID001")
    try:
        guardian_id = stored_assigned_id(
            register_as(
                host, port, "svc", guardian_lines(scheme="pgp", info="KEYID001")
            )
        )[0]
        object_id, updated = stored_assigned_id(
            register_as(host, port, "svc", object_lines(Guardian=guardian_id))
        )
        with pytest.raises(RwhoisError) as excinfo:
            register_as(
                host, port, "guarder", identifying_lines(object_id, updated), mode="del"
            )
        assert int(excinfo.value.code) == 420
    finally:
        instance.shutdown()


def test_registration_can_be_deferred_while_queries_keep_working():
    """Section 3.3.9 lists 120: keep serving, stop taking writes."""
    instance, host, port = guardian_server(deferred=True)
    try:
        with pytest.raises(RwhoisError) as excinfo:
            register_as(host, port, "svc", object_lines())
        assert int(excinfo.value.code) == 120
        # A deferred server is not an offline one: reads are untouched, and the answer
        # here is the ordinary "nothing matched", not a directive-level refusal.
        with RwhoisClient.connect(host, port, timeout=5) as client:
            result = client.query("contact", "nobody", raise_errors=False)
        assert not any(line.startswith("%error 4") for line in result.raw_lines), (
            result.raw_lines
        )
    finally:
        instance.shutdown()


# --- Private attributes and objects (section 2.3.1) -----------------------------
#
# "This is a true or false flag that indicates whether or not this attribute is private
# (that is, publicly not viewable). ... If it is true, then only the clients that satisfy
# the authentication/encryption requirements of a guardian ... are able to view the
# attribute-value pair." The flag was advertised in %schema and parsed from it, but nothing
# on the serving path consulted it -- so every private value, including the Guard-Info
# password this project had just started writing into guardian objects, went to anyone who
# could open a socket.


def private_class() -> SchemaClass:
    return SchemaClass(
        "secret",
        description="classified information",
        attributes=[
            *base_attributes(),
            AttributeDefinition("Name", "Name", required=True),
            AttributeDefinition("Nickname", "Nickname", primary=True),
            AttributeDefinition("Passcode", "Passcode", private=True),
        ],
    )


def private_server():
    """A server with a guardian class and a class holding one private attribute."""
    store = MemoryBackend(AREA)
    store.add_class(AREA, contact_class())
    store.add_class(AREA, private_class())
    store.add_class(
        AREA, next(cls for cls in standard_classes() if cls.class_name == "guardian")
    )
    store.add_password("svc")
    store.add_password("guarder")
    instance = RwhoisServer(
        store, host="127.0.0.1", port=0, server_name="127.0.0.1", idle_timeout=10
    )
    host, port = instance.start()
    return instance, host, port


def query_as(host, port, password, class_name, attribute, value):
    with RwhoisClient.connect(host, port, timeout=5) as client:
        if password:
            client.security_password(password)
        return client.query_attribute(
            class_name, attribute, value, raise_errors=False
        ).raw_lines


def secret_lines(**overrides):
    attrs = {
        "Class-Name": "secret",
        "Auth-Area": AREA,
        "Nickname": "s1",
        "Name": "classified",
        "Passcode": "hunter2",
    }
    attrs.update(overrides)
    return [f"{key}:{value}" for key, value in attrs.items() if value is not None]


def test_a_guardians_own_secret_is_not_public():
    """Guard-Info is Private in the schema, and a guardian guards itself."""
    instance, host, port = private_server()
    try:
        register_as(host, port, "svc", guardian_lines())
        lines = query_as(host, port, "svc", "guardian", "Type", "object")
        assert any("Guard-Scheme" in line for line in lines), lines
        assert not any("guarder" in line for line in lines), lines
        # The session that presents the password is the one allowed to read it back.
        lines = query_as(host, port, "guarder", "guardian", "Type", "object")
        assert any("Guard-Info:guarder" in line for line in lines), lines
    finally:
        instance.shutdown()


def test_a_private_attribute_is_hidden_from_sessions_that_satisfy_no_guardian():
    instance, host, port = private_server()
    try:
        guardian_id = stored_assigned_id(
            register_as(host, port, "svc", guardian_lines())
        )[0]
        register_as(host, port, "svc", secret_lines(Guardian=guardian_id))
        lines = query_as(host, port, "svc", "secret", "Nickname", "s1")
        assert any("classified" in line for line in lines), lines  # record is served...
        assert not any("hunter2" in line for line in lines), lines  # ...value is not
        lines = query_as(host, port, "guarder", "secret", "Nickname", "s1")
        assert any("Passcode:hunter2" in line for line in lines), lines
    finally:
        instance.shutdown()


def test_a_private_object_is_withheld_and_reads_as_no_match():
    """The base class carries the same flag at object level, and the answer must not
    announce that something matched but was hidden."""
    instance, host, port = private_server()
    try:
        guardian_id = stored_assigned_id(
            register_as(host, port, "svc", guardian_lines())
        )[0]
        register_as(
            host,
            port,
            "svc",
            secret_lines(Guardian=guardian_id, Private="true", Passcode=None),
        )
        lines = query_as(host, port, "svc", "secret", "Nickname", "s1")
        assert any(line.startswith("%error 230") for line in lines), lines
        lines = query_as(host, port, "guarder", "secret", "Nickname", "s1")
        assert any("Private:true" in line for line in lines), lines
    finally:
        instance.shutdown()


def test_editing_a_guardian_object_requires_the_password_inside_it():
    """Section 2.3.6: a guardian with no Guardian attribute guards itself."""
    instance, host, port = private_server()
    try:
        guardian_id, updated = stored_assigned_id(
            register_as(host, port, "svc", guardian_lines())
        )
        replacement = guardian_lines() + [f"ID:{guardian_id}"]
        identifying = [
            "Class-Name:guardian",
            f"Auth-Area:{AREA}",
            f"ID:{guardian_id}",
            f"Updated:{updated}",
            "_NEW_",
        ]
        with pytest.raises(RwhoisError) as excinfo:
            register_as(host, port, "svc", identifying + replacement, mode="mod")
        assert int(excinfo.value.code) == 420
        # The password inside the object is the one that unlocks it -- which is also how a
        # password rotation has to work: the old secret authorizes the change of new secret.
        register_as(host, port, "guarder", identifying + replacement, mode="mod")
    finally:
        instance.shutdown()
