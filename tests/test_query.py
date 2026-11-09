import pytest

from registrata.errors import InvalidQuerySyntax
from registrata.query import Attribute, Boolean, Query, Unrestricted, parse_query


def test_query_to_wire_plain():
    assert Query.unrestricted("ibm").to_wire() == "ibm"


def test_query_class_restricted():
    assert Query.class_restricted("domain", "ibm").to_wire() == "domain ibm"


def test_query_attribute_restricted():
    assert (
        Query.attribute("domain", "Domain-Name", "example.com").to_wire()
        == "domain Domain-Name=example.com"
    )


def test_query_quotes_values_with_spaces():
    assert (
        Query.attribute("domain", "Org-Name", "IBM Corp").to_wire()
        == 'domain Org-Name="IBM Corp"'
    )


def test_parse_query_class_restricted():
    query = parse_query("domain Domain-Name=example.com")
    assert query.class_name == "domain"
    assert isinstance(query.expression, Attribute)


def test_parse_query_boolean_is_not_class_restricted():
    query = parse_query("ibm and jubliana*")
    assert query.class_name is None
    assert isinstance(query.expression, Boolean)
    assert isinstance(query.expression.left, Unrestricted)


def test_query_rejects_double_quote():
    with pytest.raises(InvalidQuerySyntax):
        Query.unrestricted('bad"query')
