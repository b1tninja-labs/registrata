"""RWhois query construction and parsing."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Sequence

from .errors import InvalidQuerySyntax, RwhoisParseError

_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_OP_RE = re.compile(r"^(and|or)$", re.IGNORECASE)


@dataclass(frozen=True)
class _Token:
    text: str
    quoted: bool = False


def _is_id(value: str) -> bool:
    return bool(_ID_RE.match(value))


def _validate_value(value: str, *, label: str = "query value") -> str:
    if not value:
        raise InvalidQuerySyntax(f"{label} must not be empty")
    if "\r" in value or "\n" in value:
        raise InvalidQuerySyntax(f"{label} must not contain CR or LF")
    if '"' in value:
        raise InvalidQuerySyntax(f"{label} must not contain double quote")
    return value


def _format_query_value(value: str) -> str:
    if any(ch in value for ch in " \t"):
        return f'"{value}"'
    return value


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in " \t":
            i += 1
            continue
        if ch == '"':
            i += 1
            buf: list[str] = []
            while i < n and text[i] != '"':
                buf.append(text[i])
                i += 1
            if i >= n:
                raise InvalidQuerySyntax("unterminated quoted query string")
            i += 1
            token = "".join(buf)
            _validate_value(token, label="quoted query value")
            tokens.append(_Token(token, quoted=True))
            continue
        buf = []
        while i < n and text[i] not in " \t":
            if text[i] == '"':
                raise InvalidQuerySyntax(
                    "double quote is only allowed in a quoted query string"
                )
            buf.append(text[i])
            i += 1
        tokens.append(_Token("".join(buf), quoted=False))
    return tokens


def _parse_value_token(token: _Token) -> str:
    return _validate_value(token.text, label="query value")


@dataclass(frozen=True)
class Expression:
    pass


@dataclass(frozen=True)
class Unrestricted(Expression):
    value: str

    def __post_init__(self) -> None:
        _validate_value(self.value)

    def serialize(self) -> str:
        return _format_query_value(self.value)


@dataclass(frozen=True)
class Attribute(Expression):
    attribute: str
    value: str

    def __post_init__(self) -> None:
        if not _is_id(self.attribute):
            raise InvalidQuerySyntax(f"invalid attribute name: {self.attribute!r}")
        _validate_value(self.value)

    def serialize(self) -> str:
        return f"{self.attribute}={_format_query_value(self.value)}"


@dataclass(frozen=True)
class Boolean(Expression):
    operation: str
    left: Expression
    right: Expression

    def serialize(self) -> str:
        op = self.operation.lower()
        if op not in {"and", "or"}:
            raise InvalidQuerySyntax(f"invalid boolean operator: {self.operation!r}")
        return f"{self.left.serialize()} {op} {self.right.serialize()}"


def _parse_tokens(tokens: Sequence[_Token]) -> Expression:
    if not tokens:
        raise InvalidQuerySyntax("empty query")

    def parse_unary(i: int) -> tuple[Expression, int]:
        if i >= len(tokens):
            raise InvalidQuerySyntax("unexpected end of query")
        token = tokens[i]
        if not token.quoted and _OP_RE.match(token.text):
            raise InvalidQuerySyntax(f"unexpected boolean operator: {token.text!r}")
        if "=" in token.text:
            attr, value = token.text.split("=", 1)
            return Attribute(attr, value), i + 1
        return Unrestricted(_parse_value_token(token)), i + 1

    def parse_binary(i: int) -> Expression:
        left, pos = parse_unary(i)
        while pos < len(tokens):
            token = tokens[pos]
            if token.quoted or not _OP_RE.match(token.text):
                raise InvalidQuerySyntax(f"unexpected query token: {token.text!r}")
            op = token.text.lower()
            right, pos = parse_unary(pos + 1)
            left = Boolean(op, left, right)
        return left

    return parse_binary(0)


def search_values(expression: Expression) -> list[str]:
    if isinstance(expression, Unrestricted):
        return [expression.value]
    if isinstance(expression, Attribute):
        return [expression.value]
    if isinstance(expression, Boolean):
        return [*search_values(expression.left), *search_values(expression.right)]
    raise RwhoisParseError(f"unsupported expression: {expression!r}")


def terms(expression: Expression) -> list[Expression]:
    if isinstance(expression, Boolean):
        return [*terms(expression.left), *terms(expression.right)]
    return [expression]


@dataclass(frozen=True)
class Query:
    expression: Expression
    class_name: str | None = None

    def to_wire(self) -> str:
        if self.class_name is not None:
            if not _is_id(self.class_name):
                raise InvalidQuerySyntax(f"invalid class name: {self.class_name!r}")
            return f"{self.class_name} {self.expression.serialize()}"
        return self.expression.serialize()

    def __str__(self) -> str:
        return self.to_wire()

    @property
    def search_values(self) -> list[str]:
        return search_values(self.expression)

    def is_hierarchical(self) -> bool:
        return any("." in value.strip("*") for value in self.search_values)

    @classmethod
    def unrestricted(cls, value: str) -> "Query":
        return cls(Unrestricted(value))

    @classmethod
    def class_restricted(cls, class_name: str, value: str) -> "Query":
        return cls(Unrestricted(value), class_name=class_name)

    @classmethod
    def attribute(cls, class_name: str | None, attribute: str, value: str) -> "Query":
        return cls(Attribute(attribute, value), class_name=class_name)

    @classmethod
    def and_(
        cls, left: Expression, right: Expression, *, class_name: str | None = None
    ) -> "Query":
        return cls(Boolean("and", left, right), class_name=class_name)

    @classmethod
    def or_(
        cls, left: Expression, right: Expression, *, class_name: str | None = None
    ) -> "Query":
        return cls(Boolean("or", left, right), class_name=class_name)


def parse_expression(text: str) -> Expression:
    return _parse_tokens(_tokenize(text.strip()))


def parse_query(text: str) -> Query:
    text = text.strip()
    if not text:
        raise InvalidQuerySyntax("empty query")
    if text.startswith("-"):
        raise InvalidQuerySyntax("query commands must not start with '-'")
    if text.startswith('"'):
        return Query(parse_expression(text))
    parts = text.split(" ", 1)
    if len(parts) == 1:
        return Query(parse_expression(parts[0]))
    first, rest = parts
    if "=" in first:
        return Query(parse_expression(text))
    if rest.strip().split(" ", 1)[0].lower() in {"and", "or"}:
        return Query(parse_expression(text))
    return Query(parse_expression(rest), class_name=first)


__all__ = [
    "Attribute",
    "Boolean",
    "Expression",
    "Query",
    "Unrestricted",
    "parse_expression",
    "parse_query",
    "search_values",
    "terms",
]
