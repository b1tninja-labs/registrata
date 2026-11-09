"""Schema classes and attribute definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from .errors import ErrorCode, RwhoisParseError
from .records import ObjectRecord

_TRUE = {"ON", "TRUE", "YES", "Y", "1"}
_FALSE = {"OFF", "FALSE", "NO", "N", "0"}


def parse_bool(value: str | None, default: bool = False) -> bool:
    """Read a schema boolean.

    ``None`` means the option was not there, which is what ``default`` is for. An empty string
    means it was there with nothing after the colon: Appendix B gives ``attribute-value`` a
    minimum length of one, so that is malformed rather than absent, and it used to be answered
    with ``False`` -- indistinguishable from a server that had said ``OFF``. The distinction
    matters downstream, because a blank ``required:`` arrived in ``validate_object`` as
    "not required" and stopped it asking for the attribute at all.
    """
    if value is None:
        return default
    token = value.strip().upper()
    if token in _TRUE:
        return True
    if token in _FALSE:
        return False
    raise RwhoisParseError(f"invalid boolean schema value: {value!r}")


def bool_to_on_off(value: bool) -> str:
    return "ON" if value else "OFF"


@dataclass
class AttributeDefinition:
    name: str
    description: str = ""
    type: str = "TEXT"
    format: str = ""
    indexed: bool = False
    required: bool = False
    multi_line: bool = False
    repeatable: bool = False
    primary: bool = False
    hierarchical: bool = False
    private: bool = False
    extra: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.multi_line and self.repeatable:
            raise RwhoisParseError("Multi-Line and Repeatable are mutually exclusive")

    @classmethod
    def from_schema_group(cls, group: dict[str, str]) -> "AttributeDefinition":
        def get(*names: str, default: str = "") -> str:
            for name in names:
                if name in group:
                    return group[name]
                for key, value in group.items():
                    if key.lower() == name:
                        return value
            return default

        def optional(*names: str) -> str | None:
            """Like ``get``, but absence is reported as absence.

            ``get`` answers "not in the group" with an empty string, which is indistinguishable
            from a server that sent the option with nothing after the colon -- and Appendix B
            requires at least one character there, so the two are not the same input. The booleans
            need that difference: a missing option means "use the default", a blank one means the
            schema line is malformed.
            """
            for name in names:
                if name in group:
                    return group[name]
                for key, value in group.items():
                    if key.lower() == name:
                        return value
            return None

        name = get("attribute", "name")
        if not name:
            raise RwhoisParseError("schema group missing attribute name")
        extra = dict(group)
        for key in (
            "class",
            "attribute",
            "name",
            "description",
            "type",
            "format",
            "indexed",
            "required",
            "multi-line",
            "repeatable",
            "primary",
            "hierarchical",
            "private",
        ):
            extra.pop(key, None)
            extra.pop(key.lower(), None)
        return cls(
            name=name,
            description=get("description"),
            type=get("type", default="TEXT").upper(),
            format=get("format"),
            indexed=parse_bool(optional("indexed")),
            required=parse_bool(optional("required")),
            multi_line=parse_bool(optional("multi-line", "multi_line")),
            repeatable=parse_bool(optional("repeatable")),
            primary=parse_bool(optional("primary")),
            hierarchical=parse_bool(optional("hierarchical")),
            private=parse_bool(optional("private")),
            extra=extra,
        )

    def to_schema_lines(self, class_name: str) -> list[str]:
        prefix = f"%schema {class_name}"
        lines = [
            f"{prefix}:attribute:{self.name}",
            f"{prefix}:description:{self.description}",
            f"{prefix}:type:{self.type}",
        ]
        if self.format:
            lines.append(f"{prefix}:format:{self.format}")
        lines.extend(
            [
                f"{prefix}:indexed:{bool_to_on_off(self.indexed)}",
                f"{prefix}:required:{bool_to_on_off(self.required)}",
                f"{prefix}:multi-line:{bool_to_on_off(self.multi_line)}",
                f"{prefix}:repeatable:{bool_to_on_off(self.repeatable)}",
                f"{prefix}:primary:{bool_to_on_off(self.primary)}",
                f"{prefix}:hierarchical:{bool_to_on_off(self.hierarchical)}",
                f"{prefix}:private:{bool_to_on_off(self.private)}",
            ]
        )
        for key, value in self.extra.items():
            lines.append(f"{prefix}:{key}:{value}")
        lines.append("%schema")
        return lines


@dataclass
class SchemaClass:
    class_name: str
    description: str = ""
    version: str = "19700101000000000"
    attributes: list[AttributeDefinition] = field(default_factory=list)
    extra: dict[str, str] = field(default_factory=dict)

    def add(self, attr: AttributeDefinition) -> "SchemaClass":
        for existing in self.attributes:
            if existing.name.lower() == attr.name.lower():
                self.attributes[self.attributes.index(existing)] = attr
                return self
        self.attributes.append(attr)
        return self

    def get(self, name: str) -> AttributeDefinition | None:
        lowered = name.lower()
        for attr in self.attributes:
            if attr.name.lower() == lowered:
                return attr
        return None

    def to_schema_lines(self) -> list[str]:
        lines: list[str] = []
        for attr in self.attributes:
            lines.extend(attr.to_schema_lines(self.class_name))
        return lines

    def to_class_lines(self) -> list[str]:
        lines = [
            f"%class {self.class_name}:description:{self.description or self.class_name}",
            f"%class {self.class_name}:version:{self.version}",
        ]
        for key, value in self.extra.items():
            lines.append(f"%class {self.class_name}:{key}:{value}")
        lines.append("%class")
        return lines


def base_attributes() -> list[AttributeDefinition]:
    return [
        AttributeDefinition(
            "Class-Name", "Type of the object", required=True, indexed=True
        ),
        AttributeDefinition(
            "Auth-Area",
            "Authority area for the object",
            required=True,
            indexed=True,
            hierarchical=True,
        ),
        AttributeDefinition(
            "ID",
            "Globally unique object identifier",
            required=True,
            indexed=True,
            hierarchical=True,
            primary=True,
        ),
        AttributeDefinition("Updated", "Time of last modification", required=True),
        AttributeDefinition(
            "Guardian", "Link to guardian object", type="ID", repeatable=True
        ),
        AttributeDefinition("Private", "Object visibility flag"),
        AttributeDefinition("TTL", "Object time-to-live in seconds"),
    ]


def standard_classes() -> list[SchemaClass]:
    referral = SchemaClass(
        "referral",
        description="Referral information",
        attributes=[
            AttributeDefinition(
                "Referral",
                "RWhois URL for this referral",
                type="SEE-ALSO",
                required=True,
                repeatable=True,
            ),
            AttributeDefinition(
                "Referral-By",
                "Authority areas served by the referral",
                type="TEXT",
                required=True,
                repeatable=True,
                hierarchical=True,
            ),
            AttributeDefinition(
                "Class-Name",
                "Class to restrict referral query",
                type="TEXT",
                required=False,
                repeatable=True,
            ),
            AttributeDefinition(
                "Description",
                "Description of this referral",
                type="TEXT",
                required=False,
            ),
        ],
    )
    guardian = SchemaClass(
        "guardian",
        description="Guardian information",
        attributes=[
            AttributeDefinition(
                "Guarded-Auth-Area",
                "Guarded authority area",
                required=True,
                repeatable=True,
                hierarchical=True,
            ),
            AttributeDefinition(
                "Guarded-Class-Name", "Guarded class", required=False, repeatable=True
            ),
            AttributeDefinition(
                "Guarded-Attribute-Name",
                "Guarded attribute",
                required=False,
                repeatable=True,
            ),
            AttributeDefinition("Type", "Guardian type", required=True),
            # Section 2.3.6 requires both. `Guard-Scheme` names the authentication
            # methodology and dictates the form of `Guard-Info`, whose RFC-given
            # examples are a password or a PGP key id; the spec also says it should
            # not be displayed, which is what `Private` is for.
            AttributeDefinition("Guard-Scheme", "Guard scheme", required=True),
            AttributeDefinition(
                "Guard-Info", "Guard scheme data", required=True, private=True
            ),
        ],
    )
    return [referral, guardian]


def base_schema_class(class_name: str) -> SchemaClass:
    return SchemaClass(
        class_name,
        description=f"{class_name} information",
        attributes=base_attributes(),
    )


#: Protocol attributes that every class carries whether or not the schema repeats
#: them, so an object holding one is not using an undeclared attribute.
RESERVED_ATTRIBUTES = frozenset({"class-name", "auth-area", "id", "updated"})

#: Assigned by the server during registration. Section 3.3.9 says the client *must
#: not* send them, yet a schema marks them required because a stored object always
#: has them -- so the required check has to exempt them here, or every `add` would
#: be refused for omitting an attribute it is forbidden to supply.
SERVER_ASSIGNED_ATTRIBUTES = frozenset({"id", "updated"})

#: Types whose value form Appendix B pins down exactly enough to reject a bad one.
#: TEXT/EMAIL/NAME/PHONE carry a prose description instead, and inventing a grammar
#: for those would reject data the protocol allows, so they are left unenforced --
#: and said out loud rather than quietly skipped.
_SYNTAX_CHECKS: dict[str, tuple[re.Pattern[str], str]] = {
    "SEE-ALSO": (re.compile(r"^[A-Za-z0-9._-]+:\d{1,5}:\S+$"), "host:port:auth-area"),
    "NUMBER": (re.compile(r"^\d+$"), "digits only"),
}


def _structural_problems(
    obj: ObjectRecord,
    schema: SchemaClass,
    *,
    ignore_required_for: frozenset[str] = frozenset(),
) -> list[tuple[int, str]]:
    """(code, message) for each way an object departs from its class definition."""
    problems: list[tuple[int, str]] = []
    counts: dict[str, int] = {}
    valued: dict[str, int] = {}
    for attr in obj.attributes:
        key = attr.name.lower()
        counts[key] = counts.get(key, 0) + 1
        if attr.value.strip():
            valued[key] = valued.get(key, 0) + 1
    for attr_def in schema.attributes:
        key = attr_def.name.lower()
        count = counts.get(key, 0)
        if attr_def.required and key not in ignore_required_for:
            if count == 0:
                problems.append(
                    (
                        int(ErrorCode.REQUIRED_ATTRIBUTE_MISSING),
                        f"required attribute missing: {attr_def.name}",
                    )
                )
            elif not valued.get(key):
                problems.append(
                    (
                        int(ErrorCode.REQUIRED_ATTRIBUTE_MISSING),
                        f"required attribute has no value: {attr_def.name}",
                    )
                )
        if count > 1 and not (attr_def.repeatable or attr_def.multi_line):
            problems.append(
                (
                    int(ErrorCode.INVALID_ATTRIBUTE_SYNTAX),
                    f"non-repeatable attribute repeated: {attr_def.name}",
                )
            )
    return problems


def validate_object(obj: ObjectRecord, schema: SchemaClass) -> list[str]:
    """Structural check that an object satisfies its class definition.

    Checked: every required attribute is present *with a value* -- Appendix B defines
    ``attribute-value = 1*any-char``, one or more characters, so an ``ID:`` line with nothing
    after the colon supplies nothing the schema can use -- and no attribute repeats unless the
    schema allows it. Attribute names compare case-insensitively, as the protocol requires.

    Not checked, stated plainly because a validator that stays silent reads as one that passed:
    value type and format; attributes the class never declared; and repetition of a multi-line
    attribute, which this parser cannot tell apart from a multi-line value because it has no
    continuation-line support, so flagging it would invent violations. Registration wants all
    of those, and wants each labelled with its own Appendix C code: see
    :func:`validate_for_registration`.
    """
    return [message for _code, message in _structural_problems(obj, schema)]


def validate_for_registration(
    obj: ObjectRecord, schema: SchemaClass
) -> list[tuple[int, str]]:
    """Validate an object a client is registering, naming the error for each problem.

    ``validate_object`` answers "does this object fit its class". Registration needs
    more, because Appendix C gives a different code to each way an object can be wrong
    and a server that replies 322 where it meant 320 tells the client nothing about
    what to change. Reported here, in addition to the structural checks:

    * an attribute the class never declares -- 320 Invalid attribute;
    * a value that is empty, since Appendix B requires one character minimum -- 321;
    * a value whose form contradicts its declared type, for the types whose form
      Appendix B fixes exactly (SEE-ALSO, NUMBER) -- 321.

    Attributes whose schema gives only a prose description are not checked, and a
    caller that needs to know why should read this docstring rather than assume a
    pass means a full inspection.
    """
    problems = _structural_problems(
        obj, schema, ignore_required_for=SERVER_ASSIGNED_ATTRIBUTES
    )
    declared = {attr_def.name.lower(): attr_def for attr_def in schema.attributes}

    for attr in obj.attributes:
        key = attr.name.lower()
        if not attr.value.strip():
            problems.append(
                (
                    int(ErrorCode.INVALID_ATTRIBUTE_SYNTAX),
                    f"attribute has no value: {attr.name}",
                )
            )
        attr_def = declared.get(key)
        if attr_def is None:
            if key in RESERVED_ATTRIBUTES:
                continue
            problems.append(
                (int(ErrorCode.INVALID_ATTRIBUTE), f"undeclared attribute: {attr.name}")
            )
            continue
        check = _SYNTAX_CHECKS.get(attr_def.type.upper())
        if check is None or not attr.value.strip():
            continue
        pattern, expected = check
        if not pattern.match(attr.value):
            problems.append(
                (
                    int(ErrorCode.INVALID_ATTRIBUTE_SYNTAX),
                    f"{attr.name} does not match {attr_def.type} ({expected})",
                )
            )
    return problems


__all__ = [
    "AttributeDefinition",
    "RESERVED_ATTRIBUTES",
    "SERVER_ASSIGNED_ATTRIBUTES",
    "SchemaClass",
    "base_attributes",
    "base_schema_class",
    "bool_to_on_off",
    "parse_bool",
    "standard_classes",
    "validate_for_registration",
    "validate_object",
]
