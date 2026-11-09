"""Simple in-memory RWhois backend for tests, demos, and local servers."""

from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from ..errors import (
    FailedToUpdateOutdatedObject,
    InvalidAttribute,
    InvalidAuthorityArea,
    InvalidClass,
    ObjectNotFound,
    ObjectReferenceNotFound,
    PrimaryKeyNotUnique,
    RwhoisParseError,
)
from ..query import Attribute, Boolean, Expression, Query, Unrestricted
from ..records import ObjectRecord, Referral
from ..schema import AttributeDefinition, SchemaClass, base_attributes
from ..soa import SOARecord, format_timestamp
from .base import RwhoisBackend, SearchResult


@dataclass
class ReferralRule:
    referred_auth_area: str
    host: str
    port: int
    auth_area: str | None = None
    kind: str = "link"

    def matches(self, value: str) -> bool:
        value = value.strip().lower().strip("*")
        target = self.referred_auth_area.lower()
        if not target:
            return True
        return value == target or value.endswith("." + target)


def _matches(value: str, pattern: str) -> bool:
    value = value.lower()
    pattern = pattern.lower()
    if pattern == "*":
        return True
    if pattern.startswith("*") and pattern.endswith("*") and len(pattern) > 2:
        return pattern[1:-1] in value
    if pattern.startswith("*"):
        return value.endswith(pattern[1:])
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


def _expression_matches(
    obj: ObjectRecord, expr: Expression, class_name: str | None
) -> bool:
    if class_name is not None and obj.class_name.lower() != class_name.lower():
        return False
    if isinstance(expr, Unrestricted):
        return any(_matches(attr.value, expr.value) for attr in obj.attributes)
    if isinstance(expr, Attribute):
        return any(
            attr.name.lower() == expr.attribute.lower()
            and _matches(attr.value, expr.value)
            for attr in obj.attributes
        )
    if isinstance(expr, Boolean):
        left = _expression_matches(obj, expr.left, class_name)
        right = _expression_matches(obj, expr.right, class_name)
        return left and right if expr.operation.lower() == "and" else left or right
    return False


class MemoryBackend(RwhoisBackend):
    def __init__(self, default_auth_area: str | None = None) -> None:
        self.authority_areas: dict[str, SOARecord] = {}
        self.classes: dict[str, dict[str, SchemaClass]] = defaultdict(dict)
        self.objects: dict[str, list[ObjectRecord]] = defaultdict(list)
        self.referral_rules: list[ReferralRule] = []
        self.default_auth_area = default_auth_area
        self.auth_passwords: set[str] = set()
        self.register_counter = 0
        if default_auth_area:
            self.add_soa(default_auth_area, primary=f"{default_auth_area}:4321")

    @property
    def support_register(self) -> bool:
        return True

    @property
    def support_security(self) -> bool:
        return bool(self.auth_passwords)

    def add_soa(self, authority_area: str, **kwargs: Any) -> SOARecord:
        kwargs.setdefault("primary", f"{authority_area}:4321")
        kwargs.setdefault("tech_contact", f"admin@{authority_area or 'invalid'}")
        kwargs.setdefault("admin_contact", f"admin@{authority_area or 'invalid'}")
        kwargs.setdefault("hostmaster", f"hostmaster@{authority_area or 'invalid'}")
        soa = SOARecord(authority=authority_area, **kwargs)
        self.authority_areas[authority_area] = soa
        return soa

    def add_class(self, authority_area: str, cls: SchemaClass) -> None:
        self.classes[authority_area][cls.class_name.lower()] = cls

    def add_referral(
        self,
        referred_auth_area: str,
        host: str,
        port: int,
        *,
        auth_area: str | None = None,
        kind: str = "link",
    ) -> None:
        self.referral_rules.append(
            ReferralRule(referred_auth_area.lower(), host, int(port), auth_area, kind)
        )

    def add_password(self, password: str) -> None:
        self.auth_passwords.add(password)

    def ensure_class(
        self, authority_area: str, class_name: str, obj: ObjectRecord | None = None
    ) -> SchemaClass:
        key = class_name.lower()
        cls = self.classes[authority_area].get(key)
        if cls is None:
            cls = SchemaClass(
                class_name,
                description=f"{class_name} information",
                attributes=base_attributes(),
            )
            self.add_class(authority_area, cls)
        if obj is not None:
            for attr in obj.attributes:
                if cls.get(attr.name) is None:
                    cls.add(
                        AttributeDefinition(
                            attr.name,
                            description=attr.name,
                            type={"T": "TEXT", "I": "ID", "S": "SEE-ALSO"}[attr.type],
                            repeatable=True,
                        )
                    )
        return cls

    def add_object(
        self,
        class_name: str,
        attrs: dict[str, Any] | ObjectRecord,
        *,
        auth_area: str | None = None,
        id: str | None = None,
        updated: str | None = None,
    ) -> ObjectRecord:
        if isinstance(attrs, ObjectRecord):
            obj = ObjectRecord(attrs.class_name, list(attrs.attributes))
        else:
            obj = ObjectRecord.from_mapping(class_name, attrs)
        area = (
            auth_area
            or obj.get("Auth-Area")
            or self.default_auth_area
            or next(iter(self.authority_areas), "")
        )
        if not area:
            raise RwhoisParseError(
                "auth_area is required when no authority area exists"
            )
        obj.add("Class-Name", class_name)
        obj.add("Auth-Area", area)
        if id is not None:
            obj.add("ID", id)
        elif obj.get("ID") is None:
            self.register_counter += 1
            local = (
                obj.get(class_name.capitalize() + "-Name")
                or obj.get("Host-Name")
                or obj.get("Domain-Name")
                or obj.get("ID")
                or str(self.register_counter)
            )
            local = re.sub(r"[^A-Za-z0-9_-]+", "-", local).strip("-") or str(
                self.register_counter
            )
            obj.add("ID", f"{local}.{area}")
        if updated is not None:
            obj.add("Updated", updated)
        elif obj.get("Updated") is None:
            obj.add("Updated", format_timestamp(dt.datetime.now(dt.timezone.utc)))
        self.ensure_class(area, class_name, obj)
        self.objects[area].append(obj)
        self.bump_serial(area)
        # Annotated to return the record and used to return None, which silently
        # broke any caller that chained on the result.
        return obj

    def bump_serial(self, authority_area: str) -> None:
        soa = self.authority_areas.get(authority_area)
        if soa is not None:
            soa.serial = format_timestamp(dt.datetime.now(dt.timezone.utc))

    def _registration_area(self, obj: ObjectRecord) -> str:
        """The authority area an object claims, checked against what we serve."""
        area = obj.auth_area or self.default_auth_area or ""
        if area not in self.authority_areas:
            raise InvalidAuthorityArea(
                f"unknown authority area: {area or '(none given)'}"
            )
        return area

    def _registration_class(self, area: str, class_name: str) -> SchemaClass:
        """The class definition a registered object has to satisfy.

        Refusing a class this server does not advertise is deliberate: inventing a
        class on the spot would validate the object against a schema written to fit
        it, which is not validation.
        """
        cls = self.classes.get(area, {}).get(class_name.lower())
        if cls is None:
            raise InvalidClass(f"unknown class {class_name} for authority area {area}")
        return cls

    def _find_by_id(self, obj_id: str, *, area: str) -> tuple[str, int, ObjectRecord]:
        preferred = [area] + [other for other in self.objects if other != area]
        for candidate in preferred:
            for index, stored in enumerate(self.objects.get(candidate, [])):
                if stored.id == obj_id:
                    return candidate, index, stored
        raise ObjectNotFound(f"no object with ID {obj_id}")

    def _check_primary_keys(
        self,
        area: str,
        cls: SchemaClass,
        obj: ObjectRecord,
        *,
        exclude_id: str | None = None,
    ) -> None:
        """Reject a primary-key value another object in the class already holds.

        `exclude_id` is the record being replaced: without it an update collides
        with its own stored object and every `mod` would answer 324.
        """
        others = [
            stored
            for stored in self.objects.get(area, [])
            if exclude_id is None or stored.id != exclude_id
        ]
        if obj.id and any(stored.id == obj.id for stored in others):
            raise PrimaryKeyNotUnique(f"ID already registered: {obj.id}")
        for key in (attr.name for attr in cls.attributes if attr.primary):
            mine = {value.strip().lower() for value in obj.getall(key) if value.strip()}
            if not mine:
                continue
            for stored in others:
                if stored.class_name.lower() != obj.class_name.lower():
                    continue
                theirs = {
                    value.strip().lower()
                    for value in stored.getall(key)
                    if value.strip()
                }
                if mine & theirs:
                    raise PrimaryKeyNotUnique(
                        f"{key} is already registered in {area}: "
                        f"{sorted(mine & theirs)[0]}"
                    )

    def create_object(self, obj: ObjectRecord) -> ObjectRecord:
        """Store an object a client registered, assigning ID and Updated.

        RFC 2167 section 3.3.9 gives those two to the server, to return in the
        response, so a client that sent either is refused rather than silently
        overwritten: an overwrite would answer `%ok` while ignoring the identity
        the client asked for.
        """
        area = self._registration_area(obj)
        cls = self._registration_class(area, obj.class_name)
        if obj.get("ID") is not None or obj.get("Updated") is not None:
            raise InvalidAttribute("ID and Updated are assigned by the server")
        self._check_primary_keys(area, cls, obj)
        self.register_counter += 1
        stored = ObjectRecord(obj.class_name, list(obj.attributes))
        stored.add("ID", f"{self.register_counter:08d}.{area}")
        stored.add("Updated", format_timestamp(dt.datetime.now(dt.timezone.utc)))
        self.objects[area].append(stored)
        self.bump_serial(area)
        return stored

    def update_object(
        self, obj: ObjectRecord, *, identifying_updated: str | None = None
    ) -> ObjectRecord:
        """Replace the stored object with the one the client sent.

        `identifying_updated` is the `Updated` value from the half before `_NEW_`.
        If it no longer matches what is stored, someone changed the record after
        the client read it, and writing over their work unnoticed is exactly the
        failure Appendix C's 325 exists to report.
        """
        area = self._registration_area(obj)
        cls = self._registration_class(area, obj.class_name)
        if obj.id is None:
            raise ObjectReferenceNotFound("mod requires the ID attribute")
        stored_area, index, stored = self._find_by_id(obj.id, area=area)
        if stored_area != area:
            raise ObjectReferenceNotFound(
                f"ID {obj.id} is not in authority area {area}"
            )
        if stored.class_name.lower() != obj.class_name.lower():
            raise ObjectReferenceNotFound(
                "Class-Name does not match the object identified by ID"
            )
        if (
            identifying_updated is not None
            and (stored.updated or "") != identifying_updated
        ):
            raise FailedToUpdateOutdatedObject(
                f"stored object updated at {stored.updated}, client read "
                f"{identifying_updated}"
            )
        replacement = ObjectRecord(
            obj.class_name,
            [a for a in obj.attributes if a.name.lower() not in {"id", "updated"}],
        )
        replacement.add("ID", stored.id)
        replacement.add("Updated", format_timestamp(dt.datetime.now(dt.timezone.utc)))
        self._check_primary_keys(stored_area, cls, replacement, exclude_id=stored.id)
        self.objects[stored_area][index] = replacement
        self.bump_serial(stored_area)
        return replacement

    def delete_object(self, obj: ObjectRecord) -> None:
        """Remove the object a client identified by ID (and, if given, Updated)."""
        if obj.id is None:
            raise ObjectReferenceNotFound("del requires the ID attribute")
        area = obj.auth_area or self.default_auth_area or ""
        stored_area, index, stored = self._find_by_id(obj.id, area=area)
        if obj.updated and stored.updated and obj.updated != stored.updated:
            raise FailedToUpdateOutdatedObject(
                f"stored object updated at {stored.updated}, client read {obj.updated}"
            )
        del self.objects[stored_area][index]
        self.bump_serial(stored_area)

    def list_authority_areas(self) -> list[str]:
        return sorted(set(self.authority_areas) | set(self.objects))

    def get_soa(self, authority_area: str) -> SOARecord | None:
        return self.authority_areas.get(authority_area)

    def get_schema(
        self, authority_area: str, class_names: Iterable[str] | None = None
    ) -> list[SchemaClass]:
        by_class = self.classes.get(authority_area, {})
        if class_names is None:
            return list(by_class.values())
        wanted = {name.lower() for name in class_names}
        return [cls for name, cls in by_class.items() if name in wanted]

    def get_classes(
        self, authority_area: str, class_names: Iterable[str] | None = None
    ) -> list[SchemaClass]:
        return self.get_schema(authority_area, class_names)

    def object_count(self) -> int:
        return sum(len(v) for v in self.objects.values())

    def all_objects(self) -> list[ObjectRecord]:
        return [
            obj
            for area in self.list_authority_areas()
            for obj in self.objects.get(area, [])
        ]

    def get_referrals(self, query: Query) -> list[Referral]:
        refs: list[Referral] = []
        seen: set[tuple[str, int, str]] = set()
        for value in query.search_values:
            for rule in self.referral_rules:
                if rule.matches(value):
                    auth = rule.auth_area or rule.referred_auth_area
                    referral = Referral(rule.host, rule.port, auth)
                    if referral.key not in seen:
                        refs.append(referral)
                        seen.add(referral.key)
        return refs

    def search(
        self, query: Query, *, limit: int | None = None, session: Any = None
    ) -> SearchResult:
        matches = [
            obj
            for obj in self.all_objects()
            if _expression_matches(obj, query.expression, query.class_name)
        ]
        matches.sort(key=lambda obj: obj.id or "")
        if limit is not None and len(matches) > limit:
            return SearchResult(objects=matches[:limit], exceeded_limit=True)
        if not matches:
            refs = self.get_referrals(query)
            return SearchResult(referrals=refs)
        return SearchResult(objects=matches)

    def export(
        self,
        authority_area: str,
        class_names: Iterable[str] | None = None,
        attributes: Iterable[str] | None = None,
        serial_number: str | None = None,
    ) -> list[ObjectRecord]:
        objects = self.objects.get(authority_area, [])
        if class_names is not None:
            wanted = {name.lower() for name in class_names}
            objects = [obj for obj in objects if obj.class_name.lower() in wanted]
        attrs = list(attributes or [])
        out = []
        for obj in objects:
            if attrs:
                lower_attrs = {a.lower() for a in attrs}
                obj_attrs = [
                    attr for attr in obj.attributes if attr.name.lower() in lower_attrs
                ]
                if not obj_attrs:
                    continue
                obj = ObjectRecord(obj.class_name, obj_attrs)
            out.append(obj)
        return out

    supports_object_lookup = True

    def get_object_by_id(
        self, authority_area: str, object_id: str
    ) -> ObjectRecord | None:
        for stored in self.objects.get(authority_area, []):
            if stored.id == object_id:
                return stored
        return None

    def authenticate(self, password: str) -> bool:
        return password in self.auth_passwords

    def notify(self, event: str, *args: str) -> bool:
        return True


__all__ = ["MemoryBackend", "ReferralRule"]
