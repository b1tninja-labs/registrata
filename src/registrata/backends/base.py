"""Abstract backend interface used by the in-process RWhois server."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..query import Query
from ..records import ObjectRecord, Referral
from ..schema import SchemaClass
from ..soa import SOARecord


@dataclass
class SearchResult:
    objects: list[ObjectRecord] = field(default_factory=list)
    referrals: list[Referral] = field(default_factory=list)
    exceeded_limit: bool = False
    error_code: int | None = None
    error_text: str | None = None


class RwhoisBackend(ABC):
    """Minimal lookup backend required for queries, SOA, and schema."""

    support_register: bool = False
    support_security: bool = False
    support_xfer: bool = True
    support_notify: bool = False

    @abstractmethod
    def list_authority_areas(self) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def get_soa(self, authority_area: str) -> SOARecord | None:
        raise NotImplementedError

    @abstractmethod
    def get_schema(
        self, authority_area: str, class_names: Iterable[str] | None = None
    ) -> list[SchemaClass]:
        raise NotImplementedError

    @abstractmethod
    def get_classes(
        self, authority_area: str, class_names: Iterable[str] | None = None
    ) -> list[SchemaClass]:
        raise NotImplementedError

    @abstractmethod
    def search(
        self, query: Query, *, limit: int | None = None, session: Any = None
    ) -> SearchResult:
        raise NotImplementedError

    @abstractmethod
    def object_count(self) -> int:
        raise NotImplementedError

    def get_referrals(self, query: Query) -> list[Referral]:
        return []

    def export(
        self,
        authority_area: str,
        class_names: Iterable[str] | None = None,
        attributes: Iterable[str] | None = None,
        serial_number: str | None = None,
    ) -> list[ObjectRecord]:
        raise NotImplementedError

    def create_object(self, obj: ObjectRecord) -> ObjectRecord:
        """Store a new object and return it with the server-assigned ID/Updated."""
        raise NotImplementedError

    def update_object(
        self, obj: ObjectRecord, *, identifying_updated: str | None = None
    ) -> ObjectRecord:
        """Replace the object `obj` identifies.

        `identifying_updated` carries the `Updated` value the client read before
        editing, from the half of a `mod` before `_NEW_`. A backend that has it
        should refuse to overwrite a record someone else changed since -- Appendix
        C's 325 -- rather than lose their edit in silence.
        """
        raise NotImplementedError

    def delete_object(self, obj: ObjectRecord) -> None:
        """Remove the object `obj` identifies."""
        raise NotImplementedError

    #: Whether `get_object_by_id` can be trusted to answer "not there" rather than
    #: "this backend cannot look things up". Guardians are only enforced when a
    #: backend says True, because a check silently skipped reads as a check passed.
    supports_object_lookup = False

    def get_object_by_id(
        self, authority_area: str, object_id: str
    ) -> ObjectRecord | None:
        """Return one stored object by ID, or None when it is not there.

        Guardian enforcement needs to read the guardian objects an object points at.
        The default cannot answer, so it advertises that through
        :attr:`supports_object_lookup` and the server logs that guardians are not
        being checked instead of pretending otherwise.
        """
        return None

    def authenticate(self, password: str) -> bool:
        return False

    def notify(self, event: str, *args: str) -> bool:
        return False


__all__ = ["RwhoisBackend", "SearchResult"]
