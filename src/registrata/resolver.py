"""Referral-following resolver."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

from .client import RwhoisClient
from .protocol import QueryResult
from .query import Query
from .records import ObjectRecord, Referral


@dataclass
class ResolutionNode:
    referral: Referral
    depth: int


@dataclass
class ResolutionResult:
    objects: list[ObjectRecord] = field(default_factory=list)
    referrals: list[Referral] = field(default_factory=list)
    errors: list[QueryResult] = field(default_factory=list)
    path: list[tuple[Referral, QueryResult]] = field(default_factory=list)
    stopped_reason: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.objects) or any(r.ok for _, r in self.path)


class RwhoisResolver:
    def __init__(
        self,
        root: str,
        port: int = 4321,
        *,
        max_referrals: int = 20,
        max_depth: int = 10,
        timeout: float | None = 10.0,
        limit: int | None = 20,
    ):
        self.root = root
        self.port = int(port)
        self.max_referrals = int(max_referrals)
        self.max_depth = int(max_depth)
        self.timeout = timeout
        self.limit = limit

    def resolve(
        self, query: str | Query, class_name: str | None = None
    ) -> ResolutionResult:
        q = (
            query
            if isinstance(query, Query)
            else (
                Query.class_restricted(class_name, query)
                if class_name
                else Query.unrestricted(query)
            )
        )
        start = Referral(self.root, self.port, ".")
        pending = deque([ResolutionNode(start, 0)])
        visited_auth_areas: set[str] = set()
        visited_servers: set[tuple[str, int]] = set()
        result = ResolutionResult()

        while pending:
            if len(result.path) >= self.max_referrals:
                result.stopped_reason = "max_referrals"
                break
            node = pending.popleft()
            if node.depth > self.max_depth:
                result.stopped_reason = "max_depth"
                continue
            server_key = (node.referral.host.lower(), int(node.referral.port))
            if server_key in visited_servers:
                continue
            visited_servers.add(server_key)
            try:
                with RwhoisClient.connect(
                    node.referral.host, node.referral.port, timeout=self.timeout
                ) as client:
                    if self.limit is not None:
                        client.limit(self.limit)
                    query_result = client.query(class_name, q, raise_errors=False)
            except OSError:
                result.stopped_reason = "connection_error"
                continue

            result.path.append((node.referral, query_result))
            result.objects.extend(query_result.objects)
            result.referrals.extend(query_result.referrals)
            if query_result.error_code is not None:
                result.errors.append(query_result)

            for referral in dedupe_referrals(query_result.referrals):
                if referral.area_key in visited_auth_areas and referral.area_key != ".":
                    continue
                visited_auth_areas.add(referral.area_key)
                pending.append(ResolutionNode(referral, node.depth + 1))

        if not result.stopped_reason:
            result.stopped_reason = "complete"
        return result


def dedupe_referrals(referrals: Iterable[Referral]) -> list[Referral]:
    seen: set[str] = set()
    out: list[Referral] = []
    for referral in referrals:
        key = referral.area_key
        if key in seen:
            continue
        seen.add(key)
        out.append(referral)
    return out


__all__ = ["RwhoisResolver", "ResolutionNode", "ResolutionResult", "dedupe_referrals"]
