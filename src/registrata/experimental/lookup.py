"""Experimental unified lookup surface."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .._flags import ExperimentalFeature, is_enabled
from ..cache import Cache
from ..circuitbreaker import CircuitBreakerRegistry, CircuitOpen
from ..client import RwhoisClient
from ..model import RegistrationRecord, from_rwhois_object
from ..observability import log_event
from ..ratelimit import RateLimiterRegistry
from ..retry import Backoff
from ..special_names import special_use_reason
from . import rdap, whois

logger = logging.getLogger(__name__)

# Why a source failed, so callers do not have to match on message text.
ERROR_CIRCUIT_OPEN = "circuit_open"
ERROR_DISABLED = "disabled"
ERROR_CONFIG = "configuration"


@dataclass
class LookupErrorItem:
    source: str
    message: str
    # Why the source failed, so callers can branch without string matching:
    # "circuit_open" when the endpoint is being left alone, "disabled" when the
    # feature flag is off, and None for an ordinary source error.
    kind: str | None = None


@dataclass
class LookupResult:
    resource: str
    kind: str | None = None
    sources: list[str] = field(default_factory=list)
    results: dict[str, Any] = field(default_factory=dict)
    normalized: dict[str, Any] = field(default_factory=dict)
    records: list[RegistrationRecord] = field(default_factory=list)
    errors: list[LookupErrorItem] = field(default_factory=list)
    breaker: CircuitBreakerRegistry | None = None
    #: Set when the resource names something no registry can serve, so no source
    #: was asked. Neither a failure nor a miss: by construction there was nothing
    #: to find, and no endpoint spent quota on it.
    unqueryable: str | None = None

    @property
    def ok(self) -> bool:
        """True when at least one source answered.

        A source that failed contributes an entry in ``errors`` and nothing in ``results``, so this
        cannot report success for a lookup in which nothing replied. An authoritative empty answer
        -- an RWhois ``230 No objects found`` -- did answer, so it counts here; ``records`` is what
        says whether anything was found.
        """
        return bool(self.results)

    def provenance(self) -> dict[str, Any]:
        """Return source provenance and referral hop trace metadata."""
        out: dict[str, Any] = {
            "resource": self.resource,
            "sources": list(self.sources),
            "hops": [],
        }
        for source, item in self.results.items():
            if source == "rdap" and hasattr(item, "data"):
                out["hops"].append(
                    {
                        "source": source,
                        "type": "rdap",
                        "url": getattr(item, "url", None),
                        "status": getattr(item, "status", None),
                        "error": getattr(item, "error", None),
                    }
                )
            elif source == "whois" and hasattr(item, "raw"):
                out["hops"].append(
                    {
                        "source": source,
                        "type": "whois",
                        "server": getattr(item, "server", None),
                        "port": getattr(item, "port", None),
                        "referrals": list(getattr(item, "referrals", []) or []),
                        "error": getattr(item, "error", None),
                    }
                )
            elif source == "rwhois" and hasattr(item, "raw_lines"):
                out["hops"].append(
                    {
                        "source": source,
                        "type": "rwhois",
                        "server": getattr(item, "server", None),
                        "port": getattr(item, "port", None),
                        "query": getattr(item, "query", None),
                        "referrals": getattr(item, "referral_urls", lambda: [])(),
                        "ok": getattr(item, "ok", None),
                        "error_code": getattr(item, "error_code", None),
                        "error_text": getattr(item, "error_text", None),
                    }
                )
        if self.breaker is not None:
            out["circuit_breakers"] = self.breaker.snapshot()
        return out

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "resource": self.resource,
            "kind": self.kind,
            "sources": self.sources,
            "ok": self.ok,
            "unqueryable": self.unqueryable,
            "errors": [
                {"source": item.source, "message": item.message, "kind": item.kind}
                for item in self.errors
            ],
            "provenance": self.provenance(),
            "records": [record.as_dict() for record in self.records],
            "results": {},
        }
        for source, item in self.results.items():
            if source == "rdap" and hasattr(item, "data"):
                # HTTP context is folded into the record so that RFC 8288 Link
                # headers and the transport metadata travel with the result.
                rdap_record = (
                    rdap.normalize_rdap(
                        item.data,
                        headers=getattr(item, "headers", None),
                        url=getattr(item, "url", None),
                        status=getattr(item, "status", None),
                    )
                    if item.data
                    else None
                )
                data["results"][source] = {
                    "url": item.url,
                    "status": item.status,
                    "headers": getattr(item, "headers", {}),
                    "cache_mode": getattr(item, "cache_mode", None),
                    "stale": getattr(item, "stale", False),
                    "error": item.error,
                    "normalized": rdap_record.as_dict()
                    if rdap_record is not None
                    else {},
                    # RFC 9083 section 4.2 "related" links worth following,
                    # already screened for incomplete and loop-forming targets.
                    "referrals": [link.get("href") for link in rdap_record.referrals()]
                    if rdap_record is not None
                    else [],
                    "incomplete": rdap_record.incomplete
                    if rdap_record is not None
                    else False,
                }
            elif source == "whois" and hasattr(item, "raw"):
                data["results"][source] = {
                    "server": item.server,
                    "port": item.port,
                    "raw": item.raw,
                    "fields": item.fields,
                    "referrals": item.referrals,
                    "normalized": item.normalized().as_dict() if item.fields else {},
                    "error": item.error,
                }
            elif source == "rwhois" and hasattr(item, "raw_lines"):
                objects = list(getattr(item, "objects", []))
                data["results"][source] = {
                    "ok": item.ok,
                    "error_code": item.error_code,
                    "error_text": item.error_text,
                    "objects": [obj.as_dict() for obj in objects],
                    "normalized": [
                        from_rwhois_object(obj).as_dict() for obj in objects
                    ],
                    "referrals": [r.url for r in getattr(item, "referrals", [])],
                    "raw_lines": item.raw_lines,
                }
            else:
                data["results"][source] = repr(item)
        return data


def _is_rdap_endpoint_failure(item: Any) -> bool:
    if getattr(item, "error", None):
        return True
    status = getattr(item, "status", None)
    return isinstance(status, int) and (status == 429 or status >= 500)


def _is_whois_endpoint_failure(item: Any) -> bool:
    return bool(getattr(item, "error", None))


def _is_rwhois_endpoint_failure(item: Any) -> bool:
    error_code = getattr(item, "error_code", None)
    return isinstance(error_code, int) and error_code >= 400


def _lookup_with_circuit(
    breaker: CircuitBreakerRegistry | None,
    key: str,
    source: str,
    fn,
    failure_fn,
) -> Any:
    if breaker is not None:
        breaker.raise_if_open(key)
    try:
        item = fn()
    except Exception as exc:
        if breaker is not None:
            breaker.record_failure(key, reason=str(exc))
            log_event(
                logger,
                logging.INFO,
                "circuit_failure",
                source=source,
                key=key,
                error=str(exc),
            )
        raise
    if breaker is not None:
        if failure_fn(item):
            reason = (
                getattr(item, "error", None)
                or getattr(item, "error_text", None)
                or "unsuccessful source response"
            )
            breaker.record_failure(key, reason=str(reason))
            log_event(
                logger,
                logging.INFO,
                "circuit_failure",
                source=source,
                key=key,
                error=str(reason),
            )
        else:
            breaker.record_success(key)
    return item


def _all_sources_public(
    requested: list[str], *, rdap_base_url: str | None, whois_server: str | None
) -> bool:
    """True when every requested source would reach a public registry.

    RDAP bootstraps from IANA unless a base URL is given, and classic WHOIS
    selects a registry adapter unless a host is named, so those two are public by
    default. RWhois has no bootstrap -- the caller always supplies the host -- so
    it is somebody's own server by definition, and RFC 6761 says nothing about
    what it may hold.
    """
    if not requested:
        return False
    for source in requested:
        if source == "rdap" and not rdap_base_url:
            continue
        if source == "whois" and not whois_server:
            continue
        return False
    return True


def lookup(
    resource: str,
    *,
    sources: list[str] | None = None,
    timeout: float = 10.0,
    server: str | None = None,
    port: int | None = None,
    rwhois_class: str | None = None,
    whois_port: int | None = None,
    whois_server: str | None = None,
    rdap_base_url: str | None = None,
    cache_dir: str | None = None,
    limiter: RateLimiterRegistry | None = None,
    breaker: CircuitBreakerRegistry | None = None,
    retries: int = 0,
    backoff: Backoff | None = None,
    cache: Cache | None = None,
    cache_ttl: float = 3600.0,
    force_refresh: bool = False,
    follow_referrals: bool = False,
    max_bytes: int | None = None,
    conditional_rdap: bool = True,
    rdap_revalidation_ttl: float = 7 * 24 * 60 * 60,
    rdap_field_set: str | None = None,
    skip_reserved: bool = True,
) -> LookupResult:
    requested = sources or ["rdap", "whois"]
    result = LookupResult(
        resource=resource,
        kind=whois.classify_resource(resource),
        sources=requested,
        breaker=breaker,
    )

    if (
        skip_reserved
        and result.kind == "domain"
        and _all_sources_public(
            requested, rdap_base_url=rdap_base_url, whois_server=whois_server
        )
    ):
        reason = special_use_reason(resource)
        if reason is not None:
            # Reserved names are not refused by registries -- Verisign answers
            # example.com with a full, plausible object (see the live fixtures).
            # Asking anyway spends quota and hands back a documentation fixture
            # that reads exactly like a finding, which is the failure mode worth
            # preventing in a sweep. Only a lookup that would reach a public
            # registry is refused: when the caller names an endpoint -- a private
            # RWhois tree, a chosen RDAP base, an explicit whois host -- the
            # reservation does not bind it, and that server may hold such objects.
            result.unqueryable = reason
            log_event(
                logger,
                logging.INFO,
                "lookup_unqueryable",
                resource=resource,
                reason=reason,
                sources=requested,
            )
            return result

    if "rdap" in requested:
        if not is_enabled(ExperimentalFeature.RDAP):
            result.errors.append(
                LookupErrorItem("rdap", "disabled", kind=ERROR_DISABLED)
            )
        else:
            rdap_key = f"rdap:{rdap_base_url.lower() if rdap_base_url else 'bootstrap'}"
            try:
                item = _lookup_with_circuit(
                    breaker,
                    rdap_key,
                    "rdap",
                    lambda: rdap.lookup_rdap(
                        resource,
                        base_url=rdap_base_url,
                        cache_dir=cache_dir,
                        timeout=timeout,
                        limiter=limiter,
                        retries=retries,
                        backoff=backoff,
                        cache=cache,
                        cache_ttl=cache_ttl,
                        force_refresh=force_refresh,
                        max_bytes=rdap.DEFAULT_MAX_RESPONSE_BYTES
                        if max_bytes is None
                        else max_bytes,
                        conditional_revalidate=conditional_rdap,
                        revalidation_ttl=rdap_revalidation_ttl,
                        field_set=rdap_field_set,
                    ),
                    _is_rdap_endpoint_failure,
                )
            except CircuitOpen as exc:
                result.errors.append(
                    LookupErrorItem("rdap", str(exc), kind=ERROR_CIRCUIT_OPEN)
                )
            except Exception as exc:
                result.errors.append(LookupErrorItem("rdap", str(exc)))
            else:
                if item.error:
                    result.errors.append(LookupErrorItem("rdap", item.error))
                else:
                    result.results["rdap"] = item

    if "whois" in requested:
        if not is_enabled(ExperimentalFeature.WHOIS):
            result.errors.append(
                LookupErrorItem("whois", "disabled", kind=ERROR_DISABLED)
            )
        else:
            whois_key = f"whois:{(whois_server or resource).lower()}:{whois_port or whois.WHOIS_PORT}"
            try:
                item = _lookup_with_circuit(
                    breaker,
                    whois_key,
                    "whois",
                    lambda: whois.lookup_whois(
                        resource,
                        server=whois_server,
                        port=whois_port or whois.WHOIS_PORT,
                        timeout=timeout,
                        limiter=limiter,
                        retries=retries,
                        backoff=backoff,
                        cache=cache,
                        cache_ttl=cache_ttl,
                        force_refresh=force_refresh,
                        follow_referrals=follow_referrals,
                        max_bytes=whois.DEFAULT_MAX_RESPONSE_BYTES
                        if max_bytes is None
                        else max_bytes,
                    ),
                    _is_whois_endpoint_failure,
                )
            except CircuitOpen as exc:
                result.errors.append(
                    LookupErrorItem("whois", str(exc), kind=ERROR_CIRCUIT_OPEN)
                )
            except Exception as exc:
                result.errors.append(LookupErrorItem("whois", str(exc)))
            else:
                if item.error:
                    result.errors.append(LookupErrorItem("whois", item.error))
                else:
                    # A failed source contributes an error, not a result -- as the rdap branch
                    # above already does. Storing it as well made `ok`, which is `bool(results)`,
                    # report success for a lookup in which every source failed.
                    result.results["whois"] = item

    if "rwhois" in requested:
        if not server or port is None:
            result.errors.append(
                LookupErrorItem(
                    "rwhois", "server and port are required", kind=ERROR_CONFIG
                )
            )
        else:
            rwhois_key = f"rwhois:{server.lower()}:{int(port)}"

            def _query_rwhois():
                with RwhoisClient.connect(server, int(port), timeout=timeout) as client:
                    return client.query(rwhois_class, resource, raise_errors=False)

            try:
                item = _lookup_with_circuit(
                    breaker,
                    rwhois_key,
                    "rwhois",
                    _query_rwhois,
                    _is_rwhois_endpoint_failure,
                )
            except CircuitOpen as exc:
                result.errors.append(
                    LookupErrorItem("rwhois", str(exc), kind=ERROR_CIRCUIT_OPEN)
                )
            except Exception as exc:
                result.errors.append(LookupErrorItem("rwhois", str(exc)))
            else:
                if item.error_code is not None and int(item.error_code) >= 300:
                    result.errors.append(
                        LookupErrorItem(
                            "rwhois",
                            f"{item.error_code} {item.error_text or ''}".strip(),
                        )
                    )
                else:
                    # Below 300 the code is informational, and 230 "No objects found" is the
                    # authoritative answer to a well-formed query about something that is not
                    # there. Counting that as an error reported a failed lookup for a successful
                    # empty one -- the same confusion batch's status vocabulary exists to prevent.
                    result.results["rwhois"] = item

    if "rdap" in result.results and result.results["rdap"].data:
        rdap_record = rdap.normalize_rdap(result.results["rdap"].data)
        result.records.append(rdap_record)
        result.normalized = rdap_record.as_dict()

    if "whois" in result.results:
        whois_item = result.results["whois"]
        if getattr(whois_item, "fields", None):
            whois_record = whois_item.normalized()
            result.records.append(whois_record)
            if not result.normalized:
                result.normalized = whois_record.as_dict()

    if "rwhois" in result.results:
        for obj in getattr(result.results["rwhois"], "objects", []):
            rwhois_record = from_rwhois_object(obj)
            result.records.append(rwhois_record)
            if not result.normalized:
                result.normalized = rwhois_record.as_dict()

    return result


__all__ = ["LookupResult", "lookup"]
