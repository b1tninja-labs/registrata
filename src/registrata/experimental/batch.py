"""Experimental bulk lookup runner.

Large lookups -- a zone file, an ASN list, a customer domain list -- need three
things a single-shot ``lookup()`` does not provide: bounded concurrency, a request
rate that remote registries can live with, and a way to stop safely halfway
through. This module supplies all three on top of the unified lookup surface, so
every safety layer underneath (per-endpoint token buckets, retries, caches,
circuit breakers, response-size limits) keeps working unchanged.

The transports in this project are blocking stdlib sockets, so concurrency here is
thread-based: many resources are in flight at once waiting on the network, without
an event loop. :func:`batch_lookup_async` wraps the same runner for asyncio
callers, which is a thread offload rather than event-loop-native I/O.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any

from ..circuitbreaker import CircuitBreakerRegistry
from ..model import RegistrationRecord
from ..observability import log_event
from ..ratelimit import RateLimiterRegistry, RateLimitTimeout, TokenBucket
from ..retry import Backoff
from .lookup import LookupResult, lookup

logger = logging.getLogger(__name__)

#: Worker threads used when the caller does not choose.
DEFAULT_CONCURRENCY = 4
#: Deliberate ceiling: registries start refusing service long before this helps.
MAX_CONCURRENCY = 32
#: ``LookupErrorItem.kind`` value set when an endpoint is being left alone.
CIRCUIT_OPEN = "circuit_open"
#: How often the dispatch loop re-checks cancellation and the deadline.
_POLL_SECONDS = 0.25

LookupFn = Callable[..., LookupResult]
ResultHook = Callable[["BatchItem"], None]


@dataclass
class BatchItem:
    """The outcome for one resource in a batch."""

    resource: str
    index: int = 0
    kind: str | None = None
    ok: bool = False
    result: LookupResult | None = None
    error: str | None = None
    skipped: bool = False
    skip_reason: str | None = None
    duration_ms: float = 0.0
    #: The endpoint refused service (open circuit), which is not the same as the
    #: resource not existing.
    blocked: bool = False

    @property
    def status(self) -> str:
        if getattr(self.result, "unqueryable", None):
            # The name cannot exist in any registry. Calling that "error" would
            # inflate the failure count of a sweep; calling it "empty" would
            # imply somebody asked and found nothing.
            return "reserved"
        if self.skipped:
            return "skipped"
        if self.error:
            return "error"
        if self.blocked:
            return "blocked"
        errors = getattr(self.result, "errors", None) or []
        if not self.ok:
            # Nothing answered at all. That is only "empty" when a source actually replied: when
            # every source failed the lookup failed, and labelling a failure "empty" is exactly
            # the confusion this vocabulary was introduced to avoid.
            return "error" if errors else "empty"
        # An authoritative no-data answer -- RWhois "%error 230 No objects found" is one -- did
        # answer, so it is not a fault. But nothing was found, and calling that "ok" hides a miss
        # among the hits of a sweep. Sources with no records attribute at all are left alone.
        records = getattr(self.result, "records", None)
        if records is not None and not records:
            return "empty"
        # "ok" plus a source error means at least one source answered and at
        # least one complained -- typically one registry down while another
        # returned data. Reporting that as a clean success would hide it.
        return "partial" if errors else "ok"

    def as_dict(self, *, records: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "resource": self.resource,
            "kind": self.kind,
            "status": self.status,
            "ok": self.ok,
            "duration_ms": round(self.duration_ms, 3),
        }
        if self.error:
            data["error"] = self.error
        reason = getattr(self.result, "unqueryable", None) if self.result else None
        if reason:
            data["unqueryable"] = reason
        if self.skip_reason:
            data["skipped"] = self.skip_reason
        if self.result is not None:
            data["sources"] = list(self.result.sources)
            data["errors"] = [
                {"source": item.source, "message": item.message, "kind": item.kind}
                for item in self.result.errors
            ]
            if records:
                data["records"] = [record.as_dict() for record in self.result.records]
        return data


@dataclass
class BatchResult:
    """Everything a batch run produced, in the order the resources were given."""

    items: list[BatchItem] = field(default_factory=list)
    concurrency: int = DEFAULT_CONCURRENCY
    duration_ms: float = 0.0
    stopped_reason: str | None = None
    breaker: CircuitBreakerRegistry | None = None

    @property
    def ok(self) -> bool:
        return bool(self.items) and all(item.ok for item in self.items)

    def counts(self) -> dict[str, int]:
        counts = {
            "total": len(self.items),
            "ok": 0,
            "partial": 0,
            "empty": 0,
            "reserved": 0,
            "blocked": 0,
            "error": 0,
            "skipped": 0,
        }
        for item in self.items:
            counts[item.status] += 1
        return counts

    def summary(self) -> dict[str, Any]:
        """Aggregate view: how the run went, not what each registry answered."""
        source_errors: dict[str, int] = {}
        circuit_open = 0
        for item in self.items:
            if item.result is None:
                continue
            for error in item.result.errors:
                source_errors[error.source] = source_errors.get(error.source, 0) + 1
                if error.kind == CIRCUIT_OPEN:
                    circuit_open += 1
        summary: dict[str, Any] = {
            "counts": self.counts(),
            "source_errors": dict(sorted(source_errors.items())),
            "circuit_open_errors": circuit_open,
            "duration_ms": round(self.duration_ms, 3),
            "concurrency": self.concurrency,
        }
        if self.stopped_reason:
            summary["stopped_reason"] = self.stopped_reason
        if self.breaker is not None:
            summary["circuit_breakers"] = self.breaker.snapshot()
        return summary

    def as_dict(self, *, records: bool = False) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "items": [item.as_dict(records=records) for item in self.items],
        }

    def records(self) -> list[RegistrationRecord]:
        """Normalized records of every resource, concatenated in input order."""
        collected: list[RegistrationRecord] = []
        for item in self.items:
            if item.result is not None:
                collected.extend(item.result.records)
        return collected

    def jsonl(self, *, records: bool = False) -> list[str]:
        """One JSON object per resource, for streaming large runs to a file."""
        return [
            json.dumps(item.as_dict(records=records), sort_keys=True)
            for item in self.items
        ]


def _resolve_concurrency(concurrency: int | None) -> int:
    if concurrency is None:
        return DEFAULT_CONCURRENCY
    try:
        requested = int(concurrency)
    except (TypeError, ValueError):
        return DEFAULT_CONCURRENCY
    return max(1, min(MAX_CONCURRENCY, requested))


def _normalize_resources(resources: Iterable[str]) -> list[str]:
    """Trim entries and drop blanks and ``#`` comments, so a file can be annotated.

    Duplicates are kept: asking for the same resource twice is a legitimate way to
    observe cache behaviour, and silently dropping it would hide that.
    """
    cleaned: list[str] = []
    for entry in resources or []:
        if entry is None:
            continue
        text = str(entry).strip()
        if not text or text.startswith("#"):
            continue
        cleaned.append(text)
    return cleaned


class _Brake:
    """Thread-safe stop signal shared by the workers and the dispatch loop."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._reason: str | None = None

    def trip(self, reason: str) -> None:
        with self._lock:
            if self._reason is None:
                self._reason = reason

    @property
    def reason(self) -> str | None:
        with self._lock:
            return self._reason


def batch_lookup(
    resources: Iterable[str],
    *,
    concurrency: int | None = DEFAULT_CONCURRENCY,
    sources: list[str] | None = None,
    lookup_fn: LookupFn | None = None,
    on_result: ResultHook | None = None,
    # Politeness
    aggregate_rate_per_second: float | None = None,
    aggregate_burst: int = 1,
    # Stopping
    fail_fast: bool = False,
    stop_on_open_circuit: bool = False,
    deadline_seconds: float | None = None,
    cancel_event: threading.Event | None = None,
    # Forwarded to lookup()
    timeout: float = 10.0,
    server: str | None = None,
    port: int | None = None,
    rwhois_class: str | None = None,
    whois_port: int | None = None,
    whois_server: str | None = None,
    rdap_base_url: str | None = None,
    rdap_field_set: str | None = None,
    cache_dir: str | None = None,
    limiter: RateLimiterRegistry | None = None,
    breaker: CircuitBreakerRegistry | None = None,
    retries: int = 0,
    backoff: Backoff | None = None,
    cache: Any | None = None,
    cache_ttl: float = 3600.0,
    force_refresh: bool = False,
    follow_referrals: bool = False,
    max_bytes: int | None = None,
    conditional_rdap: bool = True,
    rdap_revalidation_ttl: float = 7 * 24 * 60 * 60,
    skip_reserved: bool = True,
) -> BatchResult:
    """Look up many resources with bounded concurrency and shared safety state.

    The same ``limiter``, ``breaker``, and ``cache`` are used by every worker, which
    is the point: one token bucket per endpoint and one circuit per authority hold
    across the whole batch instead of per call. Results come back in input order so
    a run is reproducible and diffable.

    Concurrency is capped at :data:`MAX_CONCURRENCY` on purpose. Raising it makes
    individual registries refuse service long before it makes a bulk job finish
    proportionally faster.

    ``aggregate_rate_per_second`` adds a *global* token bucket on top of the
    per-endpoint limiter. Registries rate-limit the querying address as a whole, so
    a batch spread across many endpoints can still flood them while each individual
    bucket looks polite.

    Stopping is safe rather than abrupt: ``fail_fast`` and ``stop_on_open_circuit``
    stop *dispatching* new work, ``deadline_seconds`` bounds the whole run, and
    ``cancel_event`` lets a caller (for example a Ctrl-C handler) stop between
    items. Work already in flight is allowed to finish, and whatever completed is
    still returned with ``stopped_reason`` set.

    ``on_result`` is called from the calling thread as each resource settles, in
    completion order rather than input order, which is what makes streaming a long
    run to disk possible.
    """
    started = time.perf_counter()
    entries = _normalize_resources(resources)
    workers = _resolve_concurrency(concurrency)
    items = [
        BatchItem(resource=resource, index=index)
        for index, resource in enumerate(entries)
    ]
    run = BatchResult(items=items, concurrency=workers, breaker=breaker)
    if not entries:
        log_event(logger, logging.INFO, "batch_empty", resources=0)
        run.duration_ms = (time.perf_counter() - started) * 1000.0
        return run

    brake = _Brake()
    global_bucket = (
        TokenBucket(
            rate_per_second=float(aggregate_rate_per_second),
            capacity=float(max(1, int(aggregate_burst))),
        )
        if aggregate_rate_per_second and float(aggregate_rate_per_second) > 0
        else None
    )
    run_fn = lookup_fn or lookup
    # ``is not None`` and not truthiness: a deadline of 0 means "stop before the
    # first lookup", which is a thing an operator legitimately asks for.
    deadline = (
        time.monotonic() + float(deadline_seconds)
        if deadline_seconds is not None
        else None
    )
    lookup_options: dict[str, Any] = {
        "sources": sources,
        "skip_reserved": skip_reserved,
        "timeout": timeout,
        "server": server,
        "port": port,
        "rwhois_class": rwhois_class,
        "whois_port": whois_port,
        "whois_server": whois_server,
        "rdap_base_url": rdap_base_url,
        "cache_dir": cache_dir,
        "limiter": limiter,
        "breaker": breaker,
        "retries": retries,
        "backoff": backoff,
        "cache": cache,
        "cache_ttl": cache_ttl,
        "force_refresh": force_refresh,
        "follow_referrals": follow_referrals,
        "max_bytes": max_bytes,
        "conditional_rdap": conditional_rdap,
        "rdap_revalidation_ttl": rdap_revalidation_ttl,
    }
    if rdap_field_set:
        # Only forwarded when asked for, so an injected ``lookup_fn`` that predates
        # the RFC 8982 parameter keeps working.
        lookup_options["rdap_field_set"] = rdap_field_set

    log_event(
        logger,
        logging.INFO,
        "batch_start",
        resources=len(entries),
        concurrency=workers,
        sources=sources or ["rdap", "whois"],
        aggregate_rate_per_second=aggregate_rate_per_second,
        deadline_seconds=deadline_seconds,
    )

    def _stop_reason() -> str | None:
        """Why a resource must not start, or None when it may.

        Cancelling and running past the deadline stop dispatch the same way a
        tripped brake does, so they share one reason and the caller can read it
        back from ``BatchResult.stopped_reason``.
        """
        if brake.reason is not None:
            return brake.reason
        if cancel_event is not None and cancel_event.is_set():
            brake.trip("cancelled")
            return brake.reason
        if deadline is not None and time.monotonic() >= deadline:
            brake.trip("deadline exceeded")
            return brake.reason
        return None

    def _skip(item: BatchItem, reason: str) -> BatchItem:
        item.skipped = True
        item.skip_reason = reason
        return item

    def _one(item: BatchItem) -> BatchItem:
        reason = _stop_reason()
        if reason is not None:
            return _skip(item, reason)
        if global_bucket is not None:
            # Taken before the per-endpoint bucket so the global ceiling is the one
            # that binds when both would otherwise allow the request.
            try:
                global_bucket.acquire(timeout=timeout if timeout else None)
            except RateLimitTimeout as exc:
                return _skip(item, f"global rate limit: {exc}")
        item_started = time.perf_counter()
        try:
            result = run_fn(item.resource, **lookup_options)
        except Exception as exc:  # noqa: BLE001 - one bad resource must not kill the run
            item.duration_ms = (time.perf_counter() - item_started) * 1000.0
            item.error = f"{type(exc).__name__}: {exc}"
            log_event(
                logger,
                logging.WARNING,
                "batch_item_error",
                resource=item.resource,
                error=item.error,
            )
            if fail_fast:
                brake.trip("fail_fast")
            return item
        item.result = result
        item.kind = result.kind
        item.ok = bool(result.ok)
        item.duration_ms = (time.perf_counter() - item_started) * 1000.0
        open_circuits = [error for error in result.errors if error.kind == CIRCUIT_OPEN]
        item.blocked = bool(open_circuits) and not item.ok
        if open_circuits and stop_on_open_circuit:
            # A registry that is refusing service will not change its mind over the
            # next thousand resources.
            brake.trip("circuit open")
        if fail_fast and not result.ok and not result.unqueryable:
            # A reserved name is not a pipeline failure: stopping a sweep of a
            # thousand resources because one of them cannot exist would throw
            # away the answers that were still coming.
            brake.trip("fail_fast")
        log_event(
            logger,
            logging.DEBUG,
            "batch_item",
            resource=item.resource,
            status=item.status,
            sources=list(result.sources),
            duration_ms=round(item.duration_ms, 3),
        )
        return item

    def _finish(item: BatchItem) -> None:
        if on_result is None:
            return
        try:
            on_result(item)
        except Exception as exc:  # noqa: BLE001 - a broken hook must not lose results
            log_event(logger, logging.WARNING, "batch_hook_error", error=str(exc))

    pending: dict[Future, BatchItem] = {}
    queued = list(items)
    interrupted = False
    try:
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="registrata-batch"
        ) as pool:
            while queued or pending:
                # Fill the window one at a time, re-checking the stop conditions
                # each round so a stop takes effect without draining the queue.
                while queued and len(pending) < workers:
                    item = queued.pop(0)
                    reason = _stop_reason()
                    if reason is not None:
                        _finish(_skip(item, reason))
                        continue
                    pending[pool.submit(_one, item)] = item
                if not pending:
                    break
                done, _ = wait(
                    list(pending), timeout=_POLL_SECONDS, return_when="FIRST_COMPLETED"
                )
                for future in done:
                    settled = pending.pop(future)
                    try:
                        _finish(future.result())
                    except Exception as exc:  # noqa: BLE001 - _one() catches, so this is the pool
                        settled.error = f"{type(exc).__name__}: {exc}"
                        _finish(settled)
    except KeyboardInterrupt:
        # Ctrl-C stops the run but keeps what was already learned.
        interrupted = True
        brake.trip("cancelled")
        if cancel_event is not None:
            cancel_event.set()
        for future in pending:
            future.cancel()
        log_event(
            logger,
            logging.INFO,
            "batch_interrupted",
            completed=len(items) - len(queued) - len(pending),
        )

    # Everything abandoned mid-run still has to be accounted for: an item that is
    # simply missing from the report is worse than an item marked as skipped.
    leftovers = list(queued)
    if interrupted:
        # Leaving the pool waits for tasks that had already started. Those did real
        # work, so report them; the ones that never started are skips.
        for future, item in pending.items():
            if future.cancelled():
                leftovers.append(item)
            else:
                _finish(item)
    for item in leftovers:
        if not item.skipped:
            _skip(item, brake.reason or "cancelled")
        _finish(item)

    run.stopped_reason = brake.reason
    if run.stopped_reason is None:
        # A stop that arrives while every resource is already in flight skips
        # nothing, because dispatch has nothing left to refuse. The run still has to
        # say that it was cut short, or the operator reads a clean report out of a
        # cancelled job.
        if cancel_event is not None and cancel_event.is_set():
            run.stopped_reason = "cancelled"
        elif deadline is not None and time.monotonic() >= deadline:
            run.stopped_reason = "deadline exceeded"
    run.duration_ms = (time.perf_counter() - started) * 1000.0
    counts = run.counts()
    log_event(
        logger,
        logging.INFO,
        "batch_complete",
        resources=counts["total"],
        ok=counts["ok"],
        errors=counts["error"],
        reserved=counts["reserved"],
        blocked=counts["blocked"],
        skipped=counts["skipped"],
        stopped_reason=run.stopped_reason,
        duration_ms=round(run.duration_ms, 3),
    )
    return run


async def batch_lookup_async(resources: Iterable[str], **kwargs: Any) -> BatchResult:
    """Run :func:`batch_lookup` without blocking the event loop.

    The worker pool still does the I/O: this lets asyncio callers await a batch
    instead of stalling their loop, and is a thread offload rather than
    event-loop-native RDAP/WHOIS transport.
    """
    return await asyncio.to_thread(batch_lookup, resources, **kwargs)


__all__ = [
    "CIRCUIT_OPEN",
    "DEFAULT_CONCURRENCY",
    "MAX_CONCURRENCY",
    "BatchItem",
    "BatchResult",
    "batch_lookup",
    "batch_lookup_async",
]
