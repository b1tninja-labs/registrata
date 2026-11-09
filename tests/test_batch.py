"""Bulk lookup runner: ordering, error isolation, politeness, and safe stopping.

Everything here injects ``lookup_fn`` so no test opens a socket, and the only
timing assertions are loose *lower* bounds with a wide margin (a slow CI can make
a run slower, never faster than the pacing math allows). Where the outcome must be
deterministic the test serialises the run with ``concurrency=1`` or drives it with
a ``threading.Event`` instead of sleeping.
"""

import asyncio
import json
import threading
import time

import pytest

from registrata.circuitbreaker import CircuitBreakerRegistry
from registrata.experimental.batch import (
    CIRCUIT_OPEN,
    DEFAULT_CONCURRENCY,
    MAX_CONCURRENCY,
    BatchItem,
    BatchResult,
    batch_lookup,
    batch_lookup_async,
)
from registrata.experimental.lookup import (
    ERROR_CIRCUIT_OPEN,
    ERROR_CONFIG,
    ERROR_DISABLED,
    LookupErrorItem,
    LookupResult,
    lookup as unified_lookup,
)
from registrata.model import RegistrationRecord

ALL_COUNT_KEYS = {
    "total",
    "ok",
    "partial",
    "empty",
    "reserved",
    "blocked",
    "error",
    "skipped",
}


def _answer(resource, *, ok=True, errors=(), records=None):
    """A minimal ``LookupResult``; ``ok`` is driven by ``results`` being non-empty.

    ``records`` defaults to one record, because "answered" in these tests means "answered with
    data". A lookup that replies "not there" is a different status from one that found something,
    and a double that claimed to answer while carrying nothing would let the two collapse back
    together; pass ``records=[]`` when the empty answer is what is being modelled.
    """
    return LookupResult(
        resource=resource,
        kind="domain",
        sources=["rwhois"] if ok else [],
        results={"rwhois": object()} if ok else {},
        records=list([_record(resource)] if records is None else records),
        errors=list(errors),
    )


def _ok(resource, **kwargs):
    return _answer(resource)


def _open_circuit(resource, **kwargs):
    """What an endpoint answers while its circuit is open: nothing, plus a kind."""
    return _answer(
        resource,
        ok=False,
        errors=[LookupErrorItem("rdap", "circuit open", kind=CIRCUIT_OPEN)],
    )


def _open_circuit_errors():
    return [
        LookupErrorItem("rdap", "circuit open for 'rdap:bootstrap'", kind=CIRCUIT_OPEN)
    ]


def _record(identifier):
    return RegistrationRecord(source="rwhois", kind="domain", identifier=identifier)


def _statuses(result):
    return [item.status for item in result.items]


def test_batch_returns_items_in_input_order_while_on_result_sees_completion_order():
    release = threading.Event()
    completed = []
    guard = threading.Lock()

    def fake(resource, **kwargs):
        if resource == "slow":
            # Released by the hook once the two fast resources have both settled, so
            # the completion order is driven by the runner rather than by a sleep.
            release.wait(timeout=10)
        return _answer(resource)

    def on_result(item):
        with guard:
            completed.append(item.resource)
            if len(completed) >= 2 and "slow" not in completed:
                release.set()

    result = batch_lookup(
        ["slow", "fast-1", "fast-2"], concurrency=3, lookup_fn=fake, on_result=on_result
    )

    assert [item.resource for item in result.items] == ["slow", "fast-1", "fast-2"]
    assert [item.index for item in result.items] == [0, 1, 2]
    assert set(completed[:2]) == {"fast-1", "fast-2"}
    assert completed[-1] == "slow"
    assert _statuses(result) == ["ok", "ok", "ok"]


def test_batch_isolates_an_exception_raised_for_one_resource():
    def fake(resource, **kwargs):
        if resource == "boom":
            raise RuntimeError("socket exploded")
        return _answer(resource)

    result = batch_lookup(["a", "boom", "c"], concurrency=2, lookup_fn=fake)

    by_resource = {item.resource: item for item in result.items}
    assert by_resource["boom"].status == "error"
    assert by_resource["boom"].error.startswith("RuntimeError:")
    assert "socket exploded" in by_resource["boom"].error
    assert by_resource["boom"].result is None
    assert by_resource["a"].status == "ok"
    assert by_resource["c"].status == "ok"
    assert result.counts() == {
        "total": 3,
        "ok": 2,
        "partial": 0,
        "empty": 0,
        "reserved": 0,
        "blocked": 0,
        "error": 1,
        "skipped": 0,
    }
    assert result.ok is False


def test_batch_runs_resources_at_the_same_time():
    barrier = threading.Barrier(3)
    met = []
    guard = threading.Lock()

    def fake(resource, **kwargs):
        # A barrier only completes if three lookups are genuinely in flight; if the
        # runner serialised, this raises BrokenBarrierError and the item ends up in
        # status "error", which the assertions below catch.
        barrier.wait(timeout=5)
        with guard:
            met.append(resource)
        return _answer(resource)

    result = batch_lookup(["a", "b", "c"], concurrency=3, lookup_fn=fake)

    assert sorted(met) == ["a", "b", "c"]
    assert result.counts()["ok"] == 3


def test_concurrency_is_clamped_into_a_polite_range():
    seen = []

    def fake(resource, **kwargs):
        seen.append(resource)
        return _answer(resource)

    assert DEFAULT_CONCURRENCY == 4
    assert MAX_CONCURRENCY == 32
    assert (
        batch_lookup(["a"], concurrency=None, lookup_fn=fake).concurrency
        == DEFAULT_CONCURRENCY
    )
    assert batch_lookup(["a"], concurrency=0, lookup_fn=fake).concurrency == 1
    assert batch_lookup(["a"], concurrency=-7, lookup_fn=fake).concurrency == 1
    assert (
        batch_lookup(["a"], concurrency=9999, lookup_fn=fake).concurrency
        == MAX_CONCURRENCY
    )
    assert batch_lookup(["a"], lookup_fn=fake).concurrency == DEFAULT_CONCURRENCY
    assert seen == ["a"] * 5


def test_fail_fast_stops_dispatch_after_a_raising_resource():
    def fake(resource, **kwargs):
        if resource == "a":
            raise RuntimeError("nope")
        return _answer(resource)

    # concurrency=1 keeps the stop deterministic: nothing is in flight when the
    # brake trips, so everything after the failure is reported as skipped.
    result = batch_lookup(
        ["a", "b", "c"], concurrency=1, fail_fast=True, lookup_fn=fake
    )

    assert _statuses(result) == ["error", "skipped", "skipped"]
    assert result.items[1].skip_reason == "fail_fast"
    assert result.stopped_reason == "fail_fast"
    assert result.counts()["skipped"] == 2
    assert "stopped_reason" in result.summary()


def test_fail_fast_also_trips_on_an_unsuccessful_answer():
    def fake(resource, **kwargs):
        return _answer(resource, ok=resource != "a")

    result = batch_lookup(["a", "b"], concurrency=1, fail_fast=True, lookup_fn=fake)

    assert _statuses(result) == ["empty", "skipped"]
    assert result.items[1].skip_reason == "fail_fast"
    assert result.stopped_reason == "fail_fast"


def test_stop_on_open_circuit_blocks_that_resource_and_halts_the_run():
    seen = []

    def fake(resource, **kwargs):
        seen.append(resource)
        if resource == "b":
            return _answer(resource, ok=False, errors=_open_circuit_errors())
        return _answer(resource)

    result = batch_lookup(
        ["a", "b", "c", "d"], concurrency=1, stop_on_open_circuit=True, lookup_fn=fake
    )

    assert seen == ["a", "b"]
    assert _statuses(result) == ["ok", "blocked", "skipped", "skipped"]
    assert result.items[1].blocked is True
    assert result.summary()["circuit_open_errors"] == 1
    assert result.stopped_reason == "circuit open"
    assert result.items[2].skip_reason == "circuit open"


def test_open_circuit_without_the_stop_flag_only_affects_that_resource():
    def fake(resource, **kwargs):
        if resource == "b":
            return _open_circuit(resource)
        return _answer(resource)

    result = batch_lookup(["a", "b", "c"], concurrency=1, lookup_fn=fake)

    assert _statuses(result) == ["ok", "blocked", "ok"]
    assert result.stopped_reason is None
    assert "stopped_reason" not in result.summary()
    assert result.summary()["circuit_open_errors"] == 1
    assert result.counts()["blocked"] == 1
    assert result.ok is False


def test_an_open_circuit_beside_real_data_is_partial_not_blocked():
    # "blocked" means the endpoint refused service and nothing came back. If another
    # source still answered, the resource is a partial answer rather than a refusal.
    result = batch_lookup(
        ["a"],
        lookup_fn=lambda resource, **kwargs: _answer(
            resource, errors=_open_circuit_errors()
        ),
    )

    assert result.items[0].blocked is False
    assert result.items[0].status == "partial"
    assert result.summary()["circuit_open_errors"] == 1
    assert result.stopped_reason is None


def test_batch_and_lookup_agree_on_the_circuit_open_kind():
    assert CIRCUIT_OPEN == ERROR_CIRCUIT_OPEN == "circuit_open"


def test_cancel_event_stops_dispatch_and_reports_the_remaining_resources():
    cancel = threading.Event()
    seen = []

    def on_result(item):
        seen.append(item.resource)
        if len(seen) == 2:
            cancel.set()

    result = batch_lookup(
        ["a", "b", "c", "d"],
        concurrency=1,
        lookup_fn=_ok,
        on_result=on_result,
        cancel_event=cancel,
    )

    assert result.stopped_reason == "cancelled"
    assert _statuses(result) == ["ok", "ok", "skipped", "skipped"]
    assert result.items[2].skip_reason == "cancelled"
    assert result.counts()["skipped"] == 2


def test_deadline_stops_the_run_and_keeps_what_already_answered():
    def fake(resource, **kwargs):
        if resource == "slow":
            # Comfortably longer than the deadline: work already in flight is allowed
            # to finish, which is what this pins. The margin is wide so a loaded CI
            # cannot make the first resource look like it blew the deadline.
            time.sleep(0.75)
        return _answer(resource)

    result = batch_lookup(
        ["a", "slow", "c", "d"], concurrency=1, deadline_seconds=0.25, lookup_fn=fake
    )

    assert [item.resource for item in result.items] == ["a", "slow", "c", "d"]
    assert result.stopped_reason == "deadline exceeded"
    assert result.items[0].status == "ok"
    ran = [item for item in result.items if not item.skipped]
    skipped = [item for item in result.items if item.skipped]
    assert ran[0].resource == "a"
    assert skipped, "the deadline must stop dispatching the tail of the run"
    assert all(item.skip_reason == "deadline exceeded" for item in skipped)
    assert result.items[-1].status == "skipped"
    assert result.duration_ms >= 0


def test_a_zero_deadline_stops_before_the_first_lookup():
    # ``deadline_seconds=0`` is a request to stop now, not a way to turn the deadline off:
    # the runner checks ``is not None``, so an already-expired deadline is honoured before
    # the first resource is dispatched and no registry is ever contacted. That is a
    # legitimate operator move (dry-run the accounting, dial nothing), and it is why the
    # count of lookups executed has to be zero rather than one.
    called = []
    seen = []

    def fake(resource, **kwargs):
        called.append(resource)
        return _answer(resource)

    result = batch_lookup(
        ["a", "b", "c"],
        concurrency=2,
        deadline_seconds=0,
        lookup_fn=fake,
        on_result=seen.append,
    )

    assert called == []
    assert [item.resource for item in result.items] == ["a", "b", "c"]
    assert _statuses(result) == ["skipped", "skipped", "skipped"]
    assert result.counts() == {
        "total": 3,
        "ok": 0,
        "partial": 0,
        "empty": 0,
        "reserved": 0,
        "blocked": 0,
        "error": 0,
        "skipped": 3,
    }
    assert all(item.skip_reason == "deadline exceeded" for item in result.items)
    assert all(item.result is None and item.duration_ms == 0.0 for item in result.items)
    assert result.stopped_reason == "deadline exceeded"
    assert result.summary()["stopped_reason"] == "deadline exceeded"
    # Skipped work is still reported, so a streaming consumer sees one line per resource.
    assert len(seen) == 3


def test_no_deadline_never_stops_a_run_however_long_the_lookups_take():
    # ``deadline_seconds=None`` (the default) means there is no deadline at all. The wait
    # is driven by an Event rather than a sleep so the run spends real, unbounded
    # wall-clock time in the pool: the first lookup only answers once two others have come
    # back and settled. Nothing here asserts how long that takes - only that the runner
    # never stops a run it was never given a deadline for.
    hold = threading.Event()
    settled = []

    def fake(resource, **kwargs):
        if resource == "slow":
            hold.wait(timeout=10)
        return _answer(resource)

    def on_result(item):
        settled.append(item.resource)
        if len(settled) == 2:
            hold.set()

    result = batch_lookup(
        ["slow", "fast-1", "fast-2"],
        concurrency=3,
        deadline_seconds=None,
        lookup_fn=fake,
        on_result=on_result,
    )

    assert hold.is_set()
    assert _statuses(result) == ["ok", "ok", "ok"]
    assert result.counts()["skipped"] == 0
    assert result.stopped_reason is None
    assert "stopped_reason" not in result.summary()
    assert set(settled[:2]) == {"fast-1", "fast-2"}

    # Omitting the argument and passing None are the same thing.
    defaulted = batch_lookup(["a", "b"], concurrency=1, lookup_fn=_ok)
    assert defaulted.stopped_reason is None
    assert defaulted.counts()["ok"] == 2


def test_aggregate_rate_paces_the_run_instead_of_dropping_resources():
    # The global token bucket waits for a token rather than skipping the resource, so
    # a polite run still answers every resource. ``timeout=0`` would mean "wait for a
    # token indefinitely"; here the default 10s timeout is never reached.
    result = batch_lookup(
        ["a", "b", "c", "d"],
        concurrency=4,
        aggregate_rate_per_second=40,
        aggregate_burst=1,
        lookup_fn=_ok,
    )

    assert _statuses(result) == ["ok", "ok", "ok", "ok"]
    assert all(not item.skipped for item in result.items)
    # Loose lower bound only: four resources at 40 req/s with a burst of one cannot
    # fit inside 30ms, and a slow CI can only ever make the run longer.
    assert result.duration_ms >= 30.0


def test_the_aggregate_bucket_paces_a_serial_run_too():
    # One worker still passes every resource through the same shared global bucket, so the
    # pacing is a property of the bucket rather than of the pool - which is what makes a
    # serial bulk run polite to a registry that counts requests per address.
    #
    # At 10 req/s with a burst of one, the first resource takes the token the bucket starts
    # with and the second waits for the next refill, roughly 0.1 s away. The bound below is
    # deliberately half of that arithmetic: a slow CI can only add to the elapsed time,
    # never take it away, and no upper bound is asserted anywhere. Nothing is skipped - the
    # bucket waits for a token instead of refusing the resource.
    result = batch_lookup(
        ["a", "b"],
        concurrency=1,
        aggregate_rate_per_second=10,
        aggregate_burst=1,
        lookup_fn=_ok,
    )

    assert _statuses(result) == ["ok", "ok"]
    assert result.counts()["skipped"] == 0
    assert result.stopped_reason is None
    assert result.duration_ms >= 50.0


def test_aggregate_rate_skips_only_when_the_caller_timeout_expires():
    # The bucket starts full, so the first resource goes straight through; at 0.5
    # req/s the next token is two seconds away and a 50ms per-request timeout cannot
    # wait for it, so those resources are reported as skipped rather than dropped.
    result = batch_lookup(
        ["a", "b", "c"],
        concurrency=1,
        aggregate_rate_per_second=0.5,
        aggregate_burst=1,
        timeout=0.05,
        lookup_fn=_ok,
    )

    assert result.items[0].status == "ok"
    assert result.counts()["skipped"] == 2
    assert result.items[1].skip_reason.startswith("global rate limit:")
    assert result.items[2].skip_reason.startswith("global rate limit:")


def test_in_flight_lookups_never_exceed_the_worker_count():
    guard = threading.Lock()
    state = {"in_flight": 0, "peak": 0}

    def fake(resource, **kwargs):
        with guard:
            state["in_flight"] += 1
            state["peak"] = max(state["peak"], state["in_flight"])
        try:
            time.sleep(0.005)
            return _answer(resource)
        finally:
            with guard:
                state["in_flight"] -= 1

    resources = [f"r{index:02d}" for index in range(20)]
    result = batch_lookup(resources, concurrency=3, lookup_fn=fake)

    assert result.counts()["ok"] == 20
    assert [item.resource for item in result.items] == resources
    assert state["peak"] <= 3


def test_a_broken_on_result_hook_loses_nothing():
    seen = []

    def hook(item):
        seen.append(item.resource)
        raise ValueError("hook is broken")

    result = batch_lookup(["a", "b", "c"], concurrency=2, lookup_fn=_ok, on_result=hook)

    assert sorted(seen) == ["a", "b", "c"]
    assert result.counts() == {
        "total": 3,
        "ok": 3,
        "partial": 0,
        "empty": 0,
        "reserved": 0,
        "blocked": 0,
        "error": 0,
        "skipped": 0,
    }
    assert result.ok is True


def test_on_result_also_sees_the_resources_that_were_never_dispatched():
    cancel = threading.Event()
    seen = []

    def hook(item):
        seen.append((item.resource, item.status))
        if len(seen) == 1:
            cancel.set()

    result = batch_lookup(
        ["a", "b", "c"],
        concurrency=1,
        lookup_fn=_ok,
        on_result=hook,
        cancel_event=cancel,
    )

    assert [resource for resource, _ in seen] == ["a", "b", "c"]
    assert [status for _, status in seen] == ["ok", "skipped", "skipped"]
    assert [item.resource for item in result.items] == ["a", "b", "c"]


def test_on_result_runs_on_the_calling_thread():
    caller = threading.get_ident()
    idents = []

    batch_lookup(
        ["a", "b", "c"],
        concurrency=3,
        lookup_fn=_ok,
        on_result=lambda item: idents.append(threading.get_ident()),
    )

    assert idents == [caller] * 3


def test_empty_input_is_a_clean_no_op_that_starts_no_workers():
    def exploding(resource, **kwargs):
        raise AssertionError("lookup_fn must not be called for an empty batch")

    before = threading.active_count()
    for resources in ([], ["", "   ", "# comment", "   # indented comment"], ()):
        result = batch_lookup(resources, lookup_fn=exploding)

        assert result.items == []
        assert set(result.counts()) == ALL_COUNT_KEYS
        assert result.counts()["total"] == 0
        assert result.summary()["counts"]["total"] == 0
        assert result.duration_ms >= 0
        assert result.stopped_reason is None
        assert result.jsonl() == []
        assert result.records() == []
        assert result.as_dict() == {"summary": result.summary(), "items": []}
    assert threading.active_count() <= before


def test_resources_are_trimmed_comments_and_blanks_dropped_but_duplicates_kept():
    result = batch_lookup(
        ["  a.example  ", "# note", "", "a.example", " b.example "], lookup_fn=_ok
    )

    assert [item.resource for item in result.items] == [
        "a.example",
        "a.example",
        "b.example",
    ]
    assert result.counts()["ok"] == 3
    assert result.counts()["total"] == 3


def test_item_reports_the_kind_and_duration_of_the_underlying_answer():
    result = batch_lookup(["a"], lookup_fn=_ok)

    item = result.items[0]
    assert item.kind == "domain"
    assert item.duration_ms >= 0
    assert item.result is not None
    assert item.error is None
    assert item.skip_reason is None


def test_records_jsonl_and_as_dict_expose_per_resource_detail():
    def fake(resource, **kwargs):
        return _answer(resource, records=[_record(resource), _record(resource.upper())])

    result = batch_lookup(["a.example", "b.example"], lookup_fn=fake)

    assert [record.identifier for record in result.records()] == [
        "a.example",
        "A.EXAMPLE",
        "b.example",
        "B.EXAMPLE",
    ]

    lines = result.jsonl()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert [entry["resource"] for entry in parsed] == ["a.example", "b.example"]
    assert [entry["status"] for entry in parsed] == ["ok", "ok"]
    assert "records" not in parsed[0]

    payload = result.as_dict(records=True)
    assert set(payload) == {"summary", "items"}
    assert payload["items"][0]["records"][0]["identifier"] == "a.example"
    assert "records" not in result.as_dict()["items"][0]


def test_item_dict_only_carries_the_members_that_apply():
    def fake(resource, **kwargs):
        if resource == "boom":
            raise RuntimeError("nope")
        if resource == "loud":
            return _answer(
                resource, errors=[LookupErrorItem("whois", "no such object", kind=None)]
            )
        return _answer(resource)

    result = batch_lookup(
        ["boom", "loud", "quiet"], concurrency=1, fail_fast=False, lookup_fn=fake
    )
    by_resource = {item.resource: item.as_dict() for item in result.items}

    assert set(by_resource["boom"]) == {
        "resource",
        "kind",
        "status",
        "ok",
        "duration_ms",
        "error",
    }
    assert by_resource["boom"]["error"].startswith("RuntimeError:")
    assert by_resource["loud"]["errors"] == [
        {"source": "whois", "message": "no such object", "kind": None}
    ]
    assert by_resource["loud"]["sources"] == ["rwhois"]
    assert by_resource["quiet"]["errors"] == []
    assert "skipped" not in by_resource["quiet"]

    stopped = batch_lookup(
        ["boom", "quiet"], concurrency=1, fail_fast=True, lookup_fn=fake
    )
    assert stopped.items[1].as_dict()["skipped"] == "fail_fast"


def test_summary_counts_source_errors_by_source_and_sorts_them():
    breaker = CircuitBreakerRegistry()

    def fake(resource, **kwargs):
        if resource == "a":
            return _answer(
                resource,
                ok=False,
                errors=[
                    LookupErrorItem("whois", "timeout"),
                    LookupErrorItem("rdap", "circuit open", kind=CIRCUIT_OPEN),
                ],
            )
        if resource == "b":
            return _answer(resource, errors=[LookupErrorItem("rdap", "not found")])
        return _answer(resource)

    result = batch_lookup(
        ["a", "b", "c"], concurrency=1, lookup_fn=fake, breaker=breaker
    )
    summary = result.summary()

    assert summary["source_errors"] == {"rdap": 2, "whois": 1}
    assert list(summary["source_errors"]) == sorted(summary["source_errors"])
    assert summary["circuit_open_errors"] == 1
    assert summary["concurrency"] == 1
    assert summary["duration_ms"] >= 0
    assert "stopped_reason" not in summary
    # The registry is shared across workers, so it is reported even when empty.
    assert summary["circuit_breakers"] == {}
    assert set(summary["counts"]) == ALL_COUNT_KEYS
    assert result.as_dict()["summary"] == summary


def test_summary_omits_the_breaker_member_when_the_runner_has_none():
    result = batch_lookup(["a"], lookup_fn=_ok)

    assert "circuit_breakers" not in result.summary()


def test_batch_item_status_precedence():
    assert (
        BatchItem(
            resource="a", skipped=True, skip_reason="cancelled", error="RuntimeError: x"
        ).status
        == "skipped"
    )
    assert (
        BatchItem(resource="a", error="RuntimeError: x", blocked=True).status == "error"
    )
    assert BatchItem(resource="a", ok=False, blocked=True).status == "blocked"
    assert BatchItem(resource="a", ok=False).status == "empty"
    assert BatchItem(resource="a").status == "empty"
    assert BatchItem(resource="a", ok=True).status == "ok"
    assert BatchItem(resource="a", ok=True, result=_answer("a")).status == "ok"
    assert (
        BatchItem(
            resource="a", ok=True, result=_answer("a", errors=_open_circuit_errors())
        ).status
        == "partial"
    )


def test_found_it_and_not_there_and_could_not_ask_are_three_different_statuses():
    """The distinction an operator actually needs, which "ok"/"not ok" cannot carry.

    A registry answering "%error 230 No objects found" and an endpoint nobody can reach both
    produce no data. Reporting them alike is how a sweep of dead servers reads as a clean run
    over a list of non-existent domains.
    """
    found = BatchItem(resource="a", ok=True, result=_answer("a"))
    absent = BatchItem(resource="a", ok=True, result=_answer("a", records=[]))
    unreachable = BatchItem(
        resource="a",
        ok=False,
        result=_answer(
            "a", ok=False, errors=[LookupErrorItem("rwhois", "connection refused")]
        ),
    )

    assert (found.status, absent.status, unreachable.status) == ("ok", "empty", "error")


def test_batch_result_ok_treats_a_partial_answer_as_answered():
    def fake(resource, **kwargs):
        if resource == "loud":
            return _answer(
                resource, errors=[LookupErrorItem("whois", "no such object")]
            )
        if resource == "silent":
            return _answer(resource, ok=False)
        return _answer(resource)

    with_partial = batch_lookup(["a", "loud"], concurrency=1, lookup_fn=fake)
    assert with_partial.items[1].status == "partial"
    assert with_partial.items[1].ok is True
    assert with_partial.ok is True

    with_empty = batch_lookup(["a", "silent"], concurrency=1, lookup_fn=fake)
    assert with_empty.items[1].status == "empty"
    assert with_empty.items[1].ok is False
    assert with_empty.ok is False

    assert batch_lookup([], lookup_fn=fake).ok is False


def test_lookup_options_are_forwarded_to_every_resource():
    seen = []

    def fake(resource, **kwargs):
        seen.append(kwargs)
        return _answer(resource)

    batch_lookup(
        ["a", "b"],
        concurrency=1,
        lookup_fn=fake,
        sources=["rwhois"],
        timeout=3.5,
        server="127.0.0.1",
        port=4321,
        rwhois_class="domain",
        whois_port=43,
        retries=2,
        cache_ttl=60.0,
        follow_referrals=True,
        max_bytes=4096,
    )

    assert len(seen) == 2
    for kwargs in seen:
        assert kwargs["sources"] == ["rwhois"]
        assert kwargs["timeout"] == 3.5
        assert kwargs["server"] == "127.0.0.1"
        assert kwargs["port"] == 4321
        assert kwargs["rwhois_class"] == "domain"
        assert kwargs["retries"] == 2
        assert kwargs["cache_ttl"] == 60.0
        assert kwargs["follow_referrals"] is True
        assert kwargs["max_bytes"] == 4096
        # Only forwarded when asked for, so an injected lookup_fn that predates the
        # RFC 8982 parameter keeps working.
        assert "rdap_field_set" not in kwargs

    requested = batch_lookup(["a"], lookup_fn=fake, rdap_field_set="brief")
    assert requested.items[0].status == "ok"
    assert seen[-1]["rdap_field_set"] == "brief"


def test_batch_lookup_async_returns_the_same_shape_as_the_sync_runner():
    resources = ["a", "b", "c"]

    result = asyncio.run(batch_lookup_async(resources, concurrency=2, lookup_fn=_ok))
    expected = batch_lookup(resources, concurrency=2, lookup_fn=_ok)

    assert isinstance(result, BatchResult)
    assert [item.resource for item in result.items] == resources
    assert result.counts() == expected.counts()
    assert result.concurrency == expected.concurrency
    assert [item.as_dict() for item in result.items][0]["status"] == "ok"
    assert list(result.as_dict()) == list(expected.as_dict())


def test_lookup_error_item_defaults_its_kind_and_serialises_it():
    error = LookupErrorItem("rdap", "boom")

    assert error.kind is None
    payload = LookupResult(resource="a", errors=[error]).as_dict()
    assert payload["errors"] == [{"source": "rdap", "message": "boom", "kind": None}]


def test_a_disabled_source_reports_kind_disabled_without_opening_a_socket(monkeypatch):
    # The flag is checked before any transport is built, so this stays offline.
    # The name is queryable on purpose: a reserved one is refused before the
    # flag is even consulted, which would test the reservation instead.
    monkeypatch.setenv("REGISTRATA_ENABLE_EXPERIMENTAL_RDAP", "0")

    result = unified_lookup("widgits.net", sources=["rdap"])

    assert result.ok is False
    assert [(error.source, error.kind) for error in result.errors] == [
        ("rdap", ERROR_DISABLED)
    ]
    assert ERROR_DISABLED == "disabled"


def test_a_missing_rwhois_endpoint_reports_kind_configuration():
    # No server or port means the source is misconfigured rather than unreachable, so
    # lookup() records an error instead of raising and never dials anything.
    result = unified_lookup("example.com", sources=["rwhois"])

    assert result.ok is False
    assert result.errors[0].kind == ERROR_CONFIG == "configuration"
    assert "server and port are required" in result.errors[0].message


def test_an_interrupted_run_still_accounts_for_every_resource():
    # Ctrl-C mid-sweep must never lose a resource. The hook is invoked from the
    # calling thread and ``_finish`` only guards ``Exception``, so a KeyboardInterrupt
    # raised there reaches the runner's own interrupt handling, which stops dispatch,
    # keeps what was already learned, and returns the partial report. Returning rather
    # than re-raising is the contract: a caller whose sweep was interrupted still wants the
    # part of the report it paid for, and the accounting below is what makes that safe.
    resources = [f"{index}.example" for index in range(8)]
    seen = []

    def hook(item):
        seen.append(item.status)
        if len(seen) == 3:
            raise KeyboardInterrupt

    result = batch_lookup(resources, concurrency=1, lookup_fn=_ok, on_result=hook)

    assert [item.resource for item in result.items] == resources
    assert _statuses(result) == ["ok", "ok", "ok"] + ["skipped"] * 5
    assert result.stopped_reason == "cancelled"
    assert result.duration_ms >= 0
    assert result.counts() == {
        "total": 8,
        "ok": 3,
        "partial": 0,
        "empty": 0,
        "reserved": 0,
        "blocked": 0,
        "error": 0,
        "skipped": 5,
    }
    assert all(item.skip_reason == "cancelled" for item in result.items if item.skipped)
    assert seen == ["ok", "ok", "ok"] + ["skipped"] * 5


def test_a_cancel_that_arrives_mid_flight_lets_running_lookups_finish():
    # Stopping is safe rather than abrupt: a stop signal only stops *dispatching*, so a
    # cancel that lands while every lookup is already in flight loses nothing. The
    # barrier makes "already in flight" a fact rather than a timing guess - the cancel
    # is only raised once all four lookups have entered the runner - and there is no
    # queued work left behind, so the run cannot accidentally be judged on how quickly
    # the runner notices the event.
    cancel = threading.Event()
    in_flight = threading.Barrier(4)
    resources = ["a", "b", "c", "d"]
    seen = []

    def fake(resource, **kwargs):
        # Every worker clears the runner's own stop check before it reaches the barrier,
        # so all four are genuinely in flight by the time the event is set.
        in_flight.wait(timeout=5)
        if resource == "a":
            cancel.set()
        return _answer(resource)

    result = batch_lookup(
        resources,
        concurrency=4,
        lookup_fn=fake,
        on_result=seen.append,
        cancel_event=cancel,
    )

    assert [item.resource for item in result.items] == resources
    assert _statuses(result) == ["ok", "ok", "ok", "ok"]
    assert result.counts() == {
        "total": 4,
        "ok": 4,
        "partial": 0,
        "empty": 0,
        "reserved": 0,
        "blocked": 0,
        "error": 0,
        "skipped": 0,
    }
    assert result.counts()["skipped"] == 0
    assert len(seen) == len(resources)
    # Completion order is whatever the pool hands back, so only the set is pinned here.
    assert sorted(item.resource for item in seen) == sorted(resources)
    assert all(item.status == "ok" for item in seen)
    assert result.ok is True
    # Nothing was left in the queue to refuse, so there is no skip to point at - but a
    # run that was cancelled still has to say so, or an operator reads a clean report out
    # of a job that was cut short.
    assert result.stopped_reason == "cancelled"
    assert result.summary()["stopped_reason"] == "cancelled"


def _stop_on_fail_fast(resources):
    def fake(resource, **kwargs):
        if resource == resources[0]:
            raise RuntimeError("nope")
        return _answer(resource)

    return batch_lookup(resources, concurrency=1, fail_fast=True, lookup_fn=fake)


def _stop_on_open_circuit(resources):
    def fake(resource, **kwargs):
        if resource == resources[0]:
            return _open_circuit(resource)
        return _answer(resource)

    return batch_lookup(
        resources, concurrency=1, stop_on_open_circuit=True, lookup_fn=fake
    )


def _stop_on_cancel_event(resources):
    cancel = threading.Event()
    seen = []

    def hook(item):
        seen.append(item.resource)
        if len(seen) == 2:
            cancel.set()

    return batch_lookup(
        resources, concurrency=1, lookup_fn=_ok, on_result=hook, cancel_event=cancel
    )


def _stop_on_deadline(resources):
    def fake(resource, **kwargs):
        if resource == resources[1]:
            time.sleep(0.4)
        return _answer(resource)

    return batch_lookup(resources, concurrency=1, deadline_seconds=0.05, lookup_fn=fake)


def _stop_on_interrupt(resources):
    seen = []

    def hook(item):
        seen.append(item.resource)
        if len(seen) == 2:
            raise KeyboardInterrupt

    return batch_lookup(resources, concurrency=1, lookup_fn=_ok, on_result=hook)


STOP_PATHS = [
    ("fail_fast", _stop_on_fail_fast, "fail_fast"),
    ("circuit_open", _stop_on_open_circuit, "circuit open"),
    ("cancel_event", _stop_on_cancel_event, "cancelled"),
    ("deadline", _stop_on_deadline, "deadline exceeded"),
    ("interrupt", _stop_on_interrupt, "cancelled"),
]


@pytest.mark.parametrize(
    "name, runner, expected_reason",
    STOP_PATHS,
    ids=[case[0] for case in STOP_PATHS],
)
def test_no_stop_path_ever_loses_a_resource(name, runner, expected_reason):
    resources = [f"s{index}.example" for index in range(8)]

    result = runner(resources)

    assert result.stopped_reason == expected_reason, name
    assert [item.resource for item in result.items] == resources
    assert set(result.counts()) == ALL_COUNT_KEYS
    assert result.counts()["total"] == len(resources)
    assert result.counts()["skipped"] >= 1
    assert all(
        item.skipped and item.skip_reason or not item.skipped for item in result.items
    )


def test_a_run_leaves_the_signal_disposition_of_the_calling_process_alone():
    # Nothing in the library installs a signal handler, and this pins that it never
    # starts: a bulk tool that swallows SIGINT, or that leaves its own handler installed
    # for the life of the process, breaks the caller's terminal long after the run ends.
    # The guard is on the disposition before and after a run being the same one, because
    # the library has no business touching it either way.
    import signal

    watched = (signal.SIGINT, signal.SIGTERM)
    before = {number: signal.getsignal(number) for number in watched}

    batch_lookup(["a", "b", "c"], concurrency=2, lookup_fn=_ok)

    assert {number: signal.getsignal(number) for number in watched} == before
