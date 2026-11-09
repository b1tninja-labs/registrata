"""Command-line interface for registrata."""

from __future__ import annotations

import argparse
import json
import logging
import pathlib
import sys
import threading
from typing import Any

from ._flags import (
    ExperimentalDisabled,
    ExperimentalFeature,
    enable as enable_feature,
    lookup_env,
)
from .cache import make_cache
from .circuitbreaker import CircuitBreakerRegistry
from .client import RwhoisClient
from .conformance import check_server
from .comparison import DEFAULT_COMPARE_FIELDS, compare_lookup_result
from .diagnostics import doctor_report, trace_report
from .errors import RwhoisError
from .observability import configure_logging, log_event
from .ratelimit import RateLimiterRegistry
from .record_schema import (
    RECORD_SCHEMA_VERSION,
    REGISTRATION_RECORD_SCHEMA,
    record_to_schema,
    validate_record,
)
from .retry import Backoff
from .resolver import RwhoisResolver
from .server import RwhoisServer
from .backends.memory import MemoryBackend

logger = logging.getLogger(__name__)


def _record_dict(obj: Any) -> dict[str, Any]:
    return {
        "class": obj.class_name,
        "id": obj.get("ID"),
        "auth_area": obj.get("Auth-Area"),
        "attributes": obj.as_dict(),
    }


def _result_dict(result: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "ok": result.ok,
        "error_code": result.error_code,
        "error_text": result.error_text,
        "objects": [_record_dict(obj) for obj in getattr(result, "objects", [])],
        "referrals": [
            {"host": r.host, "port": r.port, "auth_area": r.auth_area}
            for r in getattr(result, "referrals", [])
        ],
    }
    return data


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _lookup_exit_code(result: Any) -> int:
    """Exit status for a unified lookup.

    A special-use name is an answer, not a failure: "no registry can serve this"
    must not read as a broken pipeline in a script, so it exits 0 and says why on
    stderr -- stdout stays pure JSON when --json was given.
    """
    reason = getattr(result, "unqueryable", None)
    if reason:
        print(f"not queryable: {reason}", file=sys.stderr)
        return 0
    return 0 if result.ok else 1


def _print_query_result(result: Any, *, json_out: bool) -> int:
    if json_out:
        _print_json(_result_dict(result))
        return 0 if result.ok else 1
    if result.error_code is not None:
        print(f"error {result.error_code}: {result.error_text or ''}", file=sys.stderr)
    for obj in result.objects:
        print(
            f"object {obj.class_name} {obj.get('ID') or ''} {obj.get('Auth-Area') or ''}"
        )
        for attr in obj.attributes:
            print(f"  {attr.name}: {attr.value}")
    for ref in result.referrals:
        print(f"referral {ref.host}:{ref.port} auth-area={ref.auth_area}")
    return 0 if result.ok else 1


def _cmd_query(args: argparse.Namespace) -> int:
    with RwhoisClient.connect(args.host, args.port, timeout=args.timeout) as client:
        result = client.query(args.cls, args.query, raise_errors=False)
        return _print_query_result(result, json_out=args.json)


def _cmd_resolve(args: argparse.Namespace) -> int:
    resolver = RwhoisResolver(
        args.root, args.port, timeout=args.timeout, limit=args.limit
    )
    result = resolver.resolve(args.query, class_name=args.cls)
    if args.json:
        _print_json(
            {
                "objects": [_record_dict(obj) for obj in result.objects],
                "referrals": [
                    {"host": r.host, "port": r.port, "auth_area": r.auth_area}
                    for r in result.referrals
                ],
                "errors": [
                    {"error_code": r.error_code, "error_text": r.error_text}
                    for r in result.errors
                ],
                "stopped_reason": result.stopped_reason,
            }
        )
        return 0 if result.objects else 1
    for obj in result.objects:
        print(f"object {obj.class_name} {obj.get('ID') or ''}")
    for ref in result.referrals:
        print(f"referral {ref.host}:{ref.port} auth-area={ref.auth_area}")
    if not result.objects and not result.referrals:
        print("no results", file=sys.stderr)
    return 0 if result.objects else 1


def _cmd_schema(args: argparse.Namespace) -> int:
    with RwhoisClient.connect(args.host, args.port, timeout=args.timeout) as client:
        response = client.schema(args.authority_area, *args.cls)
        if args.json:
            _print_json({"groups": response.schema_groups})
        for group in response.schema_groups:
            class_name = group.get("class", "?")
            attrs = [f"{k}={v}" for k, v in group.items() if k != "class"]
            print(f"schema {class_name} {' '.join(attrs)}")
        return 0 if response.ok else 1


def _cmd_soa(args: argparse.Namespace) -> int:
    with RwhoisClient.connect(args.host, args.port, timeout=args.timeout) as client:
        response = client.soa(args.authority_area)
        if args.json:
            _print_json(
                [
                    {
                        "authority": soa.authority,
                        "ttl": soa.ttl,
                        "serial": soa.serial,
                        "refresh": soa.refresh,
                        "increment": soa.increment,
                        "retry": soa.retry,
                        "tech_contact": soa.tech_contact,
                        "admin_contact": soa.admin_contact,
                        "hostmaster": soa.hostmaster,
                        "primary": soa.primary,
                        "extra": soa.extra,
                    }
                    for soa in response.soa
                ]
            )
        for soa in response.soa:
            print(
                f"soa authority={soa.authority} primary={soa.primary} serial={soa.serial}"
            )
        return 0 if response.ok else 1


def _cmd_status(args: argparse.Namespace) -> int:
    with RwhoisClient.connect(args.host, args.port, timeout=args.timeout) as client:
        response = client.status()
        if args.json:
            _print_json(dict(response.status))
        else:
            for key, value in response.status:
                print(f"{key}: {value}")
        return 0 if response.ok else 1


def _cmd_banner(args: argparse.Namespace) -> int:
    with RwhoisClient.connect(args.host, args.port, timeout=args.timeout) as client:
        banner = client.banner
        if args.json:
            _print_json(
                {
                    "raw": banner.raw if banner else "",
                    "host": banner.host if banner else "",
                    "implementation": banner.implementation if banner else "",
                    "versions": [str(v) for v in banner.versions] if banner else [],
                }
            )
        else:
            print(banner.raw if banner else "")
        return 0


def _make_demo_backend(
    auth_area: str, query_value: str = "example.com"
) -> MemoryBackend:
    backend = MemoryBackend(auth_area)
    backend.add_object(
        "domain",
        {
            "Class-Name": "domain",
            "Auth-Area": auth_area,
            "ID": f"dom-1.{auth_area}",
            "Updated": "19970107201111000",
            "Domain-Name": query_value or auth_area,
            "Server": ("I", f"hst-1.{auth_area}"),
        },
        auth_area=auth_area,
    )
    return backend


def _cmd_check_server(args: argparse.Namespace) -> int:
    report = check_server(
        args.host,
        args.port,
        timeout=args.timeout,
        query_class=args.cls,
        query_text=args.query,
    )
    if args.json:
        _print_json(report.as_dict())
    else:
        print(f"checking {args.host}:{args.port}")
        for item in report.items:
            print(f"{item.status.upper():4} {item.name}: {item.detail}")
        if report.fatal:
            print(f"FATAL {report.fatal}")
        print(f"score {report.score} ok={report.ok}")
    return 0 if report.ok else 1


def _cmd_serve(args: argparse.Namespace) -> int:
    backend = (
        _make_demo_backend(args.auth_area, args.query)
        if args.memory
        else MemoryBackend(args.auth_area)
    )
    for password in args.password or []:
        backend.add_password(password)
    for referral in args.referral or []:
        try:
            area, host, port = referral.split(",")
            backend.add_referral(area, host, int(port), auth_area=area)
        except ValueError:
            print("invalid --referral; expected auth-area,host,port", file=sys.stderr)
            return 2
    server = RwhoisServer(
        backend,
        host=args.bind,
        port=args.port,
        server_name=args.server_name or args.bind,
        contact=args.contact,
        idle_timeout=args.idle_timeout,
        registration_deferred=args.defer_registrations,
    )
    host, port = server.start()
    print(f"listening on {host}:{port}", flush=True)
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


def _safety_context(args: argparse.Namespace):
    limiter = None
    if getattr(args, "rate_limit", 0.0):
        limiter = RateLimiterRegistry(
            default_rate_per_second=float(args.rate_limit),
            default_capacity=max(1, int(getattr(args, "burst", 1))),
        )
    backoff = Backoff(
        base_delay=getattr(args, "backoff_delay", 0.5),
        jitter=bool(getattr(args, "jitter", False)),
    )
    cache = None
    if getattr(args, "cache_ttl", 0.0):
        cache = make_cache(
            getattr(args, "cache_backend", "memory"),
            path=getattr(args, "cache_dir", None),
            default_ttl=float(args.cache_ttl),
            namespace="responses",
            max_size=max(1, int(getattr(args, "cache_size", 256))),
        )
    return limiter, backoff, cache


def _breaker_from_args(args: argparse.Namespace) -> CircuitBreakerRegistry | None:
    if getattr(args, "no_circuit_breaker", False):
        return None
    failure_threshold = int(getattr(args, "circuit_failure_threshold", 5) or 0)
    if failure_threshold <= 0:
        return None
    return CircuitBreakerRegistry(
        default_failure_threshold=failure_threshold,
        default_recovery_timeout=float(
            getattr(args, "circuit_recovery_timeout", 30.0) or 0.0
        ),
        default_success_threshold=max(
            1, int(getattr(args, "circuit_success_threshold", 1) or 1)
        ),
    )


def _unified_json(
    result, *, records_only: bool = False, provenance_only: bool = False
) -> dict[str, Any]:
    if provenance_only:
        data = result.as_dict()
        return {
            "resource": result.resource,
            "kind": result.kind,
            "sources": result.sources,
            "ok": result.ok,
            "errors": [
                {"source": e.source, "message": e.message} for e in result.errors
            ],
            "provenance": data.get("provenance", {}),
        }
    if not records_only:
        return result.as_dict()
    data = result.as_dict()
    return {
        "resource": result.resource,
        "kind": result.kind,
        "sources": result.sources,
        "ok": result.ok,
        "errors": [{"source": e.source, "message": e.message} for e in result.errors],
        "provenance": data.get("provenance", {}),
        "records": [record.as_dict() for record in result.records],
    }


def _cmd_lookup(args: argparse.Namespace) -> int:
    sources = (
        [s.strip() for s in args.sources.split(",") if s.strip()]
        if args.sources
        else None
    )
    breaker = _breaker_from_args(args)
    result = _run_unified_lookup(args, sources=sources, breaker=breaker)
    if args.json:
        _print_json(
            _unified_json(
                result,
                records_only=getattr(args, "records_only", False),
                provenance_only=getattr(args, "provenance", False),
            )
        )
        return _lookup_exit_code(result)

    print(f"{args.resource} [{result.kind}]")
    if result.errors:
        for err in result.errors:
            print(f"  error {err.source}: {err.message}", file=sys.stderr)
    if "rdap" in result.results:
        item = result.results["rdap"]
        print(f"  rdap: {item.url} status={item.status}")
    if "whois" in result.results:
        item = result.results["whois"]
        print(f"  whois: {item.server}:{item.port}")
    if "rwhois" in result.results:
        item = result.results["rwhois"]
        print(f"  rwhois: {args.rwhois_server}:{args.rwhois_port} ok={item.ok}")
        for obj in getattr(item, "objects", []):
            print(f"    {obj.class_name} {obj.get('ID') or ''}")
    return _lookup_exit_code(result)


def _cmd_whois(args: argparse.Namespace) -> int:
    from .experimental import whois as whois_module

    follow_referrals = not args.no_referrals
    log_event(
        logger,
        logging.INFO,
        "whois_command",
        resource=args.resource,
        server=args.whois_server,
        port=args.whois_port,
        follow_referrals=follow_referrals,
    )
    limiter, backoff, cache = _safety_context(args)
    result = whois_module.lookup_whois(
        args.resource,
        server=args.whois_server,
        port=args.whois_port,
        timeout=args.timeout,
        query=args.query,
        limiter=limiter,
        retries=args.retries,
        backoff=backoff,
        cache=cache,
        cache_ttl=args.cache_ttl,
        force_refresh=args.force_refresh,
        follow_referrals=follow_referrals,
        max_bytes=getattr(args, "max_bytes", None),
    )
    if args.json:
        payload = result.as_dict()
        payload["normalized"] = result.normalized().as_dict() if result.fields else {}
        if getattr(args, "record_only", False):
            payload = {"resource": args.resource, "record": payload["normalized"]}
        _print_json(payload)
        return _lookup_exit_code(result)

    if result.error:
        print(f"error: {result.error}", file=sys.stderr)
    if result.server:
        print(f"server: {result.server}:{result.port}")
    if len(result.hops) > 1:
        # The answer came from the end of a referral chain, and without the route it reads as a
        # wrong record: live example.com data refers from Verisign to whois.iana.org, which answers
        # about the TLD rather than the domain.
        print("hops: " + " -> ".join(result.hops))
    if result.referrals:
        print("referrals:")
        for ref in result.referrals:
            print(f"  {ref}")
    if getattr(args, "raw_only", False):
        print(result.raw, end="")
    elif result.fields:
        record = result.normalized()
        print(
            f"record: source={record.source} kind={record.kind} identifier={record.identifier}"
        )
        if result.raw:
            print("raw:")
            print(result.raw, end="")
    else:
        print(result.raw, end="")
    return _lookup_exit_code(result)


def _cmd_rdap(args: argparse.Namespace) -> int:
    from .experimental import rdap as rdap_module

    log_event(
        logger,
        logging.INFO,
        "rdap_command",
        resource=args.resource,
        base_url=args.rdap_base_url,
    )
    limiter, backoff, cache = _safety_context(args)
    result = rdap_module.lookup_rdap(
        args.resource,
        base_url=args.rdap_base_url,
        cache_dir=args.cache_dir,
        timeout=args.timeout,
        limiter=limiter,
        retries=args.retries,
        backoff=backoff,
        cache=cache,
        cache_ttl=args.cache_ttl,
        force_refresh=args.force_refresh,
        max_bytes=getattr(args, "max_bytes", None),
        conditional_revalidate=not bool(getattr(args, "no_rdap_conditional", False)),
        revalidation_ttl=float(
            getattr(args, "rdap_revalidation_ttl", 7 * 24 * 60 * 60) or 0.0
        ),
        field_set=getattr(args, "field_set", None),
    )
    if args.json:
        normalized = (
            rdap_module.normalize_rdap(
                result.data,
                headers=result.headers,
                url=result.url,
                status=result.status,
            ).as_dict()
            if result.data
            else {}
        )
        payload = {
            "resource": args.resource,
            "url": result.url,
            "status": result.status,
            "error": result.error,
            "headers": result.headers,
            "data": result.data,
            "normalized": normalized,
        }
        details = result.error_details()
        if details is not None:
            payload["rdap_error"] = details
        if getattr(args, "record_only", False):
            payload = {"resource": args.resource, "record": normalized}
        _print_json(payload)
        return _lookup_exit_code(result)

    if result.error:
        print(f"error: {result.error}", file=sys.stderr)
    details = result.error_details()
    if details is not None:
        code = (
            details.get("error_code")
            if details.get("error_code") is not None
            else details.get("error_code_raw")
        )
        message = details.get("title") or "; ".join(details.get("description") or [])
        print(f"rdap error: errorCode={code} {message}".rstrip(), file=sys.stderr)
    print(f"rdap: {result.url} status={result.status}")
    if result.data:
        normalized = rdap_module.normalize_rdap(
            result.data,
            headers=result.headers,
            url=result.url,
            status=result.status,
        )
        print(
            f"record: source={normalized.source} kind={normalized.kind} identifier={normalized.identifier}"
        )
        if normalized.conformance:
            print(f"  conformance: {', '.join(normalized.conformance)}")
        if normalized.lang:
            print(f"  lang: {normalized.lang}")
        for entry in normalized.truncation:
            print(
                f"  truncated ({entry['truncation']}): {entry['scope']}: {entry['title'] or entry['type']}"
            )
        for item in normalized.redacted[:10]:
            name = item["name_type"] or item["name_description"] or "unnamed"
            print(
                f"  redacted: {name} [{item['method']}] {item['post_path'] or item['pre_path'] or ''}".rstrip()
            )
        if len(normalized.redacted) > 10:
            print(f"  redacted: ... {len(normalized.redacted) - 10} more")
        if normalized.subsetting:
            available = ", ".join(
                str(field.get("name"))
                for field in normalized.subsetting.get("available_field_sets", [])
            )
            print(
                f"  field set: {normalized.subsetting.get('current_field_set')} of [{available}]"
            )
        if normalized.truncated or normalized.truncation:
            # Truncation only, not `incomplete`. That property also covers RFC 9537 redaction, and
            # redaction is the ordinary state of a modern gTLD record -- live PIR data for
            # example.org redacts the registry domain id and nothing else -- so warning on it means
            # warning on every lookup until the warning stops meaning anything. Each redacted
            # member is already itemized above; this line is for the abnormal case where the
            # registry sent less than it had.
            print(
                "  warning: registry sent a truncated response; more data exists",
                file=sys.stderr,
            )
    return _lookup_exit_code(result)


def _read_resources(source: str) -> list[str]:
    """Read resources from a file, or from stdin when the path is ``-``."""
    if source == "-":
        lines = sys.stdin.read().splitlines()
    else:
        path = pathlib.Path(source)
        if not path.exists():
            raise ValueError(f"resource file not found: {source}")
        lines = path.read_text(encoding="utf-8").splitlines()
    return [line for line in lines if line.strip()]


def _bulk_line(item: Any) -> str:
    detail = ""
    if item.error:
        detail = f" {item.error}"
    elif item.skip_reason:
        detail = f" ({item.skip_reason})"
    elif item.result is not None and getattr(item.result, "unqueryable", None):
        detail = f" ({item.result.unqueryable})"
    elif item.result is not None and item.result.errors:
        detail = " " + "; ".join(
            f"{error.source}:{error.message}" for error in item.result.errors[:2]
        )
    return f"{item.status:8} {item.duration_ms:8.1f}ms {item.resource}{detail}"


#: Source errors that mean the command itself could not have worked.
USAGE_ERROR_KINDS = frozenset({"configuration", "disabled"})


def _usage_problem(result) -> str | None:
    """Return a message when no resource could possibly have been answered.

    Asking for ``--sources rwhois`` without a server, or for a source switched off by
    a feature flag, makes every resource come back empty. Reporting that as a normal
    run tells a cron job that the registries simply have no data for the list, when
    in fact nothing was ever asked. Only a run where every attempted resource failed
    this way counts, so one misconfigured source alongside real answers is not
    hidden.
    """
    attempted = [item for item in result.items if not item.skipped]
    if not attempted:
        return None
    first: str | None = None
    for item in attempted:
        if item.ok or item.result is None:
            return None
        errors = list(item.result.errors)
        kinds = {error.kind for error in errors}
        if not errors or not kinds <= USAGE_ERROR_KINDS:
            return None
        if first is None:
            offending = next(
                error for error in errors if error.kind in USAGE_ERROR_KINDS
            )
            first = f"{offending.source}: {offending.message}"
    return first


def _cmd_bulk(args: argparse.Namespace) -> int:
    from .experimental.batch import batch_lookup

    try:
        resources = _read_resources(args.source)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    sources = (
        [s.strip() for s in args.sources.split(",") if s.strip()]
        if args.sources
        else None
    )
    limiter, backoff, cache = _safety_context(args)
    breaker = _breaker_from_args(args)
    log_event(
        logger,
        logging.INFO,
        "bulk_command",
        source=args.source,
        resources=len(resources),
        concurrency=args.concurrency,
        sources=sources,
    )

    stream = bool(args.jsonl)

    def _emit(item: Any) -> None:
        if stream:
            print(
                json.dumps(item.as_dict(records=args.records), sort_keys=True),
                flush=True,
            )
        elif not args.json:
            print(_bulk_line(item), flush=True)

    result = batch_lookup(
        resources,
        concurrency=args.concurrency,
        sources=sources,
        on_result=_emit,
        aggregate_rate_per_second=args.aggregate_rate,
        aggregate_burst=args.aggregate_burst,
        fail_fast=args.fail_fast,
        stop_on_open_circuit=args.stop_on_open_circuit,
        deadline_seconds=args.deadline,
        timeout=args.timeout,
        server=args.rwhois_server,
        port=args.rwhois_port,
        rwhois_class=args.cls,
        whois_server=args.whois_server,
        whois_port=args.whois_port,
        rdap_base_url=args.rdap_base_url,
        rdap_field_set=args.field_set,
        cache_dir=args.cache_dir,
        limiter=limiter,
        breaker=breaker,
        retries=args.retries,
        backoff=backoff,
        cache=cache,
        cache_ttl=args.cache_ttl,
        force_refresh=args.force_refresh,
        follow_referrals=args.follow_referrals,
        max_bytes=getattr(args, "max_bytes", None),
        conditional_rdap=not bool(getattr(args, "no_rdap_conditional", False)),
        rdap_revalidation_ttl=float(
            getattr(args, "rdap_revalidation_ttl", 7 * 24 * 60 * 60) or 0.0
        ),
        skip_reserved=not bool(getattr(args, "query_reserved", False)),
    )

    counts = result.counts()
    refused = counts["error"] + counts["blocked"]
    if args.json:
        payload = result.as_dict(records=args.records)
        if args.records:
            payload["records"] = [record.as_dict() for record in result.records()]
            payload.pop("items", None)
        _print_json(payload)
    elif not stream:
        print()
    summary = result.summary()
    print(
        "bulk: "
        + " ".join(
            f"{key}={counts[key]}"
            for key in (
                "total",
                "ok",
                "partial",
                "empty",
                "reserved",
                "blocked",
                "error",
                "skipped",
            )
        )
        + f" in {summary['duration_ms']}ms concurrency={summary['concurrency']}",
        file=sys.stderr,
    )
    if result.stopped_reason:
        print(f"bulk: stopped early: {result.stopped_reason}", file=sys.stderr)
    problem = _usage_problem(result)
    if problem:
        print(f"bulk: configuration error: {problem}", file=sys.stderr)
        return 2
    return 0 if not refused else 1


def _cmd_compare(args: argparse.Namespace) -> int:
    sources = (
        [s.strip() for s in args.sources.split(",") if s.strip()]
        if args.sources
        else None
    )
    fields = (
        tuple(f.strip() for f in args.fields.split(",") if f.strip())
        if args.fields
        else DEFAULT_COMPARE_FIELDS
    )
    log_event(
        logger,
        logging.INFO,
        "compare_command",
        resource=args.resource,
        sources=sources,
        fields=fields,
    )
    breaker = _breaker_from_args(args)
    result = _run_unified_lookup(args, sources=sources, breaker=breaker)
    report = compare_lookup_result(result, fields=fields)
    if args.json:
        _print_json(report.as_dict())
        return 0 if report.ok else 1

    print(
        f"{report.resource} [{report.kind}] sources={','.join(report.sources) or '-'}"
    )
    data = report.report
    if not report.ok:
        print("  no records to compare", file=sys.stderr)
        return 1
    if data.get("comparable"):
        print(f"  score: {data.get('score')}")
    else:
        # No number here on purpose. One source is what a lookup returns when the other failed,
        # and printing a score a few lines above an error from that other source would advertise
        # an agreement that was never measured.
        print(f"  score: n/a ({data.get('reason') or 'nothing compared'})")
    for field_name in data.get("matches", []):
        print(f"  match {field_name}")
    for field_name, values in data.get("differences", {}).items():
        print(f"  diff {field_name}")
        for source, value in values.items():
            print(f"    {source}: {value}")
    if result.errors:
        for err in result.errors:
            print(f"  error {err.source}: {err.message}", file=sys.stderr)
    return 0


def _run_unified_lookup(
    args: argparse.Namespace,
    *,
    sources: list[str] | None = None,
    breaker: CircuitBreakerRegistry | None = None,
):
    from .experimental import lookup as unified_lookup

    limiter, backoff, cache = _safety_context(args)
    if breaker is None:
        breaker = _breaker_from_args(args)
    return unified_lookup(
        args.resource,
        sources=sources,
        skip_reserved=not bool(getattr(args, "query_reserved", False)),
        timeout=args.timeout,
        server=args.rwhois_server,
        port=args.rwhois_port,
        rwhois_class=args.cls,
        whois_server=args.whois_server,
        whois_port=args.whois_port,
        rdap_base_url=args.rdap_base_url,
        cache_dir=args.cache_dir,
        limiter=limiter,
        breaker=breaker,
        retries=args.retries,
        backoff=backoff,
        cache=cache,
        cache_ttl=args.cache_ttl,
        force_refresh=args.force_refresh,
        follow_referrals=args.follow_referrals,
        max_bytes=getattr(args, "max_bytes", None),
        conditional_rdap=not bool(getattr(args, "no_rdap_conditional", False)),
        rdap_revalidation_ttl=float(
            getattr(args, "rdap_revalidation_ttl", 7 * 24 * 60 * 60) or 0.0
        ),
    )


def _cmd_trace(args: argparse.Namespace) -> int:
    sources = (
        [s.strip() for s in args.sources.split(",") if s.strip()]
        if args.sources
        else None
    )
    breaker = _breaker_from_args(args)
    log_event(
        logger,
        logging.INFO,
        "trace_command",
        resource=args.resource,
        sources=sources,
    )
    result = _run_unified_lookup(args, sources=sources, breaker=breaker)
    report = trace_report(result)
    if args.json:
        _print_json(report)
        return 0 if report["ok"] else 1

    print(
        f"{report['resource']} [{report['kind']}] sources={','.join(report['sources']) or '-'}"
    )
    for source, status in report["source_status"].items():
        if source == "rdap":
            print(
                f"  rdap: url={status.get('url')} status={status.get('status')} ok={status.get('ok')}"
            )
        elif source == "whois":
            print(
                f"  whois: {status.get('server')}:{status.get('port')} ok={status.get('ok')} fields={status.get('fields')} referrals={len(status.get('referrals', []))}"
            )
        elif source == "rwhois":
            print(
                f"  rwhois: {status.get('server')}:{status.get('port')} ok={status.get('ok')} objects={status.get('objects')} error={status.get('error_code')}"
            )
        else:
            print(f"  {source}: {status}")
        if status.get("error"):
            print(f"    error: {status['error']}", file=sys.stderr)
    for err in report["errors"]:
        print(f"  error {err['source']}: {err['message']}", file=sys.stderr)
    circuits = report.get("circuit_breakers") or {}
    for key, state in circuits.items():
        print(
            f"  circuit {key}: {state.get('state')} failures={state.get('failure_count')}"
        )
    return 0 if report["ok"] else 1


def _cmd_doctor(args: argparse.Namespace) -> int:
    sources = (
        [s.strip() for s in args.sources.split(",") if s.strip()]
        if args.sources
        else None
    )
    fields = (
        tuple(f.strip() for f in args.fields.split(",") if f.strip())
        if args.fields
        else DEFAULT_COMPARE_FIELDS
    )
    breaker = _breaker_from_args(args)
    result = None
    if not getattr(args, "no_lookup", False):
        log_event(
            logger,
            logging.INFO,
            "doctor_command",
            resource=args.resource,
            sources=sources,
            lookup_performed=True,
        )
        result = _run_unified_lookup(args, sources=sources, breaker=breaker)
    else:
        log_event(
            logger,
            logging.INFO,
            "doctor_command",
            resource=args.resource,
            sources=sources,
            lookup_performed=False,
        )
    report = doctor_report(
        args.resource,
        result=result,
        fields=fields,
        cache_dir=args.cache_dir,
        breaker=breaker,
    )
    if args.json:
        _print_json(report)
        return 0 if report["healthy"] else 1

    print(
        f"doctor: {report['resource']} [{report['kind']}] healthy={report['healthy']}"
    )
    for check in report["checks"]:
        status = (
            "ok" if check.get("ok") else "skip" if check.get("ok") is None else "fail"
        )
        detail = ""
        if check["name"] == "lookup":
            detail = f" sources={','.join(report['sources']) or '-'}"
        elif check["name"] == "records":
            detail = f" count={check.get('count')}"
            incomplete = [
                item for item in check.get("completeness", []) if item.get("incomplete")
            ]
            if incomplete:
                # A partial answer is worth flagging without --json.
                detail += " incomplete=" + ",".join(
                    item["source"] for item in incomplete
                )
        elif check["name"] == "comparison":
            score = check.get("report", {}).get("score")
            if score is not None:
                detail = f" score={score}"
        elif check["name"] == "features":
            detail = " " + ", ".join(
                f"{item['feature']}={'on' if item['enabled'] else 'off'}"
                for item in check.get("items", [])
            )
        elif check["name"] == "bootstrap_cache":
            detail = f" dir={check.get('cache_dir') or '-'}"
        elif check["name"] == "circuit_breakers":
            items = check.get("items", {})
            detail = " " + (
                ", ".join(f"{key}:{value.get('state')}" for key, value in items.items())
                if items
                else "-"
            )
        print(f"  {status} {check['name']}{detail}")
    for err in report["errors"]:
        print(f"  error {err['source']}: {err['message']}", file=sys.stderr)
    for suggestion in report.get("suggestions", []):
        print(f"  suggest: {suggestion}")
    return 0 if report["healthy"] else 1


def _cmd_record_schema(args: argparse.Namespace) -> int:
    if not getattr(args, "resource", None):
        if args.json:
            _print_json(REGISTRATION_RECORD_SCHEMA)
        else:
            print(f"registration-record schema {RECORD_SCHEMA_VERSION}")
            print(
                "  properties: "
                + ", ".join(REGISTRATION_RECORD_SCHEMA.get("properties", {}))
            )
        return 0

    sources = (
        [s.strip() for s in args.sources.split(",") if s.strip()]
        if args.sources
        else None
    )
    breaker = _breaker_from_args(args)
    result = _run_unified_lookup(args, sources=sources, breaker=breaker)
    records = [record_to_schema(record) for record in result.records]
    invalid = []
    for wrapped in records:
        errors = validate_record(wrapped["record"])
        if errors:
            invalid.append(
                {"source": wrapped["record"].get("source"), "errors": errors}
            )
    payload = {
        "schema_version": RECORD_SCHEMA_VERSION,
        "resource": result.resource,
        "kind": result.kind,
        "ok": result.ok,
        "errors": [{"source": e.source, "message": e.message} for e in result.errors],
        "records": records,
        "invalid": invalid,
    }
    if args.json:
        _print_json(payload)
        return 0 if result.ok and not invalid else 1
    print(
        f"{result.resource} [{result.kind}] records={len(records)} invalid={len(invalid)}"
    )
    for err in result.errors:
        print(f"  error {err.source}: {err.message}", file=sys.stderr)
    return 0 if result.ok and not invalid else 1


def _cmd_gateway(args: argparse.Namespace) -> int:
    enable_feature(ExperimentalFeature.GATEWAY)
    from .experimental.gateway import GatewayConfig, GatewayServer

    if args.bind not in {"127.0.0.1", "localhost", "::1"} and not args.allow_remote:
        print("refusing non-local bind without --allow-remote", file=sys.stderr)
        return 2
    api_key = getattr(args, "api_key", None) or lookup_env("GATEWAY_API_KEY")
    config = GatewayConfig(
        bind=args.bind,
        port=args.port,
        lookup_sources=args.sources,
        timeout=args.timeout,
        cache_dir=args.cache_dir,
        cache_backend=args.cache_backend,
        cache_ttl=args.cache_ttl,
        cache_size=args.cache_size,
        rate_limit=args.rate_limit,
        burst=args.burst,
        retries=args.retries,
        backoff_delay=args.backoff_delay,
        jitter=args.jitter,
        max_bytes=args.max_bytes,
        follow_referrals=args.follow_referrals,
        allow_remote=args.allow_remote,
        circuit_failure_threshold=0
        if getattr(args, "no_circuit_breaker", False)
        else int(getattr(args, "circuit_failure_threshold", 5) or 0),
        circuit_recovery_timeout=float(
            getattr(args, "circuit_recovery_timeout", 30.0) or 0.0
        ),
        circuit_success_threshold=max(
            1, int(getattr(args, "circuit_success_threshold", 1) or 1)
        ),
        metrics_enabled=not bool(getattr(args, "no_metrics", False)),
        api_key=api_key,
        tls_certfile=getattr(args, "tls_certfile", None),
        tls_keyfile=getattr(args, "tls_keyfile", None),
    )
    try:
        server = GatewayServer(config)
        host, port = server.start()
    except ExperimentalDisabled as exc:
        print(f"gateway disabled: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"gateway configuration error: {exc}", file=sys.stderr)
        return 2
    print(f"gateway listening on {server.config.scheme}://{host}:{port}", flush=True)
    try:
        threading.Event().wait(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


def _add_timeout_arg(parser: argparse.ArgumentParser, default: float = 10.0) -> None:
    parser.add_argument("--timeout", type=float, default=default)


def _add_safety_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cache-dir", default=None)
    parser.add_argument(
        "--cache-ttl", type=float, default=0.0, help="response cache TTL in seconds"
    )
    parser.add_argument(
        "--cache-backend",
        choices=("memory", "file", "sqlite"),
        default="memory",
        help="response cache backend",
    )
    parser.add_argument(
        "--cache-size", type=int, default=256, help="memory cache entry limit"
    )
    parser.add_argument(
        "--force-refresh", action="store_true", help="bypass response caches"
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="requests per second per RDAP/WHOIS endpoint",
    )
    parser.add_argument(
        "--burst", type=int, default=1, help="rate-limit token bucket capacity"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=0,
        help="retry count for transient network/HTTP failures",
    )
    parser.add_argument(
        "--backoff-delay",
        type=float,
        default=0.5,
        help="initial exponential backoff delay",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="maximum response bytes for WHOIS/RDAP HTTP fetches",
    )
    parser.add_argument(
        "--jitter", action="store_true", help="randomize retry backoff delays"
    )
    parser.add_argument(
        "--circuit-failure-threshold",
        type=int,
        default=5,
        help="consecutive failures before opening a per-endpoint circuit",
    )
    parser.add_argument(
        "--circuit-recovery-timeout",
        type=float,
        default=30.0,
        help="seconds to wait before probing an open circuit",
    )
    parser.add_argument(
        "--circuit-success-threshold",
        type=int,
        default=1,
        help="half-open successes required to close a circuit",
    )
    parser.add_argument(
        "--no-circuit-breaker",
        action="store_true",
        help="disable circuit breaker tracking",
    )
    parser.add_argument(
        "--rdap-revalidation-ttl",
        type=float,
        default=7 * 24 * 60 * 60,
        help="how long RDAP response validators are kept for conditional revalidation",
    )
    parser.add_argument(
        "--no-rdap-conditional",
        action="store_true",
        help="disable RDAP query conditional revalidation",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")


def _add_query_reserved_arg(parser: argparse.ArgumentParser) -> None:
    """Opt back in to names the reserved-name guard refuses.

    Every command that routes through the unified lookup needs this, and the
    wording has to say *why* the default is to refuse: a reserved name is not
    rejected by registries, it is answered with a documentation fixture.
    """
    parser.add_argument(
        "--query-reserved",
        action="store_true",
        help=(
            "ask registries about special-use names (RFC 6761 registry, e.g. "
            "example.com); nobody can register them and a public registry answers "
            "with a documentation fixture rather than data -- use this for a smoke "
            "test, or for a private RWhois tree that holds such objects"
        ),
    )


def _add_unified_args(
    parser: argparse.ArgumentParser,
    default_sources: str = "rdap,whois",
    *,
    positional: bool = True,
) -> None:
    if positional:
        parser.add_argument("resource")
    parser.add_argument(
        "--sources", default=default_sources, help="comma-separated: rdap,whois,rwhois"
    )
    _add_timeout_arg(parser)
    parser.add_argument("--rwhois-server", default=None)
    parser.add_argument("--rwhois-port", type=int, default=None)
    parser.add_argument(
        "--class", dest="cls", default=None, help="RWhois class restriction"
    )
    parser.add_argument("--whois-server", default=None)
    parser.add_argument("--whois-port", type=int, default=43)
    parser.add_argument("--rdap-base-url", default=None)
    parser.add_argument(
        "--follow-referrals",
        action="store_true",
        help="follow classic WHOIS Refer/Whois Server referrals",
    )
    _add_query_reserved_arg(parser)
    parser.add_argument(
        "--records-only",
        action="store_true",
        help="with --json, emit only normalized records and errors",
    )
    parser.add_argument(
        "--provenance",
        action="store_true",
        help="with --json, emit only source provenance and hop trace",
    )
    _add_safety_args(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="registrata", description="RFC 2167 RWhois client/server toolkit"
    )
    # Imported here rather than at module scope: `registrata/__init__.py` pulls in
    # the client and server, and the CLI is often the thing being imported.
    from . import __version__

    parser.add_argument(
        "--version",
        action="version",
        version=f"registrata {__version__}",
        help="print the version and exit",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON where supported")
    parser.add_argument(
        "--log-level",
        choices=("debug", "info", "warning", "error", "critical"),
        default=None,
        help="enable CLI diagnostics at the given level",
    )
    parser.add_argument(
        "--log-json", action="store_true", help="emit diagnostics as JSON objects"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    query = sub.add_parser("query", help="send one query to a server")
    query.add_argument("host")
    query.add_argument("query")
    query.add_argument("port", nargs="?", type=int, default=4321)
    query.add_argument("--class", dest="cls", default=None)
    query.add_argument("--limit", type=int, default=None)
    query.add_argument("--timeout", type=float, default=10.0)
    query.set_defaults(func=_cmd_query)

    resolve = sub.add_parser("resolve", help="follow referrals from a root server")
    resolve.add_argument("query")
    resolve.add_argument("--root", required=True)
    resolve.add_argument("--port", type=int, default=4321)
    resolve.add_argument("--class", dest="cls", default=None)
    resolve.add_argument("--limit", type=int, default=20)
    resolve.add_argument("--timeout", type=float, default=10.0)
    resolve.set_defaults(func=_cmd_resolve)

    schema = sub.add_parser("schema", help="query schema for an authority area")
    schema.add_argument("host")
    schema.add_argument("authority_area")
    schema.add_argument("port", nargs="?", type=int, default=4321)
    schema.add_argument("--class", dest="cls", action="append", default=[])
    schema.add_argument("--timeout", type=float, default=10.0)
    schema.set_defaults(func=_cmd_schema)

    soa = sub.add_parser("soa", help="query SOA information")
    soa.add_argument("host")
    soa.add_argument("authority_area")
    soa.add_argument("port", nargs="?", type=int, default=4321)
    soa.add_argument("--timeout", type=float, default=10.0)
    soa.set_defaults(func=_cmd_soa)

    status = sub.add_parser("status", help="query server status")
    status.add_argument("host")
    status.add_argument("port", nargs="?", type=int, default=4321)
    status.add_argument("--timeout", type=float, default=10.0)
    status.set_defaults(func=_cmd_status)

    banner = sub.add_parser("banner", help="print the server banner")
    banner.add_argument("host")
    banner.add_argument("port", nargs="?", type=int, default=4321)
    banner.add_argument("--timeout", type=float, default=10.0)
    banner.set_defaults(func=_cmd_banner)

    check = sub.add_parser(
        "check-server", help="check an RWhois server for basic RFC 2167 behavior"
    )
    check.add_argument("host")
    check.add_argument("port", nargs="?", type=int, default=4321)
    check.add_argument("--timeout", type=float, default=10.0)
    check.add_argument(
        "--cls",
        "--class",
        dest="cls",
        default=None,
        help="probe query class; default unrestricted",
    )
    check.add_argument("--query", default="example.invalid", help="probe query text")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=_cmd_check_server)

    serve = sub.add_parser("serve", help="run an in-memory demo server")
    serve.add_argument("--memory", action="store_true", help="use a small demo dataset")
    serve.add_argument("--auth-area", default="example.com")
    serve.add_argument("--query", default="example.com", help="demo object query value")
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=4321)
    serve.add_argument("--server-name", default=None)
    serve.add_argument("--contact", default=None)
    serve.add_argument("--idle-timeout", type=float, default=30.0)
    serve.add_argument("--password", action="append", default=[])
    serve.add_argument(
        "--defer-registrations",
        action="store_true",
        help="refuse -register with %%error 120 (Registration deferred) while keeping "
        "queries up -- a maintenance window that speaks the protocol",
    )
    serve.add_argument(
        "--referral", action="append", default=[], help="auth-area,host,port"
    )
    serve.set_defaults(func=_cmd_serve)

    lookup = sub.add_parser(
        "lookup", help="experimental unified RDAP/WHOIS/RWhois lookup"
    )
    _add_unified_args(lookup, "rdap,whois")
    lookup.set_defaults(func=_cmd_lookup)

    domain = sub.add_parser(
        "domain", help="unified domain lookup via RDAP/WHOIS/RWhois"
    )
    _add_unified_args(domain, "rdap,whois")
    domain.set_defaults(func=_cmd_lookup)

    ip = sub.add_parser("ip", help="IP/CIDR lookup, defaulting to RDAP")
    _add_unified_args(ip, "rdap")
    ip.set_defaults(func=_cmd_lookup)

    asn = sub.add_parser("asn", help="ASN lookup, defaulting to RDAP")
    _add_unified_args(asn, "rdap")
    asn.set_defaults(func=_cmd_lookup)

    compare = sub.add_parser(
        "compare", help="compare normalized records from multiple sources"
    )
    _add_unified_args(compare, "rdap,whois")
    compare.add_argument(
        "--fields",
        default=",".join(DEFAULT_COMPARE_FIELDS),
        help="comma-separated compare fields",
    )
    compare.set_defaults(func=_cmd_compare)

    trace = sub.add_parser(
        "trace", help="trace resource through RDAP/WHOIS/RWhois sources"
    )
    _add_unified_args(trace, "rdap,whois")
    trace.set_defaults(func=_cmd_trace)

    doctor = sub.add_parser(
        "doctor", help="run resource diagnostics and source health checks"
    )
    _add_unified_args(doctor, "rdap,whois")
    doctor.add_argument(
        "--fields",
        default=",".join(DEFAULT_COMPARE_FIELDS),
        help="comma-separated compare fields",
    )
    doctor.add_argument(
        "--no-lookup",
        action="store_true",
        help="inspect configuration and cache state without network lookups",
    )
    doctor.set_defaults(func=_cmd_doctor)

    record_schema = sub.add_parser(
        "record-schema", help="print or apply the stable normalized record schema"
    )
    record_schema.add_argument("resource", nargs="?", default=None)
    _add_unified_args(record_schema, "rdap,whois", positional=False)
    record_schema.set_defaults(func=_cmd_record_schema)

    whois = sub.add_parser(
        "whois", help="direct experimental classic WHOIS RFC 3912 lookup"
    )
    whois.add_argument("resource")
    whois.add_argument("--whois-server", default=None)
    _add_query_reserved_arg(whois)
    whois.add_argument("--whois-port", type=int, default=43)
    whois.add_argument(
        "--query", default=None, help="override the raw WHOIS query string"
    )
    whois.add_argument(
        "--no-referrals",
        action="store_true",
        help="disable classic WHOIS referral following",
    )
    whois.add_argument(
        "--raw-only",
        action="store_true",
        help="print only raw WHOIS text in non-JSON output",
    )
    whois.add_argument(
        "--record-only",
        action="store_true",
        help="with --json, emit only the normalized record",
    )
    _add_timeout_arg(whois)
    _add_safety_args(whois)
    whois.set_defaults(func=_cmd_whois)

    rdap = sub.add_parser("rdap", help="direct experimental RDAP lookup")
    rdap.add_argument("resource")
    rdap.add_argument("--rdap-base-url", default=None)
    _add_query_reserved_arg(rdap)
    rdap.add_argument(
        "--record-only",
        action="store_true",
        help="with --json, emit only the normalized record",
    )
    rdap.add_argument(
        "--field-set",
        default=None,
        help="request a partial response using the RFC 8982 'fieldSet' query parameter",
    )
    _add_timeout_arg(rdap)
    _add_safety_args(rdap)
    rdap.set_defaults(func=_cmd_rdap)

    bulk = sub.add_parser(
        "bulk",
        help="experimental bulk lookup over a file of resources (use - for stdin)",
    )
    bulk.add_argument(
        "source", help="file with one resource per line, or - to read stdin"
    )
    bulk.add_argument(
        "--sources", default="rdap,whois", help="comma-separated: rdap,whois,rwhois"
    )
    _add_query_reserved_arg(bulk)
    bulk.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="resources in flight at once (clamped to 1-32; keep this polite)",
    )
    bulk.add_argument(
        "--aggregate-rate",
        type=float,
        default=None,
        help="global requests per second across all endpoints, on top of --rate-limit",
    )
    bulk.add_argument(
        "--aggregate-burst", type=int, default=1, help="burst size for --aggregate-rate"
    )
    bulk.add_argument(
        "--fail-fast",
        action="store_true",
        help="stop dispatching after the first failed resource",
    )
    bulk.add_argument(
        "--stop-on-open-circuit",
        action="store_true",
        help="stop dispatching once a registry reports an open circuit",
    )
    bulk.add_argument(
        "--deadline",
        type=float,
        default=None,
        help="stop dispatching after this many seconds",
    )
    bulk.add_argument(
        "--field-set",
        default=None,
        help="RFC 8982 'fieldSet' name to request from RDAP servers",
    )
    bulk.add_argument(
        "--jsonl",
        action="store_true",
        help="emit one JSON object per resource as it completes",
    )
    bulk.add_argument(
        "--records",
        action="store_true",
        help="include normalized records in JSON output",
    )
    bulk.add_argument("--rwhois-server", default=None)
    bulk.add_argument("--rwhois-port", type=int, default=None)
    bulk.add_argument(
        "--class", dest="cls", default=None, help="RWhois class restriction"
    )
    bulk.add_argument("--whois-server", default=None)
    bulk.add_argument("--whois-port", type=int, default=43)
    bulk.add_argument("--rdap-base-url", default=None)
    bulk.add_argument(
        "--follow-referrals", action="store_true", help="follow classic WHOIS referrals"
    )
    _add_timeout_arg(bulk)
    _add_safety_args(bulk)
    bulk.set_defaults(func=_cmd_bulk)

    gateway = sub.add_parser(
        "gateway", help="run an experimental local HTTP gateway/bridge"
    )
    gateway.add_argument("--bind", default="127.0.0.1")
    gateway.add_argument("--port", type=int, default=8080)
    gateway.add_argument(
        "--sources",
        default="rdap,whois",
        help="default comma-separated sources for /lookup",
    )
    gateway.add_argument(
        "--follow-referrals",
        action="store_true",
        help="enable classic WHOIS referral following by default",
    )
    gateway.add_argument(
        "--allow-remote",
        action="store_true",
        help="explicitly allow a non-localhost bind address",
    )
    gateway.add_argument(
        "--api-key",
        default=None,
        help=(
            "require X-API-Key or Authorization bearer token; defaults to "
            "REGISTRATA_GATEWAY_API_KEY (legacy RWHOIS_GATEWAY_API_KEY also read) when set"
        ),
    )
    gateway.add_argument(
        "--tls-certfile",
        default=None,
        help="serve HTTPS using this certificate PEM file",
    )
    gateway.add_argument(
        "--tls-keyfile",
        default=None,
        help="serve HTTPS using this private key PEM file",
    )
    gateway.add_argument(
        "--no-metrics", action="store_true", help="disable gateway metrics collection"
    )
    _add_timeout_arg(gateway)
    _add_safety_args(gateway)
    gateway.set_defaults(func=_cmd_gateway)

    for subcommand in (query, resolve, schema, soa, status, banner, serve):
        subcommand.add_argument(
            "--json", action="store_true", help="emit JSON where supported"
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "log_level", None):
        configure_logging(args.log_level, json=getattr(args, "log_json", False))
    logger = logging.getLogger("registrata.cli")
    try:
        return int(args.func(args))
    except RwhoisError as exc:
        print(f"rwhois error: {exc}", file=sys.stderr)
        logging.getLogger("registrata").log(
            logging.WARNING if args.log_level else logging.DEBUG,
            "cli_error",
            extra={
                "registrata": {
                    "event": "cli_error",
                    "error": str(exc),
                    "command": getattr(args, "command", None),
                }
            },
        )
        return 1
    except ConnectionError as exc:
        print(f"connection error: {exc}", file=sys.stderr)
        logger.warning(
            "cli_connection_error",
            extra={
                "registrata": {
                    "event": "cli_connection_error",
                    "error": str(exc),
                    "command": getattr(args, "command", None),
                }
            },
        )
        return 1
    except OSError as exc:
        print(f"os error: {exc}", file=sys.stderr)
        logger.warning(
            "cli_os_error",
            extra={
                "registrata": {
                    "event": "cli_os_error",
                    "error": str(exc),
                    "command": getattr(args, "command", None),
                }
            },
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
