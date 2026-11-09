"""Experimental local HTTP gateway/bridge mode.

The gateway intentionally defaults to localhost and requires the gateway feature
flag to be enabled. It exposes compact JSON endpoints for the experimental
unified lookup surface plus direct WHOIS/RDAP/RWhois helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
import logging
import pathlib
import ssl
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

from .._flags import ExperimentalFeature, require
from ..cache import Cache, make_cache
from ..circuitbreaker import CircuitBreakerRegistry
from ..errors import RwhoisError
from ..metrics import MetricsRegistry
from ..observability import log_event
from ..ratelimit import RateLimiterRegistry
from ..retry import Backoff
from .lookup import lookup
from .rdap import lookup_rdap, normalize_rdap
from .whois import lookup_whois

logger = logging.getLogger(__name__)

LOCALHOST_VALUES = {"127.0.0.1", "localhost", "::1"}


@dataclass(frozen=True)
class GatewayConfig:
    bind: str = "127.0.0.1"
    port: int = 8080
    lookup_sources: str = "rdap,whois"
    timeout: float = 10.0
    cache_dir: str | pathlib.Path | None = None
    cache_backend: str | None = None
    cache_ttl: float = 0.0
    cache_size: int = 256
    rate_limit: float = 0.0
    burst: int = 1
    retries: int = 0
    backoff_delay: float = 0.5
    jitter: bool = False
    max_bytes: int | None = None
    follow_referrals: bool = False
    allow_remote: bool = False
    breaker: CircuitBreakerRegistry | None = None
    circuit_failure_threshold: int = 5
    circuit_recovery_timeout: float = 30.0
    circuit_success_threshold: int = 1
    metrics_enabled: bool = True
    api_key: str | None = None
    tls_certfile: str | pathlib.Path | None = None
    tls_keyfile: str | pathlib.Path | None = None

    def validate(self) -> None:
        if self.bind not in LOCALHOST_VALUES and not self.allow_remote:
            raise ValueError(
                "gateway bind address is not localhost; pass allow_remote=True to override"
            )
        try:
            ipaddress.ip_address(self.bind)
        except ValueError:
            if self.bind != "localhost":
                raise ValueError("gateway bind must be an IP address or localhost")
        if self.api_key is not None and not str(self.api_key).strip():
            raise ValueError("gateway api_key must not be blank")
        if bool(self.tls_certfile) != bool(self.tls_keyfile):
            raise ValueError("gateway TLS requires both tls_certfile and tls_keyfile")
        if self.tls_certfile and not pathlib.Path(str(self.tls_certfile)).is_file():
            raise ValueError(
                f"gateway TLS certificate file not found: {self.tls_certfile}"
            )
        if self.tls_keyfile and not pathlib.Path(str(self.tls_keyfile)).is_file():
            raise ValueError(
                f"gateway TLS private key file not found: {self.tls_keyfile}"
            )

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_certfile and self.tls_keyfile)

    @property
    def scheme(self) -> str:
        return "https" if self.tls_enabled else "http"

    def build_ssl_context(self) -> ssl.SSLContext:
        """Build the server-side TLS context for a listener with TLS configured.

        TLS 1.2 is the floor: the gateway serves registration data plus optional
        API credentials, so legacy protocol versions are not acceptable defaults.
        """
        if not self.tls_enabled:
            raise ValueError("gateway TLS requires tls_certfile and tls_keyfile")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            certfile=str(self.tls_certfile), keyfile=str(self.tls_keyfile)
        )
        return context


def _is_true(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _first(params: dict[str, list[str]], key: str) -> str | None:
    values = params.get(key) or []
    return values[0] if values else None


def _sources(raw: str | None, default: str) -> list[str] | None:
    text = raw if raw is not None else default
    sources = [item.strip() for item in text.split(",") if item.strip()]
    return sources or None


def _int_or_none(value: str | int | None, default: int | None = None) -> int | None:
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float_or_default(value: str | int | float | None, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _bool_or_default(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return _is_true(value)


def _lookup_payload(
    resource: str,
    params: dict[str, list[str]],
    config: GatewayConfig,
    cache: Cache | None,
    limiter: RateLimiterRegistry | None,
    breaker: CircuitBreakerRegistry | None = None,
) -> dict[str, Any]:
    if not resource:
        raise ValueError("resource is required")
    result = lookup(
        resource,
        sources=_sources(_first(params, "sources"), config.lookup_sources),
        timeout=_float_or_default(_first(params, "timeout"), config.timeout),
        server=_first(params, "rwhois_server")
        or _first(params, "rwhois-server")
        or _first(params, "server"),
        port=_int_or_none(
            _first(params, "rwhois_port")
            or _first(params, "rwhois-port")
            or _first(params, "port")
        ),
        rwhois_class=_first(params, "class"),
        whois_server=_first(params, "whois_server") or _first(params, "whois-server"),
        whois_port=_int_or_none(
            _first(params, "whois_port") or _first(params, "whois-port")
        ),
        rdap_base_url=_first(params, "rdap_base_url")
        or _first(params, "rdap-base-url"),
        cache_dir=str(config.cache_dir) if config.cache_dir else None,
        limiter=limiter,
        breaker=breaker,
        retries=_int_or_none(_first(params, "retries"), config.retries) or 0,
        backoff=Backoff(base_delay=config.backoff_delay, jitter=config.jitter),
        cache=cache,
        cache_ttl=_float_or_default(_first(params, "cache_ttl"), config.cache_ttl),
        force_refresh=_is_true(_first(params, "force_refresh")),
        follow_referrals=_bool_or_default(
            _first(params, "follow_referrals"), config.follow_referrals
        ),
        max_bytes=_int_or_none(_first(params, "max_bytes"), config.max_bytes),
        conditional_rdap=_bool_or_default(_first(params, "conditional"), True),
        rdap_revalidation_ttl=_float_or_default(
            _first(params, "rdap_revalidation_ttl"), 7 * 24 * 60 * 60
        ),
        # Off by default here too: a gateway is somebody else's quota, and it
        # should not be possible to point it at reserved names to no purpose.
        skip_reserved=not _is_true(_first(params, "query_reserved")),
    )
    if _is_true(_first(params, "records")):
        return {
            "resource": result.resource,
            "kind": result.kind,
            "sources": result.sources,
            "ok": result.ok,
            # Without this the compact shape says "not ok, no errors", which reads
            # as a request that never happened rather than a name that cannot exist.
            "unqueryable": result.unqueryable,
            "errors": [
                {"source": e.source, "message": e.message} for e in result.errors
            ],
            "provenance": result.provenance(),
            "records": [record.as_dict() for record in result.records],
        }
    return result.as_dict()


def _whois_payload(
    resource: str,
    params: dict[str, list[str]],
    config: GatewayConfig,
    cache: Cache | None,
    limiter: RateLimiterRegistry | None,
) -> dict[str, Any]:
    if not resource:
        raise ValueError("resource is required")
    follow = _bool_or_default(_first(params, "follow_referrals"), True)
    result = lookup_whois(
        resource,
        server=_first(params, "whois_server")
        or _first(params, "whois-server")
        or _first(params, "server"),
        port=_int_or_none(
            _first(params, "whois_port")
            or _first(params, "whois-port")
            or _first(params, "port"),
            43,
        ),
        timeout=_float_or_default(_first(params, "timeout"), config.timeout),
        query=_first(params, "query"),
        limiter=limiter,
        retries=_int_or_none(_first(params, "retries"), config.retries) or 0,
        backoff=Backoff(base_delay=config.backoff_delay, jitter=config.jitter),
        cache=cache,
        cache_ttl=_float_or_default(_first(params, "cache_ttl"), config.cache_ttl),
        force_refresh=_is_true(_first(params, "force_refresh")),
        follow_referrals=follow,
        max_bytes=_int_or_none(_first(params, "max_bytes"), config.max_bytes),
    )
    payload = result.as_dict()
    payload["normalized"] = result.normalized().as_dict() if result.fields else {}
    return payload


def _rdap_payload(
    resource: str,
    params: dict[str, list[str]],
    config: GatewayConfig,
    cache: Cache | None,
    limiter: RateLimiterRegistry | None,
) -> dict[str, Any]:
    if not resource:
        raise ValueError("resource is required")
    result = lookup_rdap(
        resource,
        base_url=_first(params, "rdap_base_url") or _first(params, "rdap-base-url"),
        cache_dir=str(config.cache_dir) if config.cache_dir else None,
        timeout=_float_or_default(_first(params, "timeout"), config.timeout),
        limiter=limiter,
        retries=_int_or_none(_first(params, "retries"), config.retries) or 0,
        backoff=Backoff(base_delay=config.backoff_delay, jitter=config.jitter),
        cache=cache,
        cache_ttl=_float_or_default(_first(params, "cache_ttl"), config.cache_ttl),
        force_refresh=_is_true(_first(params, "force_refresh")),
        max_bytes=_int_or_none(_first(params, "max_bytes"), config.max_bytes),
        conditional_revalidate=_bool_or_default(_first(params, "conditional"), True),
        revalidation_ttl=_float_or_default(
            _first(params, "rdap_revalidation_ttl"), 7 * 24 * 60 * 60
        ),
        field_set=_first(params, "field_set") or _first(params, "field-set"),
    )
    payload = result.as_dict()
    payload["normalized"] = (
        normalize_rdap(
            result.data,
            headers=result.headers,
            url=result.url,
            status=result.status,
        ).as_dict()
        if result.data
        else {}
    )
    details = result.error_details()
    if details is not None:
        # RFC 9083 section 6 error body, so a client does not have to parse
        # "data" itself to learn why a query was a negative answer.
        payload["rdap_error"] = details
    return payload


def _rwhois_payload(
    params: dict[str, list[str]],
    config: GatewayConfig,
    cache: Cache | None,
    limiter: RateLimiterRegistry | None,
    breaker: CircuitBreakerRegistry | None = None,
) -> dict[str, Any]:
    resource = _first(params, "resource") or _first(params, "q") or ""
    if not resource:
        raise ValueError("resource is required")
    result = lookup(
        resource,
        sources=["rwhois"],
        timeout=_float_or_default(_first(params, "timeout"), config.timeout),
        server=_first(params, "rwhois_server")
        or _first(params, "rwhois-server")
        or _first(params, "server"),
        port=_int_or_none(
            _first(params, "rwhois_port")
            or _first(params, "rwhois-port")
            or _first(params, "port")
        ),
        rwhois_class=_first(params, "class") or _first(params, "cls"),
        limiter=limiter,
        breaker=breaker,
        retries=_int_or_none(_first(params, "retries"), config.retries) or 0,
        backoff=Backoff(base_delay=config.backoff_delay, jitter=config.jitter),
        cache=cache,
        cache_ttl=_float_or_default(_first(params, "cache_ttl"), config.cache_ttl),
        max_bytes=_int_or_none(_first(params, "max_bytes"), config.max_bytes),
    )
    rwhois_result = result.results.get("rwhois")
    payload = result.as_dict()
    payload["rwhois"] = {
        "ok": getattr(rwhois_result, "ok", result.ok),
        "error_code": getattr(rwhois_result, "error_code", None),
        "error_text": getattr(rwhois_result, "error_text", None),
        "referrals": [r.url for r in getattr(rwhois_result, "referrals", [])],
    }
    return payload


def _request_authenticated(headers: Any, api_key: str | None) -> bool:
    if not api_key:
        return True
    supplied = headers.get("X-API-Key")
    if not supplied:
        authorization = headers.get("Authorization", "")
        if authorization.lower().startswith("bearer "):
            supplied = authorization[7:]
    if not supplied:
        return False
    return hmac.compare_digest(str(supplied).strip(), str(api_key).strip())


def make_handler(
    config: GatewayConfig,
    cache: Cache | None,
    limiter: RateLimiterRegistry | None,
    breaker: CircuitBreakerRegistry | None = None,
    metrics: MetricsRegistry | None = None,
):
    class GatewayRequestHandler(BaseHTTPRequestHandler):
        server_version = "registrata"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            log_event(logger, logging.DEBUG, "gateway_http_log", line=format % args)

        def _send_json(
            self, status: int, payload: dict[str, Any], *, path: str | None = None
        ) -> None:
            data = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            if metrics is not None:
                metrics.add(
                    "gateway_response_total",
                    1,
                    {"path": path or "/", "status": str(status)},
                )

        def _params(self) -> dict[str, list[str]]:
            return parse_qs(urlparse(self.path).query, keep_blank_values=True)

        def _acquire_rate_limit(self) -> bool:
            if limiter is None:
                return True
            key = f"ip:{self.client_address[0]}"
            return limiter.bucket(key).try_acquire(1)

        def _track(self, path: str, started: float, status: int) -> None:
            if metrics is None:
                return
            metrics.add("gateway_request_total", 1, {"path": path})
            metrics.add(
                "gateway_status_total", 1, {"path": path, "status": str(status)}
            )
            metrics.observe(
                "gateway_request_duration_ms",
                max(0.0, (time.perf_counter() - started) * 1000.0),
                {"path": path},
            )
            if status >= 400:
                metrics.add("gateway_error_total", 1, {"path": path})

        def do_GET(self) -> None:
            started = time.perf_counter()
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            params = self._params()
            resource = _first(params, "resource") or _first(params, "q") or ""

            def finish(status: int, payload: dict[str, Any]) -> None:
                self._send_json(status, payload, path=path)
                self._track(path, started, status)

            try:
                require(ExperimentalFeature.GATEWAY)
            except Exception as exc:
                finish(403, {"error": str(exc)})
                return

            if not self._acquire_rate_limit():
                if metrics is not None:
                    metrics.add("gateway_rate_limited_total", 1, {"path": path})
                finish(429, {"error": "rate limit exceeded"})
                return

            if path in {"/", "/health"}:
                payload = {
                    "status": "ok",
                    "service": "registrata-gateway",
                    "tls": config.tls_enabled,
                }
                if breaker is not None:
                    payload["circuit_breakers"] = breaker.snapshot()
                if metrics is not None:
                    payload["metrics"] = metrics.snapshot()
                finish(200, payload)
                return

            if not _request_authenticated(self.headers, config.api_key):
                if metrics is not None:
                    metrics.add("gateway_unauthorized_total", 1, {"path": path})
                finish(401, {"error": "unauthorized"})
                return

            if path == "/metrics":
                payload = (
                    metrics.snapshot()
                    if metrics is not None
                    else {"metrics_enabled": False}
                )
                if breaker is not None:
                    payload["circuit_breakers"] = breaker.snapshot()
                finish(200, payload)
                return

            log_event(
                logger,
                logging.INFO,
                "gateway_request",
                path=path,
                resource=resource,
                client=self.client_address[0],
            )

            try:
                if path == "/lookup":
                    finish(
                        200,
                        _lookup_payload(
                            resource, params, config, cache, limiter, breaker
                        ),
                    )
                    return
                if path in {"/domain", "/ip", "/asn"}:
                    default_sources = {
                        "domain": config.lookup_sources,
                        "ip": "rdap",
                        "asn": "rdap",
                    }[path.strip("/")]
                    params = {
                        **params,
                        "sources": params.get("sources", [default_sources]),
                    }
                    finish(
                        200,
                        _lookup_payload(
                            resource, params, config, cache, limiter, breaker
                        ),
                    )
                    return
                if path == "/whois":
                    finish(
                        200, _whois_payload(resource, params, config, cache, limiter)
                    )
                    return
                if path == "/rdap":
                    payload = _rdap_payload(resource, params, config, cache, limiter)
                    # Mirror the RDAP server's answer rather than masking it. A
                    # negative answer carries an RFC 9083 section 6 error body, and
                    # an HTTP client should be able to see it in the status line it
                    # already handles instead of parsing the payload.
                    upstream = payload.get("status")
                    status = (
                        upstream
                        if isinstance(upstream, int) and 400 <= upstream <= 599
                        else 200
                    )
                    finish(status, payload)
                    return
                if path == "/rwhois":
                    finish(
                        200, _rwhois_payload(params, config, cache, limiter, breaker)
                    )
                    return
                finish(404, {"error": "not found"})
            except ValueError as exc:
                finish(400, {"error": str(exc)})
            except RwhoisError as exc:
                finish(502, {"error": str(exc)})
            except OSError as exc:
                finish(502, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                log_event(
                    logger,
                    logging.WARNING,
                    "gateway_error",
                    path=path,
                    resource=resource,
                    error=str(exc),
                )
                finish(500, {"error": "internal gateway error"})

    return GatewayRequestHandler


class GatewayServer:
    """Start a threaded local HTTP gateway."""

    def __init__(self, config: GatewayConfig | None = None):
        require(ExperimentalFeature.GATEWAY)
        self.config = config or GatewayConfig()
        self.config.validate()
        self.cache: Cache | None = None
        if self.config.cache_ttl:
            backend = self.config.cache_backend or (
                "file" if self.config.cache_dir else "memory"
            )
            self.cache = make_cache(
                backend,
                path=self.config.cache_dir,
                default_ttl=self.config.cache_ttl,
                namespace="gateway-responses",
                max_size=max(1, self.config.cache_size),
            )
        self.limiter: RateLimiterRegistry | None = None
        if self.config.rate_limit:
            self.limiter = RateLimiterRegistry(
                default_rate_per_second=self.config.rate_limit,
                default_capacity=max(1, self.config.burst),
            )
        self.breaker: CircuitBreakerRegistry | None = self.config.breaker
        if self.breaker is None and self.config.circuit_failure_threshold > 0:
            self.breaker = CircuitBreakerRegistry(
                default_failure_threshold=self.config.circuit_failure_threshold,
                default_recovery_timeout=self.config.circuit_recovery_timeout,
                default_success_threshold=max(1, self.config.circuit_success_threshold),
            )
        self.metrics: MetricsRegistry | None = (
            MetricsRegistry() if self.config.metrics_enabled else None
        )
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int] | None:
        if self._httpd is None:
            return None
        host, port = self._httpd.server_address[0], self._httpd.server_address[1]
        return host, port

    def start(self) -> tuple[str, int]:
        handler = make_handler(
            self.config, self.cache, self.limiter, self.breaker, self.metrics
        )
        self._httpd = ThreadingHTTPServer((self.config.bind, self.config.port), handler)
        self._httpd.daemon_threads = True
        if self.config.tls_enabled:
            self._httpd.socket = self.config.build_ssl_context().wrap_socket(
                self._httpd.socket, server_side=True
            )
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        host, port = self.address or (self.config.bind, self.config.port)
        log_event(
            logger,
            logging.INFO,
            "gateway_started",
            host=host,
            port=port,
            tls=self.config.tls_enabled,
        )
        return host, port

    def shutdown(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


def serve(*args: Any, **kwargs: Any) -> None:
    require(ExperimentalFeature.GATEWAY)
    config = kwargs.pop("config", None)
    if isinstance(config, dict):
        config = GatewayConfig(**config)
    if config is None:
        bind = kwargs.pop("bind", "127.0.0.1")
        port = kwargs.pop("port", 8080)
        config = GatewayConfig(bind=bind, port=port, **kwargs)
    server = GatewayServer(config)
    host, port = server.start()
    print(f"gateway listening on {config.scheme}://{host}:{port}", flush=True)
    try:
        threading.Event().wait(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


__all__ = ["GatewayConfig", "GatewayServer", "make_handler", "serve"]
