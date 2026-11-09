"""Experimental classic WHOIS RFC 3912 client helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import logging
import re
import socket
import time
from typing import Any
from urllib.parse import urlparse

from .._flags import ExperimentalFeature, require
from ..cache import Cache, make_key
from ..model import RegistrationRecord
from ..observability import log_event
from ..ratelimit import RateLimiterRegistry
from ..retry import Backoff

logger = logging.getLogger(__name__)

WHOIS_PORT = 43
DEFAULT_DOMAIN_SERVER = "whois.iana.org"
DEFAULT_MAX_RESPONSE_BYTES = 4_194_304  # 4 MiB text response cap

_KEY_VALUE_RE = re.compile(r"^\s*(?P<key>[^:]{1,80})\s*:\s*(?P<value>.*?)\s*$")
# WHOIS has no comment syntax, yet registries prefix banner and commentary lines with a marker, and
# prose that names a URL gets split on the colon *inside* the URL. Live Verisign output turns
# "For more information on Whois status codes, please visit https://icann.org/epp" into a field
# called "for more information on whois status codes, please visit https" holding "//icann.org/epp";
# live PIR and IANA output do the same. Those lines are commentary, not registration data, and the
# full text stays available in `raw` either way.
_WHOIS_COMMENT_PREFIXES = ("%", "#", ">", "!")
_WHOIS_URI_TAIL_RE = re.compile(r"(?:https?|ftps?|mailto|ldap[s]?|telnet|file)$", re.IGNORECASE)
_ASN_RE = re.compile(r"^(?:AS|ASN|autnum)?[-:\s]?(?P<asn>\d+)$", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


@dataclass
class WhoisResult:
    query: str
    server: str
    port: int = WHOIS_PORT
    raw: str = ""
    fields: dict[str, list[str]] = field(default_factory=dict)
    referrals: list[str] = field(default_factory=list)
    #: Every server asked, in the order it was asked, ending with ``server``. A referral chain
    #: can end somewhere that answers about a different object than was queried -- live Verisign
    #: data for example.com names whois.iana.org as the registrar service, and IANA answers about
    #: the TLD -- so the report has to show the route or the last hop looks like a wrong record.
    hops: list[str] = field(default_factory=list)
    encoding: str = "utf-8"
    elapsed: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "server": self.server,
            "port": self.port,
            "raw": self.raw,
            "fields": self.fields,
            "referrals": self.referrals,
            "hops": list(self.hops),
            "encoding": self.encoding,
            "elapsed": self.elapsed,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "WhoisResult":
        return cls(
            query=str(value.get("query", "")),
            server=str(value.get("server", "")),
            port=int(value.get("port") or WHOIS_PORT),
            raw=str(value.get("raw", "")),
            fields=value.get("fields") or {},
            referrals=value.get("referrals") or [],
            hops=[str(item) for item in (value.get("hops") or [])],
            encoding=str(value.get("encoding", "utf-8")),
            elapsed=float(value.get("elapsed") or 0.0),
            error=value.get("error"),
        )

    def get(self, key: str) -> str | None:
        values = self.fields.get(key.strip().lower().replace("_", " "))
        return values[0] if values else None

    def getall(self, key: str) -> list[str]:
        return list(self.fields.get(key.strip().lower().replace("_", " "), []))

    def normalized(self) -> RegistrationRecord:
        from .whois_adapters import normalize_whois_fields

        return normalize_whois_fields(
            self.fields,
            resource=self.query,
            kind=classify_resource(self.query),
            server=self.server,
        )

    @property
    def record(self) -> RegistrationRecord:
        return self.normalized()


def classify_resource(value: str) -> str:
    value = value.strip()
    if not value:
        return "keyword"

    match = _ASN_RE.match(value)
    if match:
        return "autnum"

    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return "cidr"
        except ValueError:
            pass
    else:
        try:
            ip_address = ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            return "ipv4" if ip_address.version == 4 else "ipv6"

    if _DOMAIN_RE.match(value) or value.endswith("."):
        return "domain"
    return "keyword"


def decode_whois_bytes(data: bytes) -> tuple[str, str]:
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace"), "latin-1(replace)"


def parse_whois_fields(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.lstrip().startswith(_WHOIS_COMMENT_PREFIXES):
            continue
        match = _KEY_VALUE_RE.match(line)
        if not match:
            continue
        key = match.group("key").strip().lower()
        value = match.group("value").strip()
        if not key or not value:
            continue
        if _WHOIS_URI_TAIL_RE.search(key) or value.startswith("//"):
            continue  # that colon belonged to a URL scheme, not to a field separator
        fields.setdefault(key, []).append(value)
    return fields


def parse_whois_referrals(text: str) -> list[str]:
    referrals: list[str] = []
    seen: set[str] = set()
    fields = parse_whois_fields(text)
    keys = (
        "registrar whois server",
        "whois",
        "referral server",
        "whois server",
        "refer",
    )
    for key in keys:
        for value in fields.get(key, []):
            host = value.strip().rstrip("/")
            if host and host not in seen:
                referrals.append(host)
                seen.add(host)
    return referrals


def _clean_whois_server(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().rstrip("/")
    if not text:
        return None
    parsed = urlparse(text)
    host = parsed.hostname if parsed.scheme else text
    if not host:
        return None
    host = host.lower()
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    return host or None


def discover_next_whois_server(
    result: WhoisResult, *, current_server: str | None = None
) -> str | None:
    current = (current_server or result.server or "").lower()
    lowered = {k.lower().strip(): v for k, v in result.fields.items()}
    for key in ("refer", "referral server", "whois server", "whois-server", "whois"):
        for value in lowered.get(key, []):
            host = _clean_whois_server(value)
            if host and host != current:
                return host
    for value in result.referrals:
        host = _clean_whois_server(value)
        if host and host != current:
            return host
    return None


def result_from_response(
    query: str,
    server: str,
    data: bytes,
    *,
    port: int = WHOIS_PORT,
    elapsed: float = 0.0,
) -> WhoisResult:
    text, encoding = decode_whois_bytes(data)
    return WhoisResult(
        query=query,
        server=server,
        port=port,
        raw=text,
        fields=parse_whois_fields(text),
        referrals=parse_whois_referrals(text),
        encoding=encoding,
        elapsed=elapsed,
    )


def whois_query(
    query: str,
    server: str,
    *,
    port: int = WHOIS_PORT,
    timeout: float = 10.0,
    limiter: RateLimiterRegistry | None = None,
    retries: int = 0,
    backoff: Backoff | None = None,
    max_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
) -> WhoisResult:
    require(ExperimentalFeature.WHOIS)
    if not query or not server:
        raise ValueError("query and server are required")
    if "\r" in query or "\n" in query:
        raise ValueError("WHOIS query must not contain CR or LF")

    if limiter is not None:
        key = f"{server}:{port}"
        available = limiter.bucket(key).available()
        if available < 1:
            log_event(
                logger,
                logging.DEBUG,
                "whois_rate_limit_wait",
                server=server,
                port=port,
                key=key,
                available=available,
            )
        limiter.acquire(key, timeout=timeout)

    plan = backoff or Backoff()
    log_event(
        logger,
        logging.DEBUG,
        "whois_query",
        query=query,
        server=server,
        port=port,
        retries=retries,
    )
    started = time.monotonic()
    last_error: str | None = None
    for attempt in range(retries + 1):
        started = time.monotonic()
        try:
            with socket.create_connection((server, int(port)), timeout=timeout) as sock:
                sock.sendall(query.encode("utf-8") + b"\r\n")
                chunks: list[bytes] = []
                received = 0
                # ``timeout`` reaches create_connection, so it bounds each syscall, not the read:
                # a server that sends a byte every few hundred milliseconds resets it forever and
                # the lookup never returns. This is the per-attempt total, counted from the
                # connect above so retries each get a fresh budget as before. A None timeout means
                # the caller asked to block indefinitely, so there is nothing to count down.
                #
                # The deadline is checked rather than pushed into sock.settimeout(): the bound
                # that gives is the deadline plus whatever one syscall can block for, which is the
                # per-syscall timeout already set, and it leaves the caller's socket untouched
                # instead of leaving it holding the last fractional value.
                read_deadline = None if timeout is None else started + float(timeout)
                while True:
                    if read_deadline is not None and time.monotonic() >= read_deadline:
                        # Raised rather than returned so a dribbling server takes the same path a
                        # silent one does -- TimeoutError is an OSError, so the retry plan below
                        # decides whether to try again -- instead of this one read outcome
                        # bypassing backoff.
                        raise TimeoutError(f"WHOIS read exceeded {timeout}s in total")
                    read_size = (
                        65536
                        if max_bytes is None
                        else min(65536, int(max_bytes) + 1 - received)
                    )
                    if read_size <= 0:
                        return WhoisResult(
                            query=query,
                            server=server,
                            port=int(port),
                            elapsed=time.monotonic() - started,
                            error="WHOIS response exceeds maximum size",
                        )
                    chunk = sock.recv(read_size)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    received += len(chunk)
                    if max_bytes is not None and received > int(max_bytes):
                        return WhoisResult(
                            query=query,
                            server=server,
                            port=int(port),
                            elapsed=time.monotonic() - started,
                            error="WHOIS response exceeds maximum size",
                        )
        except OSError as exc:
            last_error = str(exc)
            if attempt < retries:
                delay = plan.delay(attempt)
                log_event(
                    logger,
                    logging.INFO,
                    "whois_retry",
                    query=query,
                    server=server,
                    port=port,
                    attempt=attempt + 1,
                    error=last_error,
                    delay=delay,
                )
                time.sleep(delay)
                continue
            return WhoisResult(
                query=query,
                server=server,
                port=int(port),
                elapsed=time.monotonic() - started,
                error=last_error,
            )

        elapsed = time.monotonic() - started
        return result_from_response(
            query, server, b"".join(chunks), port=int(port), elapsed=elapsed
        )

    return WhoisResult(
        query=query,
        server=server,
        port=int(port),
        elapsed=time.monotonic() - started,
        error=last_error or "retry loop exhausted",
    )


def lookup_whois(
    resource: str,
    *,
    server: str | None = None,
    port: int = WHOIS_PORT,
    timeout: float = 10.0,
    query: str | None = None,
    limiter: RateLimiterRegistry | None = None,
    retries: int = 0,
    backoff: Backoff | None = None,
    cache: Cache | None = None,
    cache_ttl: float = 3600.0,
    force_refresh: bool = False,
    follow_referrals: bool = False,
    max_hops: int = 3,
    max_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
) -> WhoisResult:
    kind = classify_resource(resource)
    if server is None:
        if kind in {"domain", "keyword"}:
            server = DEFAULT_DOMAIN_SERVER
        else:
            raise ValueError("server is required for non-domain WHOIS lookup")

    text_query = query or resource
    visited = {server.lower()}
    chain = [server]
    result: WhoisResult | None = None

    def settled(answer: WhoisResult) -> WhoisResult:
        """Attach the route taken, so a referral chain can be read off the result."""
        answer.hops = list(chain)
        return answer

    for hop in range(max(0, int(max_hops)) + 1):
        cache_key = make_key("whois", text_query, server, port)
        cached = None
        if cache is not None and not force_refresh:
            cached = cache.get(cache_key)
        if cached is not None:
            log_event(
                logger,
                logging.DEBUG,
                "whois_cache_hit",
                server=server,
                port=port,
                query=text_query,
            )
            result = WhoisResult.from_dict(cached)
        else:
            if cache is not None:
                log_event(
                    logger,
                    logging.DEBUG,
                    "whois_cache_miss",
                    server=server,
                    port=port,
                    query=text_query,
                )
            result = whois_query(
                text_query,
                server,
                port=port,
                timeout=timeout,
                limiter=limiter,
                retries=retries,
                backoff=backoff,
                max_bytes=max_bytes,
            )
            if cache is not None and result.ok:
                cache.set(cache_key, result.as_dict(), ttl=cache_ttl)
                log_event(
                    logger,
                    logging.DEBUG,
                    "whois_cache_store",
                    server=server,
                    port=port,
                    ttl=cache_ttl,
                )

        if not follow_referrals or result.error is not None:
            return settled(result)

        next_server = discover_next_whois_server(result, current_server=server)
        if not next_server or next_server in visited:
            return settled(result)

        log_event(
            logger,
            logging.INFO,
            "whois_referral_follow",
            query=text_query,
            current_server=server,
            next_server=next_server,
            hop=hop + 1,
        )
        visited.add(next_server)
        chain.append(next_server)
        server = next_server

    assert result is not None
    return settled(result)


__all__ = [
    "WhoisResult",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_DOMAIN_SERVER",
    "classify_resource",
    "decode_whois_bytes",
    "discover_next_whois_server",
    "lookup_whois",
    "parse_whois_fields",
    "parse_whois_referrals",
    "result_from_response",
    "whois_query",
]
