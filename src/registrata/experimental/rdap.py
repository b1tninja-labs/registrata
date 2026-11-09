"""Experimental RDAP bootstrap and JSON helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import logging
import os
import pathlib
import threading
import time
from typing import Any, Callable
from urllib import request, error
from urllib.parse import quote, urlparse

from .._flags import ExperimentalFeature, require
from ..cache import Cache, make_key
from ..model import (
    RegistrationRecord,
    _as_str_list,
    _clean,
    _flag_self_duplicate_links,
    _normalize_rdap_link,
    from_rdap as _from_rdap,
)
from ..observability import log_event
from ..ratelimit import RateLimiterRegistry
from ..retry import Backoff, should_retry_http_status

logger = logging.getLogger(__name__)

BOOTSTRAP_URLS: dict[str, str] = {
    "domain": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
    "autnum": "https://data.iana.org/rdap/as-numbers.json",
}

Opener = Callable[..., Any]
DEFAULT_MAX_RESPONSE_BYTES = 4_194_304  # 4 MiB JSON response cap


class _ResponseTooLarge(Exception):
    def __init__(self, status: int | None, headers: dict[str, str]):
        super().__init__("RDAP response exceeds maximum size")
        self.status = status
        self.headers = headers


def _collect_headers(items: Any) -> dict[str, str]:
    """Collapse response headers into one dict, joining repeated fields.

    RFC 9110 section 5.2 allows a repeated field to be presented as a
    comma-separated list, which is exactly what RDAP clients expect for ``Link``
    (RFC 8288 section 3); a dict comprehension would silently keep only the last
    duplicate and drop the rest. The first-seen spelling of the field name wins.
    """
    if items is None:
        return {}
    pairs = items.items() if hasattr(items, "items") else items
    names: dict[str, str] = {}
    values: dict[str, str] = {}
    for key, value in pairs:
        if value is None:
            continue
        name = str(key)
        fold = name.lower()
        if fold not in names:
            names[fold] = name
            values[fold] = str(value)
            continue
        existing = values[fold]
        text = str(value)
        values[fold] = f"{existing}, {text}" if existing else text
    return {names[fold]: values[fold] for fold in names}


def _read_capped(stream: Any, max_bytes: int | None) -> bytes:
    """Read a response body, refusing one that outruns ``max_bytes``.

    The ceiling is on bytes, not on time, and it cannot be made one here: this is a single
    blocking ``read``, so against a server that dribbles bytes it waits as long as the server
    takes, and the ``timeout`` handed to the opener bounds each syscall underneath it rather
    than the read as a whole. Interrupting it would mean reaching through ``resp.fp`` to the
    socket -- private internals, and invisible to the fake openers callers inject. The two raw
    socket transports do carry an elapsed bound (``wire.LineReader.line_deadline_seconds`` and
    the read deadline in ``experimental.whois``); this one does not, and a caller that needs one
    should pass a shorter ``timeout`` and expect it to apply per syscall.
    """
    if max_bytes is None:
        data = stream.read()
    else:
        try:
            data = stream.read(int(max_bytes) + 1)
        except TypeError:
            data = stream.read()
    if max_bytes is not None and len(data) > int(max_bytes):
        raise _ResponseTooLarge(None, {})
    return data


def _error_body_extensions(
    data: dict[str, Any],
) -> tuple[str | None, list[str], list[Any], list[Any]]:
    """Normalize the optional section 4 members an error body may also carry.

    RFC 9083 section 6 allows an error response to include ``rdapConformance``,
    ``notices`` and ``lang`` just like an answer, so those members are run through
    ``model.from_rdap`` to keep their shape identical to the answer path. A body
    hostile enough to break the normalizer degrades to what can be read directly.
    """
    try:
        record = _from_rdap(data)
        return record.lang, record.conformance, record.notices, record.links
    except Exception as exc:  # pragma: no cover - only reachable on malformed bodies
        log_event(
            logger, logging.DEBUG, "rdap_error_body_unnormalizable", error=str(exc)
        )
    return _clean(data.get("lang")), _as_str_list(data.get("rdapConformance")), [], []


def rdap_error_details(data: Any) -> dict[str, Any] | None:
    """Read RFC 9083 section 6 error response members out of an RDAP body.

    A response that is not an answer may carry a body with a required
    ``errorCode`` (a number corresponding to the HTTP response code), an optional
    ``title`` string and an optional ``description`` array of strings, plus the
    optional ``rdapConformance``/``notices``/``lang`` members of section 4.

    ``None`` means the body carries no section 6 information at all. ``errorCode``
    counts as sent when the member is present even if its type is wrong: the body
    still means itself as an error answer, so the unusable value is kept verbatim
    in ``error_code_raw`` while ``error_code`` stays ``None``.
    """
    if not isinstance(data, dict):
        return None
    if not any(member in data for member in ("errorCode", "title", "description")):
        return None

    raw_code = data.get("errorCode")
    # "errorCode" is specified as a number; bool is an int subclass but never a
    # status code, so it is reported as raw text like any other wrong type.
    error_code = (
        raw_code
        if isinstance(raw_code, int) and not isinstance(raw_code, bool)
        else None
    )
    lang, conformance, notices, links = _error_body_extensions(data)
    return {
        "error_code": error_code,
        "error_code_raw": None
        if error_code is not None or raw_code is None
        else str(raw_code),
        "title": _clean(data.get("title")),
        "description": _as_str_list(data.get("description")),
        "lang": lang,
        "conformance": conformance,
        "notices": notices,
        "links": links,
    }


@dataclass
class RdapResult:
    url: str
    status: int | None = None
    data: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    cache_mode: str | None = None
    stale: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status == 200

    def error_details(self) -> dict[str, Any] | None:
        """RFC 9083 section 6 members carried by this response body, if any.

        The transport layer keeps ``status`` and ``data`` apart, so a 404 answer
        arrives with ``ok`` false and no transport ``error``; the body is the only
        place that says why, which is what this reads.
        """
        return rdap_error_details(self.data)

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "data": self.data,
            "headers": self.headers,
            "error": self.error,
            "cache_mode": self.cache_mode,
            "stale": self.stale,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RdapResult":
        return cls(
            url=str(value.get("url", "")),
            status=value.get("status"),
            data=value.get("data") or {},
            headers=value.get("headers") or {},
            error=value.get("error"),
            cache_mode=value.get("cache_mode"),
            stale=bool(value.get("stale", False)),
        )


NormalizedRecord = RegistrationRecord


def _default_opener(req: request.Request, timeout: float):
    return request.urlopen(req, timeout=timeout)


def http_get_json(
    url: str,
    *,
    timeout: float = 10.0,
    accept: str = "application/rdap+json",
    opener: Opener | None = None,
    limiter: RateLimiterRegistry | None = None,
    limiter_key: str | None = None,
    retries: int = 0,
    backoff: Backoff | None = None,
    retry_statuses: tuple[int, ...] = (429, 500, 502, 503, 504),
    max_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
    extra_headers: dict[str, str] | None = None,
) -> RdapResult:
    use_opener = opener or _default_opener
    if limiter is not None:
        key = limiter_key or urlparse(url).netloc or url
        available = limiter.bucket(key).available()
        if available < 1:
            log_event(
                logger,
                logging.DEBUG,
                "rdap_rate_limit_wait",
                url=url,
                key=key,
                available=available,
            )
        limiter.acquire(key, timeout=timeout)
    headers = {"Accept": accept, "User-Agent": "registrata/0.1"}
    if extra_headers:
        headers.update(
            {str(k): str(v) for k, v in extra_headers.items() if v is not None}
        )
    req = request.Request(url, headers=headers)
    plan = backoff or Backoff()
    last_error: RdapResult | None = None

    log_event(logger, logging.DEBUG, "rdap_http_get", url=url, retries=retries)

    for attempt in range(retries + 1):
        raw = b"{}"
        status = None
        resp_headers: dict[str, str] = {}
        retryable = False
        current_error: RdapResult | None = None
        try:
            with use_opener(req, timeout) as resp:
                resp_headers = _collect_headers(resp.headers)
                status = getattr(resp, "status", None) or resp.getcode()
                raw = _read_capped(resp, max_bytes)
            retryable = should_retry_http_status(status, retry_statuses)
        except _ResponseTooLarge as exc:
            log_event(
                logger,
                logging.INFO,
                "rdap_response_too_large",
                url=url,
                status=exc.status,
                max_bytes=max_bytes,
            )
            return RdapResult(
                url=url, status=exc.status, headers=exc.headers, error=str(exc)
            )
        except error.HTTPError as exc:
            resp_headers = _collect_headers(exc.headers) if exc.headers else {}
            status = exc.code
            try:
                raw = _read_capped(exc, max_bytes)
            except _ResponseTooLarge as too_large:
                too_large.status = status
                too_large.headers = resp_headers
                log_event(
                    logger,
                    logging.INFO,
                    "rdap_response_too_large",
                    url=url,
                    status=status,
                    max_bytes=max_bytes,
                )
                return RdapResult(
                    url=url, status=status, headers=resp_headers, error=str(too_large)
                )
            retryable = should_retry_http_status(status, retry_statuses)
        except OSError as exc:
            current_error = RdapResult(
                url=url, status=status, headers=resp_headers, error=str(exc)
            )
            retryable = True

        if retryable and attempt < retries:
            last_error = current_error or last_error
            delay = plan.delay(attempt)
            log_event(
                logger,
                logging.INFO,
                "rdap_retry",
                url=url,
                attempt=attempt + 1,
                status=status,
                error=last_error.error if last_error is not None else None,
                delay=delay,
            )
            time.sleep(delay)
            continue

        if current_error is not None:
            return current_error

        try:
            if not raw.strip():
                data: Any = {}
            else:
                data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return RdapResult(
                url=url,
                status=status,
                headers=resp_headers,
                error=f"invalid JSON: {exc}",
            )
        return RdapResult(url=url, status=status, data=data, headers=resp_headers)

    return last_error or RdapResult(url=url, error="retry loop exhausted")


def bootstrap_cache_path(cache_dir: str | pathlib.Path, kind: str) -> pathlib.Path:
    return pathlib.Path(cache_dir) / f"rdap_bootstrap_{kind}.json"


def _write_json_atomic(path: pathlib.Path, payload: dict[str, Any]) -> None:
    """Replace a bootstrap cache file in one step.

    ``write_text`` truncates first, so a second writer (or a reader) landing in the
    middle of a dump sees half a JSON document. Writing a private temporary and
    renaming it means readers only ever observe the old file or the complete new one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


_bootstrap_locks: dict[str, threading.Lock] = {}
_bootstrap_locks_guard = threading.Lock()
#: Locks are only an optimisation, so the registry is capped rather than growing
#: with every distinct cache directory a long-lived process is handed.
_MAX_BOOTSTRAP_LOCKS = 128


def _bootstrap_lock(path: pathlib.Path) -> threading.Lock:
    """One lock per bootstrap file, so a cold cache costs one download per process.

    A bulk run wakes several workers at once, and without this each of them fetches
    the whole IANA bootstrap document and then races to overwrite the same file.

    Entries are dropped wholesale once the registry gets large, because a caller
    using a throwaway ``cache_dir`` per request would otherwise pin a lock forever.
    Losing a lock only costs a duplicated fetch: the file itself is replaced
    atomically, so two concurrent writers still cannot corrupt it.
    """
    key = str(path)
    with _bootstrap_locks_guard:
        lock = _bootstrap_locks.get(key)
        if lock is not None:
            return lock
        if len(_bootstrap_locks) >= _MAX_BOOTSTRAP_LOCKS:
            _bootstrap_locks.clear()
        lock = threading.Lock()
        _bootstrap_locks[key] = lock
        return lock


def load_bootstrap(
    kind: str,
    *,
    cache_dir: str | pathlib.Path | None = None,
    url: str | None = None,
    timeout: float = 10.0,
    max_age_seconds: float = 24 * 60 * 60,
    opener: Opener | None = None,
    limiter: RateLimiterRegistry | None = None,
    force_refresh: bool = False,
    retries: int = 0,
    backoff: Backoff | None = None,
    max_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
    conditional_refresh: bool = True,
) -> dict[str, Any]:
    """Return the IANA bootstrap service list for a kind, using a cached copy.

    With a ``cache_dir`` the work happens under a per-file lock, which both
    serialises writers and lets the threads that arrive while a fetch is in progress
    find the fresh file instead of fetching again.
    """
    cache_file = bootstrap_cache_path(cache_dir, kind) if cache_dir else None
    arguments = {
        "url": url,
        "timeout": timeout,
        "max_age_seconds": max_age_seconds,
        "opener": opener,
        "limiter": limiter,
        "force_refresh": force_refresh,
        "retries": retries,
        "backoff": backoff,
        "max_bytes": max_bytes,
        "conditional_refresh": conditional_refresh,
    }
    if cache_file is None:
        return _load_bootstrap(kind, cache_dir=None, **arguments)
    with _bootstrap_lock(cache_file):
        return _load_bootstrap(kind, cache_dir=cache_file.parent, **arguments)


def _load_bootstrap(
    kind: str,
    *,
    cache_dir: str | pathlib.Path | None = None,
    url: str | None = None,
    timeout: float = 10.0,
    max_age_seconds: float = 24 * 60 * 60,
    opener: Opener | None = None,
    limiter: RateLimiterRegistry | None = None,
    force_refresh: bool = False,
    retries: int = 0,
    backoff: Backoff | None = None,
    max_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
    conditional_refresh: bool = True,
) -> dict[str, Any]:
    if kind not in BOOTSTRAP_URLS:
        raise ValueError(f"unknown RDAP bootstrap kind: {kind!r}")
    bootstrap_url = url or BOOTSTRAP_URLS[kind]
    cache_file = bootstrap_cache_path(cache_dir, kind) if cache_dir else None
    cached_payload: dict[str, Any] | None = None
    fresh_cache = False
    if cache_file and cache_file.exists():
        try:
            payload = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                cached_payload = payload
                fresh_cache = (
                    time.time() - float(payload.get("_cached_at") or 0)
                    < max_age_seconds
                )
        except Exception:
            cached_payload = None
            fresh_cache = False

    if cache_file and not force_refresh and fresh_cache:
        return (
            cached_payload.get("services", {"services": []})
            if cached_payload
            else {"services": []}
        )

    conditional_headers: dict[str, str] = {}
    if conditional_refresh and not force_refresh and cached_payload:
        etag = cached_payload.get("_etag")
        last_modified = cached_payload.get("_last_modified")
        if etag:
            conditional_headers["If-None-Match"] = str(etag)
        if last_modified:
            conditional_headers["If-Modified-Since"] = str(last_modified)

    result = http_get_json(
        bootstrap_url,
        accept="application/json",
        timeout=timeout,
        opener=opener,
        limiter=limiter,
        retries=retries,
        backoff=backoff,
        max_bytes=max_bytes,
        extra_headers=conditional_headers,
    )

    if result.status == 304 and cached_payload is not None:
        cached_payload["_cached_at"] = time.time()
        if cache_file:
            _write_json_atomic(cache_file, cached_payload)
        log_event(
            logger,
            logging.DEBUG,
            "rdap_bootstrap_conditional_hit",
            kind=kind,
            url=bootstrap_url,
        )
        return cached_payload.get("services", {"services": []})

    if not result.ok:
        if cached_payload is not None and not force_refresh:
            log_event(
                logger,
                logging.INFO,
                "rdap_bootstrap_stale_cache",
                kind=kind,
                url=bootstrap_url,
                error=result.error,
            )
            return cached_payload.get("services", {"services": []})
        raise RuntimeError(
            result.error or f"RDAP bootstrap fetch failed: {bootstrap_url}"
        )

    services = result.data
    payload: dict[str, Any] = {
        "_cached_at": time.time(),
        "services": services,
    }
    # Headers keep the spelling the server used, so look them up case-insensitively
    # or a bootstrap file would stop revalidating when "ETag" arrives as "Etag".
    etag = _header_value(result.headers, "etag")
    last_modified = _header_value(result.headers, "last-modified")
    if etag:
        payload["_etag"] = etag
    if last_modified:
        payload["_last_modified"] = last_modified
    if cached_payload:
        if etag:
            payload["_etag"] = etag
        if last_modified:
            payload["_last_modified"] = last_modified

    if cache_file:
        _write_json_atomic(cache_file, payload)
    return services


def _longest_domain_match(domain: str, names: list[str]) -> int:
    domain = domain.lower().rstrip(".")
    best = 0
    for name in names:
        label = str(name).lower().rstrip(".")
        if domain == label or domain.endswith("." + label):
            best = max(best, len(label))
    return best


def resolve_domain_base(services: dict[str, Any], domain: str) -> str | None:
    best_len = 0
    best_url: str | None = None
    for entry in services.get("services", []):
        names = entry[0] if len(entry) > 0 else []
        urls = entry[1] if len(entry) > 1 else []
        if not urls:
            continue
        length = _longest_domain_match(domain, names)
        if length > best_len:
            best_len = length
            best_url = urls[0]
    return best_url


def resolve_cidr_base(services: dict[str, Any], cidr: str) -> str | None:
    try:
        target = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    best_len: int | None = None
    best_url: str | None = None
    for entry in services.get("services", []):
        prefixes = entry[0] if len(entry) > 0 else []
        urls = entry[1] if len(entry) > 1 else []
        if not urls:
            continue
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(str(prefix), strict=False)
            except ValueError:
                continue
            if target.version != network.version:
                continue
            if target.subnet_of(network):
                if best_len is None or network.prefixlen > best_len:
                    best_len = network.prefixlen
                    best_url = urls[0]
    return best_url


def resolve_autnum_base(services: dict[str, Any], autnum: int) -> str | None:
    target = int(autnum)
    best_len: int | None = None
    best_url: str | None = None
    for entry in services.get("services", []):
        ranges = entry[0] if len(entry) > 0 else []
        urls = entry[1] if len(entry) > 1 else []
        if not urls:
            continue
        for as_range in ranges:
            try:
                parts = str(as_range).split("-", 1)
                low = int(parts[0])
                high = int(parts[1]) if len(parts) > 1 else low
            except Exception:
                continue
            if low <= target <= high:
                length = high - low
                if best_len is None or length < best_len:
                    best_len = length
                    best_url = urls[0]
    return best_url


def normalize_rdap(
    data: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    url: str | None = None,
    status: int | None = None,
) -> NormalizedRecord:
    """Normalize an RDAP body, optionally together with the HTTP response it arrived in.

    Given only the body this is exactly ``model.from_rdap``. Adding ``url``,
    ``status`` or ``headers`` records the transport context the body cannot speak
    for and merges the ``Link`` header field (RFC 8288 section 3) into the link set:

    * ``context["http"]`` is set only when one of those arguments is given, and
      only carries the keys that are actually present: ``url``, ``status``,
      ``content_type``, ``content_language``, ``notice`` (the raw ``Notice`` header
      kept as opaque transport context - RFC 9083 sections 9 and 10.2.1 signal
      truncation in the body, and no partial-response ``Notice`` value is defined by
      RFC 7480 or RFC 9082), and ``link_header_targets``.
    * Header links are appended with ``scope`` "http:link" and ``value`` set to the
      request URI, then ``model._flag_self_duplicate_links`` runs over body and
      header links in one pass, so a "related" header link that repeats a body
      "self" href is marked and skipped instead of looping (RFC 9083 section 4.2).
    * RFC 7480 section 9.3 asks servers to ignore Accept-Language so clients do not
      confuse it with the body's ``lang``; ``Content-Language`` therefore stays
      advisory context and never overwrites ``record.lang``.
    """
    record = _from_rdap(data)
    if url is None and status is None and headers is None:
        return record

    collected = _collect_headers(headers)
    request_url = _clean(url)
    http: dict[str, Any] = {}
    if request_url is not None:
        http["url"] = request_url
    if status is not None:
        http["status"] = status
    for key, header_name in (
        ("content_type", "content-type"),
        ("content_language", "content-language"),
        ("notice", "notice"),
    ):
        value = _clean(_header_value(collected, header_name))
        if value is not None:
            http[key] = value

    header_links = rdap_header_links(collected, base_url=request_url, lang=record.lang)
    targets = [link["href"] for link in header_links if link.get("href")]
    if targets:
        http["link_header_targets"] = targets
    if header_links:
        # from_rdap() has already flagged the body links among themselves, so this
        # pass is only worth running once header links join the list - it is not a
        # double pass and must not be moved out of the guard.
        record.links = list(record.links) + header_links
        _flag_self_duplicate_links(record.links)

    record.context = {**record.context, "http": http}
    return record


def _header_value(headers: dict[str, str] | None, name: str) -> str | None:
    if not headers:
        return None
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    return lowered.get(name.lower())


def _split_outside_quotes(text: str, sep: str, *, angles: bool = False) -> list[str]:
    """Split on ``sep`` only where it is not inside quotes (and ``<...>``).

    RFC 8288 section 3 puts commas between link-values and semicolons between their
    parameters, but a comma may also appear inside a quoted parameter value or
    inside the angle-bracketed target, so neither may split here.
    """
    parts: list[str] = []
    buffer: list[str] = []
    in_quotes = False
    in_angle = False
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            buffer.append(char)
            continue
        if in_quotes and char == "\\":
            escaped = True
            buffer.append(char)
            continue
        if char == '"':
            in_quotes = not in_quotes
        elif not in_quotes and char == "<" and angles:
            in_angle = True
        elif not in_quotes and char == ">" and angles:
            in_angle = False
        elif char == sep and not in_quotes and not in_angle:
            parts.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)
    parts.append("".join(buffer))
    return parts


def _unquote_param(value: str) -> str:
    """Strip RFC 9110 quoted-string framing, tolerating an unterminated quote."""
    text = value.strip()
    if not text.startswith('"'):
        return text
    out: list[str] = []
    index = 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            out.append(text[index + 1])
            index += 2
            continue
        if char == '"':
            break
        out.append(char)
        index += 1
    return "".join(out)


def parse_link_header(value: str | None) -> list[dict[str, str]]:
    """Parse a ``Link`` header field into one dict per link-value (RFC 8288 §3).

    Each entry carries the angle-bracketed target under ``href`` plus its
    parameters keyed by lower-cased name; ``hreflang`` is kept as the raw
    comma-separated string the field carries, and is split later by
    :func:`rdap_header_links`. Malformed link-values are skipped rather than
    raised on: a server that mangles one link must not hide the others.
    """
    if not isinstance(value, str) or not value.strip():
        return []

    links: list[dict[str, str]] = []
    for entry in _split_outside_quotes(value, ",", angles=True):
        text = entry.strip()
        if not text.startswith("<"):
            continue
        end = text.find(">", 1)
        if end < 0:
            continue
        target = text[1:end]
        # RFC 3986 section 2.4 excludes space and angle brackets from a URI, so a
        # target holding them was cut at the wrong point and is not usable.
        if not target or any(char in target for char in ' \t\r\n<>"'):
            continue
        link: dict[str, str] = {"href": target}
        for parameter in _split_outside_quotes(text[end + 1 :], ";"):
            chunk = parameter.strip()
            if not chunk or "=" not in chunk:
                continue
            name, _, raw = chunk.partition("=")
            parameter_name = name.strip().lower()
            parameter_value = _unquote_param(raw)
            if not parameter_name or not parameter_value:
                continue
            # A parameter name is not allowed to carry two different values in one
            # link-value, so the first one seen is kept.
            link.setdefault(parameter_name, parameter_value)
        links.append(link)
    return links


def rdap_header_links(
    headers: Any,
    *,
    base_url: str | None = None,
    lang: str | None = None,
) -> list[dict[str, Any]]:
    """Normalize the ``Link`` header field of an RDAP response.

    Links arrive from HTTP as well as from the body, so they are given the same
    dict shape through ``model._normalize_rdap_link`` with ``scope`` "http:link".
    ``value`` is the request URI: RFC 8288 section 3 makes a link relative to the
    content it is carried with, and RFC 9083 section 4.2 requires ``value`` to name
    that context. ``headers`` may be a mapping or an iterable of pairs, as produced
    by :func:`http_get_json`.
    """
    collected = _collect_headers(headers)
    parsed = parse_link_header(_header_value(collected, "link"))
    links: list[dict[str, Any]] = []
    for entry in parsed:
        # RFC 8288 registers more parameters than RFC 9083 section 4.2 has members
        # ("anchor", "titles", extension parameters), so the whole entry is carried
        # over and the leftovers are preserved under "extra" by the model helper
        # rather than silently dropped here.
        item: dict[str, Any] = {
            key: value for key, value in entry.items() if key != "href"
        }
        item["value"] = base_url
        item["href"] = entry["href"]
        # "hreflang" stays the raw comma-separated field value, which
        # _normalize_rdap_link() splits into a list of language tags.
        link = _normalize_rdap_link(item, scope="http:link", lang=lang)
        if link is not None:
            links.append(link)
    return links


def _is_transient_rdap_result(result: RdapResult) -> bool:
    if result.error:
        return True
    status = result.status
    return isinstance(status, int) and (status == 429 or status >= 500)


def _store_rdap_cache_entry(
    cache: Cache,
    cache_key: str,
    result: RdapResult,
    *,
    cache_ttl: float,
    revalidation_ttl: float,
) -> None:
    etag = _header_value(result.headers, "etag")
    last_modified = _header_value(result.headers, "last-modified")
    entry = {
        "result": result.as_dict(),
        "etag": etag,
        "last_modified": last_modified,
        "fresh_until": time.time() + float(cache_ttl),
    }
    ttl = max(float(cache_ttl), float(revalidation_ttl))
    cache.set(cache_key, entry, ttl=ttl)


def _cached_rdap_entry(cached: Any) -> tuple[dict[str, Any] | None, RdapResult | None]:
    if not isinstance(cached, dict):
        return None, None
    if isinstance(cached.get("result"), dict):
        entry = cached
        raw = entry["result"]
    else:
        entry = {
            "result": cached,
            "etag": None,
            "last_modified": None,
            "fresh_until": 0.0,
        }
        raw = cached
    try:
        stored = RdapResult.from_dict(raw)
    except Exception:
        return entry, None
    return entry, stored


def _append_field_set(url: str, field_set: str | None) -> str:
    """Append the RFC 8982 section 2 ``fieldSet`` parameter requesting a partial response.

    The parameter name is fixed by the standard and the value is a server-defined
    field-set name, so it is percent-encoded as a single query component.
    """
    name = _clean(field_set)
    if name is None:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}fieldSet={quote(name, safe='')}"


def query_rdap(
    base_url: str,
    path: str,
    *,
    timeout: float = 10.0,
    opener: Opener | None = None,
    limiter: RateLimiterRegistry | None = None,
    retries: int = 0,
    backoff: Backoff | None = None,
    cache: Cache | None = None,
    cache_ttl: float = 3600.0,
    force_refresh: bool = False,
    max_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
    conditional_revalidate: bool = True,
    revalidation_ttl: float = 7 * 24 * 60 * 60,
    field_set: str | None = None,
) -> RdapResult:
    require(ExperimentalFeature.RDAP)
    if not path.startswith("/"):
        path = "/" + path
    url = base_url.rstrip("/") + path
    # RFC 8982 section 2 asks for a field set in the query, and the cache key below
    # is derived from the URL, so a partial response never shadows the full one.
    url = _append_field_set(url, field_set)
    cache_key = make_key("rdap:get", url)
    cached_entry: dict[str, Any] | None = None
    cached_result: RdapResult | None = None

    if cache is not None and not force_refresh:
        cached = cache.get(cache_key)
        cached_entry, cached_result = _cached_rdap_entry(cached)
        if cached_result is not None and cached_entry is not None:
            if time.time() < float(cached_entry.get("fresh_until") or 0):
                log_event(logger, logging.DEBUG, "rdap_cache_hit", url=url)
                cached_result.cache_mode = "hit"
                cached_result.stale = False
                return cached_result
            log_event(logger, logging.DEBUG, "rdap_cache_expired", url=url)
        elif cached is not None:
            log_event(logger, logging.DEBUG, "rdap_cache_hit", url=url)
            result = RdapResult.from_dict(cached)
            result.cache_mode = "hit"
            return result
        else:
            log_event(logger, logging.DEBUG, "rdap_cache_miss", url=url)
    elif force_refresh:
        log_event(logger, logging.DEBUG, "rdap_force_refresh", url=url)

    extra_headers: dict[str, str] = {}
    revalidating = False
    if (
        cache is not None
        and conditional_revalidate
        and cached_result is not None
        and cached_entry is not None
    ):
        etag = cached_entry.get("etag")
        last_modified = cached_entry.get("last_modified")
        if etag:
            extra_headers["If-None-Match"] = str(etag)
        if last_modified:
            extra_headers["If-Modified-Since"] = str(last_modified)
        revalidating = bool(extra_headers)

    result = http_get_json(
        url,
        timeout=timeout,
        opener=opener,
        limiter=limiter,
        retries=retries,
        backoff=backoff,
        max_bytes=max_bytes,
        extra_headers=extra_headers,
    )

    if result.status == 304 and cached_result is not None and cached_entry is not None:
        cached_result.cache_mode = "revalidated"
        cached_result.stale = False
        cached_result.error = None
        cached_entry["fresh_until"] = time.time() + float(cache_ttl)
        cache.set(
            cache_key, cached_entry, ttl=max(float(cache_ttl), float(revalidation_ttl))
        )
        log_event(logger, logging.DEBUG, "rdap_conditional_hit", url=url)
        return cached_result

    if (
        _is_transient_rdap_result(result)
        and cached_result is not None
        and not force_refresh
    ):
        stale = RdapResult.from_dict(cached_result.as_dict())
        stale.cache_mode = "stale"
        stale.stale = True
        log_event(
            logger,
            logging.INFO,
            "rdap_stale_cache",
            url=url,
            error=result.error,
            status=result.status,
        )
        return stale

    if cache is not None and result.ok:
        result.cache_mode = result.cache_mode or "miss"
        _store_rdap_cache_entry(
            cache,
            cache_key,
            result,
            cache_ttl=cache_ttl,
            revalidation_ttl=revalidation_ttl,
        )
        log_event(
            logger,
            logging.DEBUG,
            "rdap_cache_store",
            url=url,
            ttl=cache_ttl,
            revalidation_ttl=revalidation_ttl,
        )
    elif result.error:
        log_event(logger, logging.INFO, "rdap_error", url=url, error=result.error)
    elif revalidating:
        result.cache_mode = "revalidated_fresh"
    else:
        result.cache_mode = result.cache_mode or "miss"
    return result


def lookup_rdap(
    resource: str,
    *,
    base_url: str | None = None,
    cache_dir: str | pathlib.Path | None = None,
    timeout: float = 10.0,
    opener: Opener | None = None,
    limiter: RateLimiterRegistry | None = None,
    retries: int = 0,
    backoff: Backoff | None = None,
    cache: Cache | None = None,
    cache_ttl: float = 3600.0,
    force_refresh: bool = False,
    max_bytes: int | None = DEFAULT_MAX_RESPONSE_BYTES,
    conditional_refresh: bool = True,
    conditional_revalidate: bool = True,
    revalidation_ttl: float = 7 * 24 * 60 * 60,
    field_set: str | None = None,
) -> RdapResult:
    require(ExperimentalFeature.RDAP)
    resource = resource.strip()
    if not resource:
        raise ValueError("resource must not be empty")

    if base_url:
        is_domain = "." in resource and not resource.isdigit()
        path = f"/domain/{resource}" if is_domain else f"/entity/{resource}"
        return query_rdap(
            base_url,
            path,
            timeout=timeout,
            opener=opener,
            limiter=limiter,
            retries=retries,
            backoff=backoff,
            cache=cache,
            cache_ttl=cache_ttl,
            force_refresh=force_refresh,
            max_bytes=max_bytes,
            conditional_revalidate=conditional_revalidate,
            revalidation_ttl=revalidation_ttl,
            field_set=field_set,
        )

    try:
        if "/" in resource:
            kind = "ipv6" if ":" in resource else "ipv4"
            services = load_bootstrap(
                kind,
                cache_dir=cache_dir,
                timeout=timeout,
                opener=opener,
                limiter=limiter,
                retries=retries,
                backoff=backoff,
                max_bytes=max_bytes,
                conditional_refresh=conditional_refresh,
            )
            resolved = resolve_cidr_base(services, resource)
            path = f"/ip/{resource}"
        else:
            lower = resource.lower()
            if lower.startswith("autnum"):
                asn_text = resource[len("autnum") :]
            elif lower.startswith("as"):
                asn_text = resource[len("as") :]
            elif lower.isdigit():
                asn_text = resource
            else:
                asn_text = None

            if asn_text is not None and asn_text.isdigit():
                services = load_bootstrap(
                    "autnum",
                    cache_dir=cache_dir,
                    timeout=timeout,
                    opener=opener,
                    limiter=limiter,
                    retries=retries,
                    backoff=backoff,
                    max_bytes=max_bytes,
                    conditional_refresh=conditional_refresh,
                )
                resolved = resolve_autnum_base(services, int(asn_text))
                path = f"/autnum/{int(asn_text)}"
            else:
                services = load_bootstrap(
                    "domain",
                    cache_dir=cache_dir,
                    timeout=timeout,
                    opener=opener,
                    limiter=limiter,
                    retries=retries,
                    backoff=backoff,
                    max_bytes=max_bytes,
                    conditional_refresh=conditional_refresh,
                )
                resolved = resolve_domain_base(services, resource)
                path = f"/domain/{resource}"
    except (ValueError, RuntimeError) as exc:
        return RdapResult(url="", error=str(exc))

    if resolved is None:
        return RdapResult(
            url="", error=f"no RDAP bootstrap entry found for {resource!r}"
        )
    return query_rdap(
        resolved,
        path,
        timeout=timeout,
        opener=opener,
        limiter=limiter,
        retries=retries,
        backoff=backoff,
        cache=cache,
        cache_ttl=cache_ttl,
        force_refresh=force_refresh,
        max_bytes=max_bytes,
        conditional_revalidate=conditional_revalidate,
        revalidation_ttl=revalidation_ttl,
        field_set=field_set,
    )


__all__ = [
    "BOOTSTRAP_URLS",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "NormalizedRecord",
    "RdapResult",
    "http_get_json",
    "load_bootstrap",
    "lookup_rdap",
    "normalize_rdap",
    "parse_link_header",
    "query_rdap",
    "rdap_error_details",
    "rdap_header_links",
    "resolve_autnum_base",
    "resolve_cidr_base",
    "resolve_domain_base",
]
