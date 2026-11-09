"""Python client and server toolkit for Referral Whois (RWhois).

This package implements the wire protocol from RFC 2167, including TCP client
sessions, referral following, schema/SOA helpers, and a pluggable server
backend. The available `rfclib` RFC library was used as the specification
source during development.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .banner import Banner, Version, parse_banner, serialize_banner
from .backends import MemoryBackend, RwhoisBackend, SearchResult
from .cache import (
    Cache,
    CacheEntry,
    JsonFileCache,
    SQLiteCache,
    TTLCache,
    cached,
    make_cache,
    make_key,
)
from .capabilities import Capability, decode_capability_id, encode_capability_id
from .client import RwhoisClient
from .circuitbreaker import CircuitBreaker, CircuitBreakerRegistry, CircuitOpen
from .comparison import CompareReport, compare_lookup_result, compare_records
from .diagnostics import doctor_report, rdap_bootstrap_cache_status, trace_report
from .model import (
    RDAP_BASE_CONFORMANCE,
    RDAP_DEFAULT_PATH_LANG,
    RDAP_DEFAULT_REDACTION_METHOD,
    RDAP_REDACTED_CONFORMANCE,
    RDAP_REDACTION_METHODS,
    RDAP_SUBSETTING_CONFORMANCE,
    RDAP_TRUNCATION_TYPES,
    RegistrationRecord,
    from_rdap,
    from_rwhois_object,
    from_whois_fields,
)
from .observability import configure_logging, get_logger, log_event
from ._flags import ExperimentalFeature
from . import experimental
from .ratelimit import RateLimitTimeout, RateLimiterRegistry, TokenBucket
from .record_schema import (
    RECORD_SCHEMA_VERSION,
    REGISTRATION_RECORD_SCHEMA,
    RDAP_LINK_ITEM_SCHEMA,
    RDAP_NOTICE_ITEM_SCHEMA,
    RDAP_REDACTED_ITEM_SCHEMA,
    record_to_schema,
    validate_record,
)
from .retry import Backoff, RetryExhausted, with_retries
from .errors import (
    ErrorCode,
    ExceededMaximumObjectsLimit,
    InvalidDirectiveSyntax,
    InvalidLimit,
    InvalidQuerySyntax,
    NoObjectsFound,
    RwhoisError,
    RwhoisParseError,
    RwhoisProtocolError,
    error_from_code,
    format_error_line,
    parse_error_line,
)
from .protocol import (
    QueryResult,
    ServerResponse,
    parse_directive_response,
    parse_query_result,
    parse_response,
)
from .query import Attribute, Boolean, Query, Unrestricted, parse_query
from .records import AttributeLine, ObjectRecord, Referral, parse_referral_line
from .resolver import ResolutionResult, RwhoisResolver
from .schema import AttributeDefinition, SchemaClass, base_attributes, validate_object
from .server import RwhoisServer
from .soa import SOARecord
from .wire import CRLF, LineReader

get_logger("registrata")

__all__ = [
    "__version__",
    "Attribute",
    "AttributeDefinition",
    "AttributeLine",
    "Banner",
    "Backoff",
    "Boolean",
    "CRLF",
    "Cache",
    "CacheEntry",
    "Capability",
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "CircuitOpen",
    "CompareReport",
    "compare_lookup_result",
    "compare_records",
    "configure_logging",
    "doctor_report",
    "ErrorCode",
    "ExperimentalFeature",
    # Re-exported so `registrata.experimental` resolves after `import registrata`.
    "experimental",
    "ExceededMaximumObjectsLimit",
    "InvalidDirectiveSyntax",
    "InvalidLimit",
    "InvalidQuerySyntax",
    "JsonFileCache",
    "LineReader",
    "MemoryBackend",
    "NoObjectsFound",
    "ObjectRecord",
    "Query",
    "QueryResult",
    "RateLimitTimeout",
    "RateLimiterRegistry",
    "RECORD_SCHEMA_VERSION",
    "REGISTRATION_RECORD_SCHEMA",
    "RDAP_BASE_CONFORMANCE",
    "RDAP_DEFAULT_PATH_LANG",
    "RDAP_DEFAULT_REDACTION_METHOD",
    "RDAP_LINK_ITEM_SCHEMA",
    "RDAP_NOTICE_ITEM_SCHEMA",
    "RDAP_REDACTED_CONFORMANCE",
    "RDAP_REDACTED_ITEM_SCHEMA",
    "RDAP_REDACTION_METHODS",
    "RDAP_SUBSETTING_CONFORMANCE",
    "RDAP_TRUNCATION_TYPES",
    "Referral",
    "RegistrationRecord",
    "RetryExhausted",
    "ResolutionResult",
    "RwhoisBackend",
    "RwhoisClient",
    "RwhoisError",
    "RwhoisParseError",
    "RwhoisProtocolError",
    "RwhoisResolver",
    "RwhoisServer",
    "SearchResult",
    "SchemaClass",
    "ServerResponse",
    "SQLiteCache",
    "SOARecord",
    "TokenBucket",
    "TTLCache",
    "Unrestricted",
    "with_retries",
    "Version",
    "base_attributes",
    "cached",
    "decode_capability_id",
    "encode_capability_id",
    "error_from_code",
    "format_error_line",
    "from_rdap",
    "from_rwhois_object",
    "from_whois_fields",
    "get_logger",
    "log_event",
    "make_cache",
    "make_key",
    "parse_banner",
    "parse_directive_response",
    "parse_error_line",
    "parse_query",
    "parse_query_result",
    "parse_referral_line",
    "parse_response",
    "rdap_bootstrap_cache_status",
    "record_to_schema",
    "serialize_banner",
    "trace_report",
    "validate_object",
    "validate_record",
]
