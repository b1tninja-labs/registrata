"""Typed exceptions and RFC 2167 Appendix C error codes."""

from __future__ import annotations

import re
from enum import IntEnum

ERROR_LINE_RE = re.compile(r"^%error[ \t]+(?P<code>\d{3})(?:[ \t]+(?P<text>.*))?$")


class ErrorCode(IntEnum):
    """RWhois error codes from RFC 2167 Appendix C."""

    REGISTRATION_DEFERRED = 120
    OBJECT_NOT_AUTHORITATIVE = 130
    NO_OBJECTS_FOUND = 230
    NOT_COMPATIBLE_WITH_VERSION = 300
    INVALID_ATTRIBUTE = 320
    INVALID_ATTRIBUTE_SYNTAX = 321
    REQUIRED_ATTRIBUTE_MISSING = 322
    OBJECT_REFERENCE_NOT_FOUND = 323
    PRIMARY_KEY_NOT_UNIQUE = 324
    FAILED_TO_UPDATE_OUTDATED_OBJECT = 325
    EXCEEDED_MAXIMUM_OBJECTS_LIMIT = 330
    INVALID_LIMIT = 331
    NOTHING_TO_TRANSFER = 332
    NOT_MASTER_FOR_AUTHORITY_AREA = 333
    OBJECT_NOT_FOUND = 336
    INVALID_DIRECTIVE_SYNTAX = 338
    INVALID_AUTHORITY_AREA = 340
    INVALID_CLASS = 341
    INVALID_HOST_PORT = 342
    INVALID_QUERY_SYNTAX = 350
    QUERY_TOO_COMPLEX = 351
    INVALID_SECURITY_METHOD = 352
    AUTHENTICATION_FAILED = 353
    ENCRYPTION_FAILED = 354
    DIRECTIVE_NOT_AVAILABLE = 400
    NOT_AUTHORIZED_FOR_DIRECTIVE = 401
    UNIDENTIFIED_ERROR = 402
    REGISTRATION_NOT_AUTHORIZED = 420
    INVALID_DISPLAY_FORMAT = 436
    MEMORY_ALLOCATION_PROBLEM = 500
    SERVICE_NOT_AVAILABLE = 501
    UNRECOVERABLE_ERROR = 502
    IDLE_TIME_EXCEEDED = 503


ERROR_TEXT: dict[int, str] = {
    ErrorCode.REGISTRATION_DEFERRED: "Registration deferred",
    ErrorCode.OBJECT_NOT_AUTHORITATIVE: "Object not authoritative",
    ErrorCode.NO_OBJECTS_FOUND: "No objects found",
    ErrorCode.NOT_COMPATIBLE_WITH_VERSION: "Not compatible with version",
    ErrorCode.INVALID_ATTRIBUTE: "Invalid attribute",
    ErrorCode.INVALID_ATTRIBUTE_SYNTAX: "Invalid attribute syntax",
    ErrorCode.REQUIRED_ATTRIBUTE_MISSING: "Required attribute missing",
    ErrorCode.OBJECT_REFERENCE_NOT_FOUND: "Object reference not found",
    ErrorCode.PRIMARY_KEY_NOT_UNIQUE: "Primary key not unique",
    ErrorCode.FAILED_TO_UPDATE_OUTDATED_OBJECT: "Failed to update outdated object",
    ErrorCode.EXCEEDED_MAXIMUM_OBJECTS_LIMIT: "Exceeded maximum objects limit",
    ErrorCode.INVALID_LIMIT: "Invalid limit",
    ErrorCode.NOTHING_TO_TRANSFER: "Nothing to transfer",
    ErrorCode.NOT_MASTER_FOR_AUTHORITY_AREA: "Not master for authority area",
    ErrorCode.OBJECT_NOT_FOUND: "Object not found",
    ErrorCode.INVALID_DIRECTIVE_SYNTAX: "Invalid directive syntax",
    ErrorCode.INVALID_AUTHORITY_AREA: "Invalid authority area",
    ErrorCode.INVALID_CLASS: "Invalid class",
    ErrorCode.INVALID_HOST_PORT: "Invalid host/port",
    ErrorCode.INVALID_QUERY_SYNTAX: "Invalid query syntax",
    ErrorCode.QUERY_TOO_COMPLEX: "Query too complex",
    ErrorCode.INVALID_SECURITY_METHOD: "Invalid security method",
    ErrorCode.AUTHENTICATION_FAILED: "Authentication failed",
    ErrorCode.ENCRYPTION_FAILED: "Encryption failed",
    ErrorCode.DIRECTIVE_NOT_AVAILABLE: "Directive not available",
    ErrorCode.NOT_AUTHORIZED_FOR_DIRECTIVE: "Not authorized for directive",
    ErrorCode.UNIDENTIFIED_ERROR: "Unidentified error",
    ErrorCode.REGISTRATION_NOT_AUTHORIZED: "Registration not authorized",
    ErrorCode.INVALID_DISPLAY_FORMAT: "Invalid display format",
    ErrorCode.MEMORY_ALLOCATION_PROBLEM: "Memory allocation problem",
    ErrorCode.SERVICE_NOT_AVAILABLE: "Service not available",
    ErrorCode.UNRECOVERABLE_ERROR: "Unrecoverable error",
    ErrorCode.IDLE_TIME_EXCEEDED: "Idle time exceeded",
}


class RwhoisError(Exception):
    """Base class for protocol errors returned by an RWhois server."""

    code: int | None = None

    def __init__(self, error_text: str | None = None, *, code: int | None = None):
        if code is None:
            code = type(self).code
        self.code = int(code) if code is not None else None
        if error_text is None and self.code is not None:
            error_text = ERROR_TEXT.get(self.code, "Unknown RWhois error")
        self.error_text = error_text or ""
        super().__init__(error_text or "RWhois error")

    def __str__(self) -> str:
        if self.code is None:
            return self.error_text or super().__str__()
        return f"{self.code} {self.error_text}".strip()


class RwhoisProtocolError(RwhoisError):
    """Local protocol violation, not a server `%error` response."""


class RwhoisParseError(ValueError, RwhoisProtocolError):
    """Raised when wire data does not match RFC 2167 enough to parse."""


class RegistrationDeferred(RwhoisError):
    code = ErrorCode.REGISTRATION_DEFERRED


class ObjectNotAuthoritative(RwhoisError):
    code = ErrorCode.OBJECT_NOT_AUTHORITATIVE


class NoObjectsFound(RwhoisError):
    code = ErrorCode.NO_OBJECTS_FOUND


class NotCompatibleWithVersion(RwhoisError):
    code = ErrorCode.NOT_COMPATIBLE_WITH_VERSION


class InvalidAttribute(RwhoisError):
    code = ErrorCode.INVALID_ATTRIBUTE


class InvalidAttributeSyntax(RwhoisError):
    code = ErrorCode.INVALID_ATTRIBUTE_SYNTAX


class RequiredAttributeMissing(RwhoisError):
    code = ErrorCode.REQUIRED_ATTRIBUTE_MISSING


class ObjectReferenceNotFound(RwhoisError):
    code = ErrorCode.OBJECT_REFERENCE_NOT_FOUND


class PrimaryKeyNotUnique(RwhoisError):
    code = ErrorCode.PRIMARY_KEY_NOT_UNIQUE


class FailedToUpdateOutdatedObject(RwhoisError):
    code = ErrorCode.FAILED_TO_UPDATE_OUTDATED_OBJECT


class ExceededMaximumObjectsLimit(RwhoisError):
    code = ErrorCode.EXCEEDED_MAXIMUM_OBJECTS_LIMIT


class InvalidLimit(RwhoisError):
    code = ErrorCode.INVALID_LIMIT


class NothingToTransfer(RwhoisError):
    code = ErrorCode.NOTHING_TO_TRANSFER


class NotMasterForAuthorityArea(RwhoisError):
    code = ErrorCode.NOT_MASTER_FOR_AUTHORITY_AREA


class ObjectNotFound(RwhoisError):
    code = ErrorCode.OBJECT_NOT_FOUND


class InvalidDirectiveSyntax(RwhoisError):
    code = ErrorCode.INVALID_DIRECTIVE_SYNTAX


class InvalidAuthorityArea(RwhoisError):
    code = ErrorCode.INVALID_AUTHORITY_AREA


class InvalidClass(RwhoisError):
    code = ErrorCode.INVALID_CLASS


class InvalidHostPort(RwhoisError):
    code = ErrorCode.INVALID_HOST_PORT


class InvalidQuerySyntax(RwhoisError):
    code = ErrorCode.INVALID_QUERY_SYNTAX


class QueryTooComplex(RwhoisError):
    code = ErrorCode.QUERY_TOO_COMPLEX


class InvalidSecurityMethod(RwhoisError):
    code = ErrorCode.INVALID_SECURITY_METHOD


class AuthenticationFailed(RwhoisError):
    code = ErrorCode.AUTHENTICATION_FAILED


class EncryptionFailed(RwhoisError):
    code = ErrorCode.ENCRYPTION_FAILED


class DirectiveNotAvailable(RwhoisError):
    code = ErrorCode.DIRECTIVE_NOT_AVAILABLE


class NotAuthorizedForDirective(RwhoisError):
    code = ErrorCode.NOT_AUTHORIZED_FOR_DIRECTIVE


class UnidentifiedError(RwhoisError):
    code = ErrorCode.UNIDENTIFIED_ERROR


class RegistrationNotAuthorized(RwhoisError):
    code = ErrorCode.REGISTRATION_NOT_AUTHORIZED


class InvalidDisplayFormat(RwhoisError):
    code = ErrorCode.INVALID_DISPLAY_FORMAT


class MemoryAllocationProblem(RwhoisError):
    code = ErrorCode.MEMORY_ALLOCATION_PROBLEM


class ServiceNotAvailable(RwhoisError):
    code = ErrorCode.SERVICE_NOT_AVAILABLE


class UnrecoverableError(RwhoisError):
    code = ErrorCode.UNRECOVERABLE_ERROR


class IdleTimeExceeded(RwhoisError):
    code = ErrorCode.IDLE_TIME_EXCEEDED


def error_class_for_code(code: int) -> type[RwhoisError]:
    for cls in globals().values():
        if (
            isinstance(cls, type)
            and issubclass(cls, RwhoisError)
            and getattr(cls, "code", None) == int(code)
        ):
            return cls
    return RwhoisError


def error_from_code(code: int, error_text: str | None = None) -> RwhoisError:
    cls = error_class_for_code(code)
    return cls(
        error_text or ERROR_TEXT.get(int(code), "Unknown RWhois error"), code=int(code)
    )


def parse_error_line(line: str) -> tuple[int, str]:
    match = ERROR_LINE_RE.match(line)
    if not match:
        raise RwhoisParseError(f"invalid error response line: {line!r}")
    return int(match.group("code")), match.group("text") or ""


def format_error_line(code: int, error_text: str | None = None) -> str:
    number = int(code)
    if not 0 <= number <= 999:
        raise ValueError(f"error code must fit in three digits: {code!r}")
    text = error_text or ERROR_TEXT.get(number, "Unknown RWhois error")
    # Zero-padded, because error-code is 3DIGIT and a leading zero is legal: Appendix B
    # admits "030", and an unpadded "%error 30 ..." is rejected by parse_error_line's own
    # \d{3}, so emitting one would produce a line no RWhois client can read -- including
    # this library.
    return f"%error {number:03d} {text}"


__all__ = [name for name in globals() if not name.startswith("_")]
