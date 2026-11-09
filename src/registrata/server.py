"""Threaded TCP RWhois server toolkit."""

from __future__ import annotations

import logging
import re
import socket
import socketserver
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .banner import Version
from .capabilities import Capability
from .errors import (
    ErrorCode,
    InvalidAuthorityArea,
    InvalidClass,
    InvalidDirectiveSyntax,
    NotAuthorizedForDirective,
    ObjectReferenceNotFound,
    RegistrationNotAuthorized,
    RequiredAttributeMissing,
    RwhoisError,
    RwhoisParseError,
    RwhoisProtocolError,
    format_error_line,
)
from .observability import get_logger, log_event
from .query import parse_query
from .records import ObjectRecord, validate_id
from .schema import SchemaClass, validate_for_registration
from .soa import SOARecord
from .wire import LineReader, encode_line, validate_wire_text


DIRECTIVE_DESCRIPTIONS = {
    "rwhois": "RWhois version directive",
    "class": "Class meta-information",
    "directive": "Directive meta-information",
    "display": "Display format",
    "forward": "Forward referrals on server",
    "holdconnect": "Hold connection after query",
    "limit": "Set maximum objects returned",
    "notify": "Referral and replication notifications",
    "quit": "Quit connection",
    "register": "Object registration",
    "schema": "Schema meta-information",
    "security": "Security state",
    "soa": "Start of authority information",
    "status": "Connection status",
    "xfer": "Transfer data",
    "X": "Extended directive",
}


_LOG = get_logger("registrata.server")

#: Text values that mean "hide this" for the base class's object-level `Private`
#: attribute. Section 2.3.1 describes the flag as true or false, but the value arrives as
#: free text in an attribute-value pair, so both spellings are accepted. Anything else --
#: including the attribute being absent -- means not private, which is the documented
#: default.
_PRIVATE_TRUE = frozenset({"true", "on", "1", "yes"})


@dataclass
class SessionState:
    limit: int = 20
    # RFC 2167 section 3.3.5: "Normally, the server closes the connection after each query... By
    # default, the holdconnect state must be set to off for each connection." This used to be
    # True, which made multi-query sessions work but contradicted the directive's own section;
    # the client now negotiates `-holdconnect on` at connect time instead (see client.py), so
    # sessions still work without the server silently ignoring the specified default.
    hold_connect: bool = False
    forward: bool = False
    display: str = "dump"
    authenticated: bool = False
    register_mode: str | None = None
    register_maintainer: str | None = None
    register_lines: list[str] = field(default_factory=list)
    security_direction: str | None = None
    security_method: str | None = None
    # The password the session authenticated with, kept so a guardian whose
    # Guard-Scheme is "password" can be checked against it. Section 2.3.6 leaves the
    # form of Guard-Info to the scheme, and a password is the RFC's own example.
    security_credential: str | None = None


class RwhoisServer:
    def __init__(
        self,
        backend: Any,
        host: str = "127.0.0.1",
        port: int = 4321,
        *,
        server_name: str | None = None,
        implementation: str = "registrata 0.1.0",
        default_limit: int = 20,
        contact: str | None = None,
        idle_timeout: float | None = 30.0,
        x_handlers: dict[str, Callable[..., list[str] | None]] | None = None,
        registration_deferred: bool = False,
    ):
        self.backend = backend
        # Section 3.3.9 lists 120 Registration deferred among the answers a server
        # may give to a register directive: keep serving queries, stop accepting
        # writes. A maintenance window that answers 402 or hangs is worse for the
        # client than one that says "come back later" in the protocol's own words.
        self.registration_deferred = registration_deferred
        self.host = host
        self.port = int(port)
        # Validated at construction rather than at the first connection. Both land in the banner,
        # which is sent during setup(), so an unsendable value would otherwise look like a server
        # that accepts a connection and then hangs up. getfqdn() is checked too, since a hostname
        # from a reverse lookup is not operator input anyone reviewed.
        #
        # RwhoisError rather than ValueError is deliberate: the constraint is the wire format's,
        # and validate_wire_text is the only copy of that rule. A second check that raised
        # ValueError would be a second rule to keep in step.
        self.server_name = validate_wire_text(
            server_name or socket.getfqdn(), label="server_name"
        )
        self.implementation = validate_wire_text(implementation, label="implementation")
        self.default_limit = int(default_limit)
        self.contact = contact
        self.idle_timeout = idle_timeout
        self.x_handlers = dict(x_handlers or {})
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self.capabilities = self._derive_capabilities()

    def _derive_capabilities(self) -> Capability:
        caps = (
            Capability.CLASS
            | Capability.DIRECTIVE
            | Capability.DISPLAY
            | Capability.HOLDCONNECT
            | Capability.LIMIT
            | Capability.QUIT
            | Capability.SCHEMA
            | Capability.SOA
            | Capability.STATUS
        )
        if getattr(self.backend, "support_xfer", True):
            caps |= Capability.XFER
        if getattr(self.backend, "support_register", False):
            caps |= Capability.REGISTER
        if getattr(self.backend, "support_security", False):
            caps |= Capability.SECURITY
        if getattr(self.backend, "support_notify", False):
            caps |= Capability.NOTIFY
        if self.x_handlers:
            caps |= Capability.X
        return caps

    def banner_line(self) -> str:
        version = Version("1.5", self.capabilities)
        return f"%rwhois {version} {self.server_name} {self.implementation}".strip()

    def start(self) -> tuple[str, int]:
        self._server = _make_server((self.host, self.port), self)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.host, self.port

    def serve_forever(self) -> None:
        self._server = _make_server((self.host, self.port), self)
        self.port = self._server.server_address[1]
        try:
            self._server.serve_forever()
        finally:
            self._server.server_close()

    def shutdown(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port


def _make_server(
    addr: tuple[str, int], app: RwhoisServer
) -> socketserver.ThreadingTCPServer:
    class AppServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = AppServer(addr, RwhoisRequestHandler)
    server.app = app  # type: ignore[attr-defined]
    server.backend = app.backend  # type: ignore[attr-defined]
    server.default_limit = app.default_limit  # type: ignore[attr-defined]
    server.idle_timeout = app.idle_timeout  # type: ignore[attr-defined]
    server.contact = app.contact  # type: ignore[attr-defined]
    server.x_handlers = app.x_handlers  # type: ignore[attr-defined]
    server.banner_line = app.banner_line  # type: ignore[attr-defined]
    return server


class RwhoisRequestHandler(socketserver.BaseRequestHandler):
    server: Any

    def setup(self) -> None:
        self.state = SessionState(limit=self.server.default_limit)
        self.close_after_response = False
        self.reader = LineReader(self.request)
        if self.server.idle_timeout:
            self.request.settimeout(self.server.idle_timeout)
        self.send_lines([self.server.banner_line()])

    def handle(self) -> None:
        while True:
            if self.close_after_response:
                break
            try:
                line = self.reader.readline()
            except ConnectionError:
                break
            except socket.timeout:
                try:
                    self.send_error(ErrorCode.IDLE_TIME_EXCEEDED)
                except OSError:
                    pass
                break
            if not line:
                continue
            try:
                self.process_command(line)
            except RwhoisProtocolError as exc:
                # One place answers for every send site. A line break can arrive from a backend
                # row, a class description, an extension's return value, or operator
                # configuration, and wrapping each caller individually is how some of them end up
                # reporting properly while others reset. An unannounced reset is the outcome to
                # avoid: it is indistinguishable from a network fault, and the peer never learns
                # that its own data was rejected.
                #
                # A response is several send_lines calls, so a late refusal can follow lines
                # already written. There is no rollback in this protocol; saying so in an error is
                # the honest option, and it beats letting a truncated response look like success.
                try:
                    self.send_error(ErrorCode.UNIDENTIFIED_ERROR, str(exc))
                except (RwhoisProtocolError, OSError):
                    break
            if self.close_after_response:
                break

    def send_lines(self, lines: Iterable[str]) -> None:
        # encode_line is where the framing rule lives: one line in, one CRLF-terminated line
        # out, and a refusal for anything carrying a CR or LF. Going around it turned the rule
        # into something each caller had to remember, and the callers are backends, directive
        # descriptions and operator configuration -- a served value with a line break in it
        # would append lines to the response, and an injected "%ok" ends a client's read
        # early. Encoding the whole batch before writing any of it also means a refusal cannot
        # leave a half-sent response on the socket.
        encoded = [encode_line(line) for line in lines]
        if encoded:
            self.request.sendall(b"".join(encoded))

    def send_ok(self) -> None:
        self.send_lines(["%ok"])

    def send_error(self, code: int, text: str | None = None) -> None:
        # format_error_line rather than an inline f-string: the copy here had the same
        # zero-padding defect that made "%error 30" unparseable, and fixing the library's copy
        # would not have fixed this one. Two renderings of one wire format drift by design.
        self.send_lines([format_error_line(code, text)])

    def process_command(self, line: str) -> None:
        if self.state.register_mode is not None:
            self.collect_register_line(line)
            return
        if line.startswith("-"):
            self.process_directive(line)
        else:
            self.process_query(line)

    def process_query(self, line: str) -> None:
        try:
            self._execute_query(line)
        finally:
            # Arming this in a finally rather than at the end of the body is the whole point: the
            # two error paths inside return early, and each one left the connection open after
            # answering. Section 3.3.5 says the server must close after a query when holdconnect is
            # off, and a malformed query is still a query -- a client that is not holding the
            # session should not have to wait for the idle timeout to find out it was refused.
            if not self.state.hold_connect:
                self.close_after_response = True

    def _execute_query(self, line: str) -> None:
        try:
            query = parse_query(line)
        except Exception as exc:
            self.send_error(ErrorCode.INVALID_QUERY_SYNTAX, str(exc))
            return
        try:
            search = self.server.backend.search(
                query, limit=self.state.limit, session=self.state
            )
        except Exception as exc:
            self.send_error(ErrorCode.UNIDENTIFIED_ERROR, str(exc))
            return

        # Section 2.3.1's `Private` flag is applied here, at the one place records leave the
        # server, rather than inside the backend: what a caller may see depends on the
        # session, and the backend has no session to ask.
        visible = [
            record
            for record in (self._viewable(obj) for obj in search.objects)
            if record is not None
        ]
        for record in visible:
            self.send_lines(record.to_wire_lines())
            self.send_lines([""])
        for referral in search.referrals:
            self.send_lines([referral.to_wire()])

        if search.error_code is not None:
            self.send_error(search.error_code, search.error_text)
        elif search.exceeded_limit:
            self.send_error(ErrorCode.EXCEEDED_MAXIMUM_OBJECTS_LIMIT)
        elif not visible and not search.referrals:
            # Decided here, after the search, rather than before it: a zone that holds no data for
            # a class can still be the right place to be referred onward from, and refusing up front
            # swallows the referral -- the very mechanism this protocol exists for. An answer of
            # "nothing at all" is the ambiguous case, and this distinguishes the two kinds: section
            # 4 lists 341 among the errors a query may return, "%error 230" reads as "this resource
            # is not here" while 341 reads as "that class does not exist here", and this library's
            # own client treats the first as an answer and the second as a failed query.
            if query.class_name and not self._class_is_known(query.class_name):
                self.send_error(
                    ErrorCode.INVALID_CLASS, f"unknown class: {query.class_name}"
                )
            else:
                self.send_error(ErrorCode.NO_OBJECTS_FOUND)
        else:
            self.send_ok()

    def _class_is_known(self, class_name: str) -> bool:
        """Whether any authority area this server serves defines ``class_name``.

        Scanned per query rather than cached, because classes can appear while the server is
        running (a registration, a reload) and a stale answer would refuse queries that are
        perfectly good. A deployment with many authority areas would want an invalidation hook
        before turning this into a cache.
        """
        wanted = class_name.lower()
        for area in self.server.backend.list_authority_areas():
            for cls in self.server.backend.get_classes(area):
                if cls.class_name.lower() == wanted:
                    return True
        return False

    def process_directive(self, line: str) -> None:
        if self.state.register_mode is not None:
            self.collect_register_line(line)
            return
        parts = line.split(maxsplit=1)
        name = parts[0].lower()
        rest = parts[1].strip() if len(parts) > 1 else ""
        handler = getattr(self, f"_do_{name[1:].replace('-', '_')}", None)
        if handler is None:
            if name.startswith("-x-"):
                self._do_x(name[3:], rest)
            else:
                self.send_error(
                    ErrorCode.INVALID_DIRECTIVE_SYNTAX, f"unknown directive: {name}"
                )
            return
        handler(rest)

    def _split_args(self, rest: str, maxsplit: int = -1) -> list[str]:
        return rest.split(" ", maxsplit=maxsplit) if rest else []

    def _do_rwhois(self, rest: str) -> None:
        if not rest:
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
            return
        version_token = rest.split(" ", 1)[0]
        if not version_token.lower().startswith("v-1.5"):
            self.send_error(ErrorCode.NOT_COMPATIBLE_WITH_VERSION)
            return
        self.send_lines([self.server.banner_line()])
        self.send_ok()

    def _do_limit(self, rest: str) -> None:
        if not rest or not rest.isdigit():
            self.send_error(ErrorCode.INVALID_LIMIT)
            return
        self.state.limit = int(rest)
        self.send_ok()

    def _do_holdconnect(self, rest: str) -> None:
        if rest not in {"on", "off"}:
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
            return
        self.state.hold_connect = rest == "on"
        self.send_ok()

    def _do_forward(self, rest: str) -> None:
        if rest not in {"on", "off"}:
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
            return
        self.state.forward = rest == "on"
        self.send_ok()

    def _do_quit(self, rest: str) -> None:
        self.send_ok()
        self.close_after_response = True

    def _do_display(self, rest: str) -> None:
        if not rest:
            self.send_lines(["%display name:dump", "%display"])
            self.send_ok()
            return
        if rest != "dump":
            self.send_error(ErrorCode.INVALID_DISPLAY_FORMAT)
            return
        self.state.display = rest
        self.send_ok()

    def _do_status(self, rest: str) -> None:
        try:
            objects = self.server.backend.object_count()
        except Exception:
            objects = 0
        lines = [
            f"%status limit:{self.state.limit}",
            f"%status holdconnect:{'ON' if self.state.hold_connect else 'OFF'}",
            f"%status forward:{'ON' if self.state.forward else 'OFF'}",
            f"%status objects:{objects}",
            f"%status display:{self.state.display}",
        ]
        if self.server.contact:
            lines.append(f"%status contact:{self.server.contact}")
        self.send_lines(lines)
        self.send_ok()

    def _classes_or_error(self, rest: str, kind: str) -> list[SchemaClass] | None:
        parts = self._split_args(rest)
        if not parts:
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
            return None
        area = parts[0]
        names = parts[1:] or None
        if area not in self.server.backend.list_authority_areas():
            self.send_error(ErrorCode.INVALID_AUTHORITY_AREA)
            return None
        classes = (
            self.server.backend.get_schema(area, names)
            if kind == "schema"
            else self.server.backend.get_classes(area, names)
        )
        if names:
            found = {cls.class_name.lower() for cls in classes}
            for name in names:
                if name.lower() not in found:
                    self.send_error(ErrorCode.INVALID_CLASS)
                    return None
        return classes

    def _do_soa(self, rest: str) -> None:
        areas = self._split_args(rest) or self.server.backend.list_authority_areas()
        records: list[SOARecord] = []
        for area in areas:
            soa = self.server.backend.get_soa(area)
            if soa is None:
                self.send_error(
                    ErrorCode.INVALID_AUTHORITY_AREA, f"unknown authority area: {area}"
                )
                return
            records.append(soa)
        lines: list[str] = []
        for soa in records:
            lines.extend(soa.to_lines())
        if lines:
            self.send_lines(lines)
        self.send_ok()

    def _do_schema(self, rest: str) -> None:
        classes = self._classes_or_error(rest, "schema")
        if classes is None:
            return
        lines: list[str] = []
        for cls in classes:
            lines.extend(cls.to_schema_lines())
        if lines:
            self.send_lines(lines)
        self.send_ok()

    def _do_class(self, rest: str) -> None:
        classes = self._classes_or_error(rest, "class")
        if classes is None:
            return
        lines: list[str] = []
        for cls in classes:
            lines.extend(cls.to_class_lines())
        if lines:
            self.send_lines(lines)
        self.send_ok()

    def _do_directive(self, rest: str) -> None:
        requested = set(self._split_args(rest)) or set(DIRECTIVE_DESCRIPTIONS)
        known = set(DIRECTIVE_DESCRIPTIONS)
        lines: list[str] = []
        for name in sorted(requested):
            if name in known:
                lines.append(f"%directive directive:{name}")
                lines.append(
                    f"%directive description:{DIRECTIVE_DESCRIPTIONS.get(name, name)}"
                )
                lines.append("%directive")
        if lines:
            self.send_lines(lines)
        self.send_ok()

    def _do_notify(self, rest: str) -> None:
        if not getattr(self.server.backend, "support_notify", False):
            self.send_error(ErrorCode.DIRECTIVE_NOT_AVAILABLE)
            return
        if not rest:
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
            return
        event, *args = rest.split(" ")
        try:
            ok = self.server.backend.notify(event, *args)
        except Exception as exc:
            self.send_error(ErrorCode.UNIDENTIFIED_ERROR, str(exc))
            return
        if ok:
            self.send_ok()
        else:
            self.send_error(ErrorCode.NOT_AUTHORIZED_FOR_DIRECTIVE)

    def _do_security(self, rest: str) -> None:
        if not getattr(self.server.backend, "support_security", False):
            self.send_error(ErrorCode.DIRECTIVE_NOT_AVAILABLE)
            return
        if rest == "off":
            self.state.authenticated = False
            self.state.security_direction = None
            self.state.security_method = None
            self.state.security_credential = None
            self.send_ok()
            return
        parts = rest.split(" ", 3)
        if len(parts) < 3 or parts[0] != "on":
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
            return
        direction, method = parts[1], parts[2]
        password = parts[3] if len(parts) > 3 else ""
        if direction not in {"request", "response"}:
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
            return
        if method != "password" or direction != "request":
            self.send_error(ErrorCode.INVALID_SECURITY_METHOD)
            return
        if not self.server.backend.authenticate(password):
            self.send_error(ErrorCode.AUTHENTICATION_FAILED)
            return
        self.state.authenticated = True
        self.state.security_direction = direction
        self.state.security_method = method
        self.state.security_credential = password
        self.send_ok()

    def _do_xfer(self, rest: str) -> None:
        if not getattr(self.server.backend, "support_xfer", False):
            self.send_error(ErrorCode.DIRECTIVE_NOT_AVAILABLE)
            return
        parts = self._split_args(rest)
        if not parts:
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
            return
        area = parts[0]
        class_names: list[str] = []
        attributes: list[str] = []
        serial = None
        for token in parts[1:]:
            if token.startswith("class="):
                class_names.append(token.split("=", 1)[1])
            elif token.startswith("attribute="):
                attributes.append(token.split("=", 1)[1])
            elif re.match(r"^\d{17}$", token):
                serial = token
            else:
                self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
                return
        if area not in self.server.backend.list_authority_areas():
            self.send_error(ErrorCode.INVALID_AUTHORITY_AREA)
            return
        try:
            objs = self.server.backend.export(
                area, class_names or None, attributes or None, serial
            )
        except NotImplementedError:
            self.send_error(ErrorCode.DIRECTIVE_NOT_AVAILABLE)
            return
        if not objs:
            self.send_error(ErrorCode.NOTHING_TO_TRANSFER)
            return
        lines: list[str] = []
        for obj in objs:
            for attr in obj.attributes:
                lines.append(f"%xfer {obj.class_name}:{attr.name}:{attr.value}")
            lines.append("%xfer")
        self.send_lines(lines)
        self.send_ok()

    def _do_x(self, name: str, rest: str) -> None:
        handler = self.server.x_handlers.get(name)
        if handler is None:
            self.send_error(ErrorCode.DIRECTIVE_NOT_AVAILABLE)
            return
        try:
            out = handler(rest, self.state)
        except Exception as exc:
            self.send_error(ErrorCode.UNIDENTIFIED_ERROR, str(exc))
            return
        if out:
            # Deliberately unguarded. An x handler returns raw operator strings, and handle() is
            # now the single place that turns a refused line into "%error 402" for every send
            # site; catching here too would give this one path different semantics from the rest
            # of the protocol. The exception also skips the send_ok() below, which is exactly
            # right -- a batch that was refused must not be followed by a success.
            self.send_lines(out)
        self.send_ok()

    def _do_register(self, rest: str) -> None:
        if not getattr(self.server.backend, "support_register", False):
            self.send_error(ErrorCode.DIRECTIVE_NOT_AVAILABLE)
            return
        # Read through the app rather than a copy on the socket server: `_make_server`
        # mirrors a handful of fields onto AppServer, and an option that exists in two
        # places is an option that silently does nothing when only one is updated --
        # which is exactly how this flag first shipped broken.
        app = getattr(self.server, "app", None)
        if getattr(app, "registration_deferred", False):
            # Ahead of the syntax check, because the reason for the refusal has nothing
            # to do with what the client sent.
            self.send_error(ErrorCode.REGISTRATION_DEFERRED)
            return
        if rest == "off":
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX, "no active register")
            return
        parts = self._split_args(rest)
        if len(parts) != 3 or parts[0] != "on" or parts[1] not in {"add", "mod", "del"}:
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX)
            return
        self.state.register_mode = parts[1]
        self.state.register_maintainer = parts[2]
        self.state.register_lines = []
        self.send_ok()

    def collect_register_line(self, line: str) -> None:
        if line == "-register off":
            mode = self.state.register_mode
            self.state.register_mode = None
            self.finish_register(mode)
            return
        self.state.register_lines.append(line)

    def _resolve_guardians(
        self, area: str, guardian_ids: list[str]
    ) -> list[ObjectRecord]:
        """Turn a class's ``Guardian`` values into guardian objects, refusing any that
        point at nothing (Appendix C: 323, and Section 2.3.6 says the value *is* the ID
        of a guardian object).

        Returns nothing on a backend that cannot look objects up. That is not a pass:
        the caller's check is skipped and the log says so, because "no guardians" and
        "guardians we could not read" must not look alike on the wire and then differ
        in what they let through.
        """
        backend = self.server.backend
        if not guardian_ids:
            return []
        if not getattr(backend, "supports_object_lookup", False):
            log_event(
                _LOG,
                logging.WARNING,
                "guardian_checks_skipped",
                area=area,
                guardians=len(guardian_ids),
                detail="backend does not implement get_object_by_id",
            )
            return []
        resolved: list[ObjectRecord] = []
        for guardian_id in guardian_ids:
            guardian = backend.get_object_by_id(area, guardian_id)
            if guardian is None:
                raise ObjectReferenceNotFound(
                    f"guardian object not found: {guardian_id}"
                )
            resolved.append(guardian)
        return resolved

    def _check_guardian_references(self, obj: ObjectRecord) -> None:
        self._resolve_guardians(obj.auth_area or "", obj.getall("Guardian"))

    def _authorize_guarded_change(self, area: str, object_id: str | None) -> None:
        """Section 2.3.6: modifying or deleting a guarded object requires satisfying one
        of its guardians. Adding is not gated -- the spec names modify and delete.

        Guardians have no rank, so satisfying any one is sufficient. Only the
        ``password`` scheme can be satisfied here; a guardian that names any other
        (PGP, say) cannot be met by this server, and Section 2.3.6 requires a scheme be
        "understood by both the client and server" -- so an unsatisfiable guardian is a
        refusal, never an accidental yes.
        """
        if not object_id:
            return
        stored = None
        if getattr(self.server.backend, "supports_object_lookup", False):
            stored = self.server.backend.get_object_by_id(area, object_id)
        if stored is None:
            return  # the backend reports a missing object with its own code
        guardians = self._resolve_guardians(area, stored.getall("Guardian"))
        if not guardians and not (stored.get("Guard-Scheme") or "").strip():
            return  # nothing guards it, linked or self
        if not self._guardian_satisfied(area, stored):
            raise RegistrationNotAuthorized(
                "the object's guardians did not accept the session's credentials"
            )

    def _private_attribute_names(self, area: str, class_name: str) -> set[str]:
        """The names this class declares `Private`, lower-cased for comparison.

        No try/except around the schema read on purpose. A privacy check that falls back to
        "nothing is private" when the schema is unreadable is a leak that looks like a
        working server, so the failure travels up to the one place that can turn it into an
        honest `%error`.
        """
        classes = self.server.backend.get_schema(area, [class_name])
        if not classes:
            return set()
        return {attr.name.lower() for attr in classes[0].attributes if attr.private}

    def _guardian_satisfied(self, area: str, obj: ObjectRecord) -> bool:
        """Whether this session satisfies at least one of the object's guardians (2.3.6).

        Shared by the registration gate and the `Private` filter deliberately: two copies of
        "who is allowed" drift apart, and the failure mode is a client that can read a value
        it cannot change, or cannot change a value it was allowed to write.
        """
        guardians = self._resolve_guardians(area, obj.getall("Guardian"))
        # Section 2.3.6: "A guardian object that does not have any Guardian attribute
        # linking it to other guardians guards itself. That is, the authentication scheme in
        # the guardian object itself must be satisfied to modify, delete, or possibly view
        # it." Adding the record as its own candidate is what implements that, and it is what
        # makes a guardian's Guard-Info viewable by exactly the sessions that present it.
        if (obj.get("Guard-Scheme") or "").strip():
            guardians = [*guardians, obj]
        credential = self.state.security_credential
        for guardian in guardians:
            scheme = (guardian.get("Guard-Scheme") or "").strip().lower()
            if scheme != "password":
                continue
            if credential is not None and guardian.get("Guard-Info") == credential:
                return True
        return False

    def _viewable(self, obj: ObjectRecord) -> ObjectRecord | None:
        """Apply section 2.3.1's `Private` rule to a record about to be sent.

        A private attribute-value pair is "publicly not viewable": only a client satisfying
        one of the object's guardians may see it. The base class carries the same flag at
        object level, in which case the record is not sent at all. Returns None for a record
        that must be withheld, and the caller treats that as no match -- which is the point:
        answering with an empty record set would announce that something matched.

        Note the asymmetry with the registration gate. When a backend cannot read guardians,
        a write is allowed and logged -- refusing every write on such a backend would make
        the feature unusable -- but a read is withheld. Failing open is acceptable where the
        operator can see the log line and the client is identified anyway; on a read it would
        hand out the value the flag exists to protect.
        """
        area = obj.auth_area or ""
        private_names = self._private_attribute_names(area, obj.class_name)
        object_private = (obj.get("Private") or "").strip().lower() in _PRIVATE_TRUE
        if not private_names and not object_private:
            return obj
        if self._guardian_satisfied(area, obj):
            return obj
        if object_private:
            return None
        kept = [a for a in obj.attributes if a.name.lower() not in private_names]
        if len(kept) == len(obj.attributes):
            return obj
        return ObjectRecord(class_name=obj.class_name, attributes=kept)

    def _check_registration_object(self, obj: ObjectRecord) -> None:
        """Validate a client-supplied object against the class this server advertises.

        Reports the first problem with the Appendix C code that names it, because the
        codes differ deliberately: 320 means "this attribute is not in the class",
        321 "the value does not fit the attribute", 322 "a required attribute is
        absent". Answering all three with one code leaves the client guessing.
        """
        area = obj.auth_area or ""
        if area not in self.server.backend.list_authority_areas():
            raise InvalidAuthorityArea(
                f"unknown authority area: {area or '(none given)'}"
            )
        classes = self.server.backend.get_schema(area, [obj.class_name])
        if not classes:
            raise InvalidClass(
                f"unknown class {obj.class_name} for authority area {area}"
            )
        problems = validate_for_registration(obj, classes[0])
        if problems:
            code, message = problems[0]
            raise RwhoisError(message, code=code)

    def finish_register(self, mode: str | None = None) -> None:
        """Validate and apply a completed `-register` block (RFC 2167 section 3.3.9).

        Each way a client can get this wrong has its own Appendix C code, and the
        whole method used to end in `except Exception` -> 402, so a missing required
        attribute, an unknown class, and a backend that cannot write at all were all
        reported as the same unidentified server error -- including when the fault was
        the client's.
        """
        mode = mode or self.state.register_mode
        lines = self.state.register_lines
        self.state.register_lines = []
        backend = self.server.backend
        try:
            if (
                getattr(backend, "support_security", False)
                and not self.state.authenticated
            ):
                # A server configured to authenticate is saying registration must be
                # attributable to somebody; 401 is the code Appendix C offers for it.
                raise NotAuthorizedForDirective(
                    "registration requires an authenticated session"
                )

            if mode == "del":
                obj = _object_from_register_lines(lines)
                for attribute in ("ID", "Updated"):
                    if obj.get(attribute) is None:
                        raise RequiredAttributeMissing(
                            f"del requires the {attribute} attribute"
                        )
                self._authorize_guarded_change(obj.auth_area or "", obj.get("ID"))
                backend.delete_object(obj)
                self.send_lines([f"%register ID:{obj.get('ID')}"])
                self.send_ok()
                return

            if mode == "mod":
                try:
                    sep = lines.index("_NEW_")
                except ValueError:
                    raise InvalidDirectiveSyntax("_NEW_ separator required for mod")
                old = _object_from_register_lines(lines[:sep])
                new = _object_from_register_lines(lines[sep + 1 :])
                for attribute in ("ID", "Updated"):
                    if old.get(attribute) is None:
                        raise RequiredAttributeMissing(
                            f"mod identifying data requires the {attribute} attribute"
                        )
                # The RFC requires ID, Auth-Area and Class-Name to agree across the
                # separator: they are what identifies the record, and disagreeing
                # halves mean the client is describing two different objects.
                for attribute in ("ID", "Auth-Area", "Class-Name"):
                    before = (old.get(attribute) or "").strip().lower()
                    after = (new.get(attribute) or "").strip().lower()
                    if before != after:
                        raise ObjectReferenceNotFound(
                            f"{attribute} differs between the two halves of the mod"
                        )
                # The stored object is what is being changed, so its guardians are the
                # ones that must be satisfied (Section 2.3.6 names modify and delete).
                self._authorize_guarded_change(new.auth_area or "", new.id)
                self._check_guardian_references(new)
                self._check_registration_object(new)
                result = backend.update_object(new, identifying_updated=old.updated)
                self.send_lines(
                    [
                        f"%register ID:{result.get('ID') or old.get('ID')}",
                        f"%register Updated:{result.get('Updated') or ''}",
                    ]
                )
                self.send_ok()
                return

            obj = _object_from_register_lines(lines)
            self._check_registration_object(obj)
            self._check_guardian_references(obj)
            result = backend.create_object(obj)
            self.send_lines(
                [
                    f"%register ID:{result.get('ID') or ''}",
                    f"%register Updated:{result.get('Updated') or ''}",
                ]
            )
            self.send_ok()
        except RwhoisParseError as exc:
            # A malformed attribute line is the client's syntax error, not ours.
            self.send_error(ErrorCode.INVALID_DIRECTIVE_SYNTAX, str(exc))
        except RwhoisError as exc:
            self.send_error(
                exc.code or ErrorCode.UNIDENTIFIED_ERROR, exc.error_text or None
            )
        except NotImplementedError as exc:
            self.send_error(
                ErrorCode.DIRECTIVE_NOT_AVAILABLE,
                str(exc) or "backend does not support registration",
            )
        except Exception as exc:  # noqa: BLE001 - a fault here must stay the server's
            self.send_error(ErrorCode.UNIDENTIFIED_ERROR, str(exc))


def _object_from_register_lines(lines: list[str]) -> ObjectRecord:
    """Parse a register block's attribute lines into an object.

    Appendix B makes `register-line` an `attribute-name ":" attribute-value`, so a
    line with no colon is something the client must be told about. It used to be
    dropped, which let a half-written object be stored as a successful
    registration. Class-Name sets the class wherever it appears: a client that
    sends the attributes first and the class last was previously filed under
    "unknown".
    """
    obj: ObjectRecord | None = None
    for line in lines:
        if not line or line == "_NEW_":
            continue
        name, sep, value = line.partition(":")
        name = name.strip()
        if not sep or not name:
            raise InvalidDirectiveSyntax(f"invalid register line: {line!r}")
        if name.lower() == "class-name":
            class_name = value.strip()
            if obj is None:
                obj = ObjectRecord(class_name or "unknown")
            elif obj.class_name == "unknown" and class_name:
                validate_id(class_name, label="class name")
                obj.class_name = class_name
        if obj is None:
            obj = ObjectRecord("unknown")
        obj.add(name, value)
    if obj is None:
        raise InvalidDirectiveSyntax("register block contained no attributes")
    return obj


__all__ = ["RwhoisServer", "SessionState"]
