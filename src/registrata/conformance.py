"""Server conformance checker for RWhois servers."""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Callable

from .banner import Banner
from .capabilities import Capability
from .client import RwhoisClient
from .errors import ErrorCode, RwhoisError


@dataclass
class CheckItem:
    name: str
    status: str
    detail: str = ""
    error_code: int | None = None

    @property
    def ok(self) -> bool:
        return self.status == "pass"


@dataclass
class ServerReport:
    host: str
    port: int
    items: list[CheckItem] = field(default_factory=list)
    banner: Banner | None = None
    capabilities: Capability = Capability.NONE
    duration: float = 0.0
    fatal: str | None = None

    @property
    def ok(self) -> bool:
        return self.fatal is None and all(item.status != "fail" for item in self.items)

    @property
    def score(self) -> float:
        """Fraction of the checks that *ran*, skipping the ones that could not.

        A skip is not evidence against a server: it means a capability the banner never
        advertised, or an optional directive the server lawfully declined. Counting skips in the
        denominator made a minimal server that does everything it promises score about a third
        while ``ok`` reported it conformant, and this number is printed next to that verdict.
        Zero means nothing was evaluated, which is no evidence either way.
        """
        evaluated = [item for item in self.items if item.status != "skip"]
        if not evaluated:
            return 0.0
        return round(sum(1 for item in evaluated if item.ok) / len(evaluated), 3)

    def add(
        self, name: str, status: str, *, detail: str = "", error_code: int | None = None
    ) -> None:
        self.items.append(
            CheckItem(name=name, status=status, detail=detail, error_code=error_code)
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "ok": self.ok,
            "fatal": self.fatal,
            "duration": round(self.duration, 3),
            "score": self.score,
            "banner": self.banner.raw if self.banner else "",
            "versions": list(self.banner.version_numbers) if self.banner else [],
            "capabilities": {
                c.name.lower(): bool(c & self.capabilities)
                for c in Capability
                if int(c)
            },
            "items": [
                {
                    "name": item.name,
                    "status": item.status,
                    "detail": item.detail,
                    "error_code": item.error_code,
                }
                for item in self.items
            ],
        }


#: Answers to ``-class`` that still prove the directive is implemented: the server understood it
#: well enough to reject the probe's authority area or syntax, or to say it holds no such object.
#: The probe sends a handle where an authority area belongs, so these are the expected answers
#: from a server that implements -class but holds nothing the probe could name.
_CLASSES_EVIDENCE = {
    ErrorCode.NO_OBJECTS_FOUND,
    ErrorCode.INVALID_AUTHORITY_AREA,
    ErrorCode.INVALID_QUERY_SYNTAX,
}

#: -class sits in RFC 2167 section 3.3, "Optional Directives -- the server should implement the
#: following directives". A server that declines it is exercising a lawful option, so the verdict
#: is a skip: the same one the checker already gives for a capability the banner never advertised.
#: There is no entry here for a code Appendix C does not define -- the list this replaces named
#: 201, which appears in no version of the RFC, which meant an unrecognised code was the one
#: answer guaranteed to be scored as a pass.
_CLASSES_UNAVAILABLE = {ErrorCode.DIRECTIVE_NOT_AVAILABLE}


def classes_verdict(code: int | None) -> str:
    """What an error answer to ``-class`` says about the server, not about the probe."""
    if code in _CLASSES_UNAVAILABLE:
        return "skip"
    if code in _CLASSES_EVIDENCE:
        return "pass"
    return "fail"


def check_server(
    host: str,
    port: int,
    *,
    timeout: float = 10.0,
    query_class: str | None = None,
    query_text: str = "example.invalid",
) -> ServerReport:
    started = time.monotonic()
    report = ServerReport(host=host, port=int(port))
    try:
        # hold_connect=False so the checker's own session does not negotiate the directive before
        # the probe runs. A client that has already sent "-holdconnect on" cannot observe a server
        # refusing it, and "advertises the capability, declines the directive" is exactly the
        # inconsistency this check exists to report.
        client = RwhoisClient.connect(
            host, int(port), timeout=timeout, hold_connect=False
        )
    except Exception as exc:
        report.fatal = f"connection failed: {exc}"
        report.duration = time.monotonic() - started
        return report

    report.banner = client.banner
    best = client.banner.best_version() if client.banner else None
    report.capabilities = best.capability if best else Capability.NONE

    with client:
        report.add("banner", "pass", detail=client.banner.raw if client.banner else "")

        def optional(capability: Capability, name: str, fn: Callable[[], Any]) -> None:
            if not (report.capabilities & capability):
                report.add(name, "skip", detail="capability not advertised")
                return
            try:
                value = fn()
            except Exception as exc:
                report.add(name, "fail", detail=str(exc))
                return
            if value is None:
                report.add(name, "fail", detail="directive did not end with -ok/-error")
            else:
                report.add(name, "pass", detail=str(value)[:200])

        optional(
            Capability.HOLDCONNECT,
            "directive:holdconnect",
            lambda: client.holdconnect(True),
        )
        optional(Capability.LIMIT, "directive:limit", lambda: client.limit(5))
        optional(Capability.STATUS, "directive:status", lambda: client.status())
        optional(Capability.SOA, "directive:soa", lambda: client.soa() or [])
        optional(
            Capability.DIRECTIVE,
            "directive:directive",
            lambda: client.directives() or [],
        )
        optional(
            Capability.DISPLAY, "directive:display", lambda: client.display() or []
        )

        try:
            response = client.classes(query_text)
            classes = getattr(response, "class_classes", [])
            if response.error_code is not None:
                report.add(
                    "directive:classes",
                    classes_verdict(response.error_code),
                    detail=f"{response.error_code} {response.error_text or ''}".strip(),
                )
            elif classes:
                report.add(
                    "directive:classes", "pass", detail=f"{len(classes)} class(es)"
                )
            else:
                report.add("directive:classes", "pass", detail="empty class response")
        except RwhoisError as exc:
            status = classes_verdict(exc.code)
            detail = (
                f"{exc.code} {exc.error_text}".strip()
                if exc.code is not None
                else str(exc)
            )
            report.add("directive:classes", status, detail=detail)
        except Exception as exc:
            report.add("directive:classes", "fail", detail=str(exc))

        try:
            result = client.query(query_class, query_text, raise_errors=False)
            if result.raw_lines:
                if result.error_code is None:
                    report.add(
                        "query", "pass", detail=f"{len(result.objects)} object(s)"
                    )
                elif result.error_code in {230, 350}:
                    # A structured expected error response is still protocol-compliant for a probe query.
                    report.add(
                        "query",
                        "pass",
                        detail=f"{result.error_code} {result.error_text or ''}".strip(),
                    )
                else:
                    report.add(
                        "query",
                        "fail",
                        detail=f"{result.error_code} {result.error_text or ''}".strip(),
                        error_code=result.error_code,
                    )
            else:
                report.add("query", "fail", detail="empty response")
        except Exception as exc:
            report.add("query", "fail", detail=str(exc))

    report.duration = time.monotonic() - started
    return report


__all__ = ["CheckItem", "ServerReport", "check_server"]
