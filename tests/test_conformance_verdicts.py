"""Verdicts from ``check_server`` against a server scripted to answer in chosen ways.

check_server's entire job is emitting conformance verdicts, and the only paths exercised before
this file were "our own server passes" and "nothing is listening". A claim-producing module with
untested claim logic is how a wrong verdict ships, so each answer below pins one verdict.
"""

from __future__ import annotations

import socket
import threading

from registrata.conformance import CheckItem, ServerReport, check_server

BANNER = "%rwhois V-1.5:000000:00 127.0.0.1 probe 1.0"


def serve_replies(replies: list[tuple[str, list[str]]], banner: str = BANNER):
    """A server that answers the first matching request prefix and advertises no capabilities.

    Advertising nothing is deliberate: every optional() check then skips, so classes and query
    are the only verdicts in the report that these assertions can be satisfying. Pass a banner
    with capability bits set to exercise the advertised path.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    stop = threading.Event()

    def handle(conn: socket.socket) -> None:
        conn.sendall((banner + "\r\n").encode())
        buffered = b""
        while not stop.is_set():
            try:
                data = conn.recv(4096)
            except OSError:
                return
            if not data:
                return
            buffered += data
            while b"\n" in buffered:
                line, _, buffered = buffered.partition(b"\n")
                request = line.decode("latin-1").strip()
                for prefix, lines in replies:
                    if request.startswith(prefix):
                        conn.sendall(("\r\n".join(lines) + "\r\n").encode())
                        break

    def loop() -> None:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            with conn:
                try:
                    handle(conn)
                except OSError:
                    pass

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return listener, thread, stop


def report_from(replies: list[tuple[str, list[str]]], banner: str = BANNER):
    listener, thread, stop = serve_replies(replies, banner)
    try:
        return check_server("127.0.0.1", listener.getsockname()[1], timeout=2)
    finally:
        stop.set()
        listener.close()
        thread.join(2)


def status_of(report: ServerReport, name: str) -> CheckItem:
    for item in report.items:
        if item.name == name:
            return item
    raise AssertionError(f"{name} missing from {[i.name for i in report.items]}")


def test_a_class_directive_that_is_not_available_is_a_skip_not_a_failure() -> None:
    """RFC 2167 section 3.3 files -class under "Optional Directives: the server should implement".

    So "%error 400 Directive not available" is a lawful answer, and scoring it a failure condemns
    a conforming server. Nor is it a pass -- the directive is not implemented. The module already
    has a verdict for "not supported here" (skip, used for unadvertised capabilities) and it
    belongs here too.
    """
    report = report_from(
        [("-class", ["%error 400 Directive not available"]), ("", ["%ok"])]
    )

    item = status_of(report, "directive:classes")
    assert item.status == "skip", f"400 must not be a failure: {item.detail}"
    assert report.ok, "a lawful refusal must not make the whole report not-ok"


def test_an_unknown_error_code_is_not_counted_as_a_pass() -> None:
    """Code 201 is in no RFC 2167 error list, and the whitelist entry naming it was dead.

    What it actually did was score anything unrecognised as passing, because an unknown code was
    the one thing the list guaranteed not to match a known failure.
    """
    report = report_from([("-class", ["%error 201 Something invented"]), ("", ["%ok"])])

    item = status_of(report, "directive:classes")
    assert item.status != "pass", f"an unknown code passed the check: {item.detail}"


def test_a_rejected_authority_area_still_proves_the_directive_exists() -> None:
    """340 is a server implementing -class far enough to validate its arguments.

    The probe sends a handle where the authority area goes, so any real server reaches its own
    argument checking; that is evidence the directive exists even though no metadata came back.
    """
    report = report_from(
        [("-class", ["%error 340 Invalid authority area"]), ("", ["%ok"])]
    )

    assert status_of(report, "directive:classes").status == "pass"


def test_skipped_checks_are_left_out_of_the_score() -> None:
    """Score divides the checks that ran, because a skip is not a failed check.

    With skips in the denominator, a server that advertises no optional capabilities and does
    everything it promises scores about a third, which reads to an operator as a badly broken
    server while report.ok says the opposite. The two must not disagree.
    """
    report = ServerReport(host="h", port=1)
    report.add("banner", "pass")
    report.add("directive:classes", "skip", detail="not supported")
    report.add("query", "pass")

    assert report.score == 1.0
    assert report.ok


def test_advertising_holdconnect_but_refusing_it_is_reported() -> None:
    """The checker must not negotiate a session for itself, or it hides exactly this bug.

    ``check_server`` passes ``hold_connect=False`` so its probe is the first thing the server is
    asked. A client that had already asked -- and quietly carried on after a refusal, as it must
    to be useful -- could never notice a server that advertises the capability and declines the
    directive, which is a real deployment bug and the kind worth reporting.
    """
    advertised = "%rwhois V-1.5:000010:00 127.0.0.1 probe 1.0"  # Capability.HOLDCONNECT
    refused = report_from(
        [("-holdconnect", ["%error 400 Directive not available"]), ("", ["%ok"])],
        banner=advertised,
    )
    accepted = report_from([("", ["%ok"])], banner=advertised)

    assert status_of(refused, "directive:holdconnect").status == "fail"
    assert status_of(accepted, "directive:holdconnect").status == "pass"
