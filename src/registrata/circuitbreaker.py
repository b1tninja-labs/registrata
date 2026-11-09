"""Circuit breaker helpers for registration-data clients.

Registration-data endpoints can fail persistently during outages, DNS problems,
or policy blocks. Retrying those endpoints too aggressively makes the failure
worse. The breaker here is deliberately simple and dependency-free:

- closed: request traffic is allowed;
- open: traffic is blocked until the recovery timeout expires;
- half_open: one trial request is allowed to probe recovery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from typing import Any, Iterable

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"


class CircuitOpen(RuntimeError):
    """Raised when a caller tries to use a circuit that is currently open."""

    def __init__(
        self, key: str, *, retry_after: float | None = None, reason: str | None = None
    ):
        self.key = key
        self.retry_after = retry_after
        self.reason = reason
        message = f"circuit open for {key!r}"
        if retry_after is not None:
            message += f"; retry after {retry_after:.1f}s"
        if reason:
            message += f": {reason}"
        super().__init__(message)


@dataclass
class CircuitBreaker:
    """A per-endpoint consecutive-failure breaker."""

    name: str = "default"
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    success_threshold: int = 1
    _state: str = field(default=CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _success_count: int = field(default=0, init=False)
    _opened_at: float | None = field(default=None, init=False)
    _last_failure: str | None = field(default=None, init=False)
    _trial_in_progress: bool = field(default=False, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.failure_threshold = max(1, int(self.failure_threshold))
        self.success_threshold = max(1, int(self.success_threshold))
        self.recovery_timeout = max(0.0, float(self.recovery_timeout))

    @property
    def state(self) -> str:
        with self._lock:
            self._maybe_half_open_locked(time.monotonic())
            return self._state

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    @property
    def success_count(self) -> int:
        with self._lock:
            return self._success_count

    def retry_after(self, now: float | None = None) -> float | None:
        """Seconds until an open circuit may be probed again."""
        with self._lock:
            if self._state != OPEN or self._opened_at is None:
                return None
            clock = time.monotonic() if now is None else float(now)
            return max(0.0, self.recovery_timeout - (clock - self._opened_at))

    def allow(self, *, now: float | None = None) -> bool:
        """Return whether a request may proceed, reserving half-open trials."""
        with self._lock:
            clock = time.monotonic() if now is None else float(now)
            self._maybe_half_open_locked(clock)
            if self._state == CLOSED:
                return True
            if self._state == OPEN:
                return False
            if self._trial_in_progress:
                return False
            self._trial_in_progress = True
            return True

    def record_success(self, *, now: float | None = None) -> None:
        with self._lock:
            if self._state == HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._reset_closed_locked()
                return
            self._failure_count = 0
            self._success_count += 1
            self._trial_in_progress = False

    def record_failure(
        self, *, reason: str | None = None, now: float | None = None
    ) -> None:
        with self._lock:
            clock = time.monotonic() if now is None else float(now)
            self._trial_in_progress = False
            self._success_count = 0
            self._last_failure = reason
            if (
                self._state == HALF_OPEN
                or self._failure_count + 1 >= self.failure_threshold
            ):
                self._failure_count += 1
                self._state = OPEN
                self._opened_at = clock
            else:
                self._failure_count += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._maybe_half_open_locked(time.monotonic())
            return {
                "name": self.name,
                "state": self._state,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "failure_threshold": self.failure_threshold,
                "recovery_timeout": self.recovery_timeout,
                "last_failure": self._last_failure,
                "retry_after": (
                    max(
                        0.0,
                        self.recovery_timeout - (time.monotonic() - self._opened_at),
                    )
                    if self._state == OPEN and self._opened_at is not None
                    else None
                ),
            }

    def raise_if_open(self) -> None:
        if not self.allow():
            raise CircuitOpen(
                self.name, retry_after=self.retry_after(), reason=self._last_failure
            )

    def _maybe_half_open_locked(self, now: float) -> None:
        if self._state == OPEN and self._opened_at is not None:
            if now - self._opened_at >= self.recovery_timeout:
                self._state = HALF_OPEN
                self._success_count = 0
                self._trial_in_progress = False

    def _reset_closed_locked(self) -> None:
        self._state = CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._opened_at = None
        self._trial_in_progress = False


@dataclass
class CircuitBreakerRegistry:
    """Registry of named circuit breakers."""

    default_failure_threshold: int = 5
    default_recovery_timeout: float = 30.0
    default_success_threshold: int = 1
    _breakers: dict[str, CircuitBreaker] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def breaker(self, key: str) -> CircuitBreaker:
        normalized = str(key).lower()
        with self._lock:
            breaker = self._breakers.get(normalized)
            if breaker is None:
                breaker = CircuitBreaker(
                    name=normalized,
                    failure_threshold=self.default_failure_threshold,
                    recovery_timeout=self.default_recovery_timeout,
                    success_threshold=self.default_success_threshold,
                )
                self._breakers[normalized] = breaker
            return breaker

    def configure(
        self,
        key: str,
        *,
        failure_threshold: int | None = None,
        recovery_timeout: float | None = None,
        success_threshold: int | None = None,
    ) -> CircuitBreaker:
        normalized = str(key).lower()
        breaker = self.breaker(normalized)
        if failure_threshold is not None:
            breaker.failure_threshold = max(1, int(failure_threshold))
        if recovery_timeout is not None:
            breaker.recovery_timeout = max(0.0, float(recovery_timeout))
        if success_threshold is not None:
            breaker.success_threshold = max(1, int(success_threshold))
        return breaker

    def allow(self, key: str) -> bool:
        return self.breaker(key).allow()

    def raise_if_open(self, key: str) -> None:
        self.breaker(key).raise_if_open()

    def record_success(self, key: str) -> None:
        self.breaker(key).record_success()

    def record_failure(self, key: str, *, reason: str | None = None) -> None:
        self.breaker(key).record_failure(reason=reason)

    def keys(self) -> Iterable[str]:
        return tuple(self._breakers.keys())

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {
                name: breaker.snapshot() for name, breaker in self._breakers.items()
            }


def run_with_circuit(
    registry: CircuitBreakerRegistry,
    key: str,
    fn,
    *,
    success_fn=None,
):
    """Call *fn* while recording success/failure into *registry*."""
    registry.raise_if_open(key)
    try:
        value = fn()
    except Exception as exc:
        registry.record_failure(key, reason=str(exc))
        raise
    if success_fn is None or success_fn(value):
        registry.record_success(key)
    else:
        registry.record_failure(
            key, reason=getattr(value, "error", None) or "unsuccessful result"
        )
    return value


__all__ = [
    "CLOSED",
    "HALF_OPEN",
    "OPEN",
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "CircuitOpen",
    "run_with_circuit",
]
