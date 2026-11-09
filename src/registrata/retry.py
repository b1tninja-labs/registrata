"""Retry helpers with exponential backoff."""

from __future__ import annotations

from dataclasses import dataclass
import random
import time
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")


class RetryExhausted(RuntimeError):
    """Raised when retries are exhausted and the caller wants an exception."""


@dataclass(frozen=True)
class Backoff:
    base_delay: float = 0.5
    max_delay: float = 30.0
    multiplier: float = 2.0
    jitter: bool = False

    def delay(self, attempt: int) -> float:
        attempt = max(0, int(attempt))
        raw = self.base_delay * (self.multiplier**attempt)
        raw = min(raw, self.max_delay)
        if self.jitter:
            raw = random.uniform(0.0, raw)
        return raw


def with_retries(
    fn: Callable[[], T],
    *,
    retries: int = 0,
    backoff: Backoff | None = None,
    retry_on: tuple[type[BaseException], ...] = (OSError,),
    sleeper: Callable[[float], None] = time.sleep,
    on_retry: Callable[[int, BaseException, float], None] | None = None,
    raise_on_exhaustion: bool = False,
) -> T | BaseException:
    """Call *fn* up to ``retries + 1`` times, returning the last error when exhausted."""
    if retries < 0:
        raise ValueError("retries must be >= 0")
    plan = backoff or Backoff()
    last_exc: BaseException | None = None
    for attempt in range(retries + 1):
        try:
            return fn()
        except retry_on as exc:
            last_exc = exc
            if attempt >= retries:
                break
            delay = plan.delay(attempt)
            if on_retry is not None:
                on_retry(attempt + 1, exc, delay)
            sleeper(delay)
    if raise_on_exhaustion and last_exc is not None:
        raise RetryExhausted(str(last_exc)) from last_exc
    assert last_exc is not None
    return last_exc


def should_retry_http_status(
    status: int | None, retry_statuses: Iterable[int] = (429, 500, 502, 503, 504)
) -> bool:
    return status in set(retry_statuses)


__all__ = ["Backoff", "RetryExhausted", "should_retry_http_status", "with_retries"]
