"""Small dependency-free rate limiting helpers.

These helpers are intentionally conservative. They are meant for polite
registration-data querying, not for abusive bulk scanning.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Iterable


class RateLimitTimeout(TimeoutError):
    """Raised when a rate limit cannot be satisfied within the timeout."""


@dataclass
class TokenBucket:
    """A simple token bucket with monotonic-clock accounting."""

    rate_per_second: float = 1.0
    capacity: float = 1.0
    _tokens: float = field(init=False, default=0.0)
    _last: float = field(init=False, default_factory=time.monotonic)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.rate_per_second = max(0.0, float(self.rate_per_second))
        self.capacity = max(0.0, float(self.capacity))
        self._tokens = self.capacity

    def available(self) -> float:
        with self._lock:
            self._refill_locked()
            return self._tokens

    def _refill_locked(self) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self._last)
        self._last = now
        if self.rate_per_second > 0:
            self._tokens = min(
                self.capacity, self._tokens + elapsed * self.rate_per_second
            )

    def try_acquire(self, amount: float = 1.0) -> bool:
        with self._lock:
            self._refill_locked()
            if self._tokens >= amount:
                self._tokens -= amount
                return True
            return False

    def acquire(self, amount: float = 1.0, timeout: float | None = None) -> None:
        deadline = None if timeout is None else time.monotonic() + float(timeout)
        amount = float(amount)
        if self.rate_per_second <= 0 and self.capacity < amount:
            raise RateLimitTimeout(
                f"rate limit capacity {self.capacity} is lower than requested {amount}"
            )
        while True:
            if self.try_acquire(amount):
                return
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                raise RateLimitTimeout("timed out waiting for rate limit")
            wait_for = 0.01
            if self.rate_per_second > 0:
                needed = max(0.0, amount - self._tokens)
                wait_for = max(wait_for, min(0.25, needed / self.rate_per_second))
            if deadline is not None:
                wait_for = min(wait_for, max(0.0, deadline - time.monotonic()))
            time.sleep(wait_for)


@dataclass
class RateLimiterRegistry:
    """Registry of per-key token buckets."""

    default_rate_per_second: float = 1.0
    default_capacity: float = 1.0
    _buckets: dict[str, TokenBucket] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def bucket(self, key: str) -> TokenBucket:
        normalized = str(key).lower()
        with self._lock:
            bucket = self._buckets.get(normalized)
            if bucket is None:
                bucket = TokenBucket(
                    rate_per_second=self.default_rate_per_second,
                    capacity=self.default_capacity,
                )
                self._buckets[normalized] = bucket
            return bucket

    def configure(
        self,
        key: str,
        *,
        rate_per_second: float | None = None,
        capacity: float | None = None,
    ) -> TokenBucket:
        normalized = str(key).lower()
        with self._lock:
            bucket = self._buckets.get(normalized)
            if bucket is None:
                bucket = TokenBucket(
                    rate_per_second=self.default_rate_per_second,
                    capacity=self.default_capacity,
                )
                self._buckets[normalized] = bucket
            if rate_per_second is not None:
                bucket.rate_per_second = max(0.0, float(rate_per_second))
            if capacity is not None:
                bucket.capacity = max(0.0, float(capacity))
                bucket._tokens = min(bucket.capacity, bucket._tokens)
            return bucket

    def acquire(
        self, key: str, amount: float = 1.0, timeout: float | None = None
    ) -> None:
        self.bucket(key).acquire(amount=amount, timeout=timeout)

    def keys(self) -> Iterable[str]:
        return tuple(self._buckets.keys())


__all__ = ["RateLimitTimeout", "RateLimiterRegistry", "TokenBucket"]
