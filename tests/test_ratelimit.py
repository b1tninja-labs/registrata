import pytest

from registrata.ratelimit import RateLimitTimeout, RateLimiterRegistry, TokenBucket


def test_token_bucket_acquire_and_refill():
    bucket = TokenBucket(rate_per_second=100, capacity=2)
    assert bucket.try_acquire(2)
    assert not bucket.try_acquire(1)
    bucket.acquire(1, timeout=0.1)
    assert bucket.available() >= 0


def test_registry_is_per_key():
    registry = RateLimiterRegistry(default_rate_per_second=0, default_capacity=1)
    registry.acquire("a", timeout=None)
    with pytest.raises(RateLimitTimeout):
        registry.acquire("a", timeout=0)
    registry.configure("a", rate_per_second=10, capacity=5)
    registry.acquire("b")
    assert set(registry.keys()) == {"a", "b"}
