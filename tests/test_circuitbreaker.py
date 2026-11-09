import pytest

from registrata.circuitbreaker import (
    CLOSED,
    OPEN,
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitOpen,
    run_with_circuit,
)


def test_circuit_breaker_opens_after_consecutive_failures():
    breaker = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=10)

    assert breaker.allow(now=0)
    breaker.record_failure(now=1)
    assert breaker.allow(now=1)
    breaker.record_failure(now=2)

    assert breaker._state == OPEN
    assert not breaker.allow(now=5)


def test_circuit_breaker_half_open_trial_closes_on_success():
    breaker = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=10)

    breaker.record_failure(now=0)
    assert not breaker.allow(now=5)

    assert breaker.allow(now=11)
    assert not breaker.allow(now=11)

    breaker.record_success(now=11)
    assert breaker._state == CLOSED
    assert breaker.allow(now=12)


def test_circuit_breaker_half_open_failure_reopens():
    breaker = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=10)

    breaker.record_failure(now=0)
    assert breaker.allow(now=11)
    breaker.record_failure(now=12)

    assert breaker._state == OPEN
    assert not breaker.allow(now=15)


def test_registry_and_run_with_circuit_block_open_endpoint():
    registry = CircuitBreakerRegistry(default_failure_threshold=1)

    with pytest.raises(ValueError):
        run_with_circuit(
            registry,
            "rdap:bootstrap",
            lambda: (_ for _ in ()).throw(ValueError("boom")),
        )

    with pytest.raises(CircuitOpen):
        run_with_circuit(registry, "rdap:bootstrap", lambda: True)

    snapshot = registry.snapshot()
    assert snapshot["rdap:bootstrap"]["state"] == "open"
    assert snapshot["rdap:bootstrap"]["failure_count"] == 1
