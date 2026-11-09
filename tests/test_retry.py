import pytest

from registrata.retry import (
    Backoff,
    RetryExhausted,
    should_retry_http_status,
    with_retries,
)


def test_backoff_is_exponential_and_capped():
    backoff = Backoff(base_delay=0.25, max_delay=1.0, multiplier=2.0)
    assert backoff.delay(0) == 0.25
    assert backoff.delay(1) == 0.5
    assert backoff.delay(10) == 1.0


def test_with_retries_returns_success_and_sleeps():
    calls = []
    sleeps = []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise OSError("transient")
        return "ok"

    assert (
        with_retries(
            fn,
            retries=2,
            backoff=Backoff(base_delay=1, multiplier=2),
            sleeper=sleeps.append,
        )
        == "ok"
    )
    assert len(calls) == 3
    assert sleeps == [1, 2]


def test_with_retries_returns_last_error_by_default():
    def fn():
        raise OSError("boom")

    result = with_retries(fn, retries=1, sleeper=lambda _: None)
    assert isinstance(result, OSError)
    assert str(result) == "boom"


def test_with_retries_can_raise_on_exhaustion():
    def fn():
        raise OSError("boom")

    with pytest.raises(RetryExhausted):
        with_retries(fn, retries=0, sleeper=lambda _: None, raise_on_exhaustion=True)


def test_should_retry_http_status():
    assert should_retry_http_status(429)
    assert not should_retry_http_status(404)
