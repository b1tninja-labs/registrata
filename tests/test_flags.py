import os

import pytest

from registrata._flags import (
    ENV_PREFIX,
    LEGACY_ENV_PREFIX,
    ExperimentalDisabled,
    ExperimentalFeature,
    enable,
    is_enabled,
    lookup_env,
    require,
    status,
)


def test_flags_defaults():
    assert is_enabled(ExperimentalFeature.WHOIS, env={}) is True
    assert is_enabled(ExperimentalFeature.RDAP, env={}) is True
    assert is_enabled(ExperimentalFeature.GATEWAY, env={}) is False


def test_global_enable_overrides_default():
    assert (
        is_enabled(
            ExperimentalFeature.GATEWAY, env={"REGISTRATA_ENABLE_EXPERIMENTAL": "1"}
        )
        is True
    )


def test_specific_flag_overrides_global():
    assert (
        is_enabled(
            ExperimentalFeature.RDAP,
            env={
                "REGISTRATA_ENABLE_EXPERIMENTAL": "1",
                "REGISTRATA_ENABLE_EXPERIMENTAL_RDAP": "0",
            },
        )
        is False
    )


def test_legacy_rwhois_prefix_is_still_honored():
    assert (
        is_enabled(
            ExperimentalFeature.GATEWAY, env={"RWHOIS_ENABLE_EXPERIMENTAL_GATEWAY": "1"}
        )
        is True
    )
    assert (
        is_enabled(
            ExperimentalFeature.WHOIS, env={"RWHOIS_ENABLE_EXPERIMENTAL_WHOIS": "0"}
        )
        is False
    )


def test_canonical_prefix_wins_over_legacy_prefix():
    env = {
        "RWHOIS_ENABLE_EXPERIMENTAL_GATEWAY": "1",
        "REGISTRATA_ENABLE_EXPERIMENTAL_GATEWAY": "0",
    }
    assert is_enabled(ExperimentalFeature.GATEWAY, env=env) is False


def test_lookup_env_falls_back_to_legacy_prefix():
    assert (
        lookup_env("GATEWAY_API_KEY", {"RWHOIS_GATEWAY_API_KEY": "legacy"}) == "legacy"
    )
    assert (
        lookup_env(
            "GATEWAY_API_KEY",
            {"REGISTRATA_GATEWAY_API_KEY": "new", "RWHOIS_GATEWAY_API_KEY": "legacy"},
        )
        == "new"
    )
    assert lookup_env("GATEWAY_API_KEY", {}) is None


def test_enable_writes_canonical_variable(monkeypatch):
    monkeypatch.delenv("REGISTRATA_ENABLE_EXPERIMENTAL_RDAP", raising=False)
    monkeypatch.delenv("RWHOIS_ENABLE_EXPERIMENTAL_RDAP", raising=False)
    enable(ExperimentalFeature.RDAP, value=True)
    assert os.environ["REGISTRATA_ENABLE_EXPERIMENTAL_RDAP"] == "1"
    assert "RWHOIS_ENABLE_EXPERIMENTAL_RDAP" not in os.environ


def test_require_names_canonical_variable():
    with pytest.raises(ExperimentalDisabled, match=ENV_PREFIX) as excinfo:
        require(ExperimentalFeature.GATEWAY, env={})
    assert f"{ENV_PREFIX}ENABLE_EXPERIMENTAL_GATEWAY=1" in str(excinfo.value)
    assert LEGACY_ENV_PREFIX not in str(excinfo.value)


def test_status_reports_all_features():
    statuses = status(env={})
    assert {s.feature.value for s in statuses} == {"whois", "rdap", "gateway"}
    assert {s.feature.value: s.enabled for s in statuses} == {
        "whois": True,
        "rdap": True,
        "gateway": False,
    }
