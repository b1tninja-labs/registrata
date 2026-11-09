"""Experimental feature flags.

Environment variables (``REGISTRATA_*`` is canonical; the pre-rename ``RWHOIS_*``
names are still read, and an unset variable falls back to it):

- ``REGISTRATA_ENABLE_EXPERIMENTAL`` enables or disables all experimental features.
- ``REGISTRATA_ENABLE_EXPERIMENTAL_WHOIS`` overrides the classic WHOIS feature.
- ``REGISTRATA_ENABLE_EXPERIMENTAL_RDAP`` overrides RDAP.
- ``REGISTRATA_ENABLE_EXPERIMENTAL_GATEWAY`` overrides gateway mode.

When both spellings of a variable are set, the ``REGISTRATA_*`` value wins.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

ENV_PREFIX = "REGISTRATA_"
# Accepted for compatibility with the pre-rename ``pyrwhois``/``rwhois`` project.
LEGACY_ENV_PREFIX = "RWHOIS_"


class ExperimentalFeature(str, Enum):
    WHOIS = "whois"
    RDAP = "rdap"
    GATEWAY = "gateway"


class ExperimentalDisabled(RuntimeError):
    """Raised when an experimental feature is disabled."""


_DEFAULTS: dict[ExperimentalFeature, bool] = {
    ExperimentalFeature.WHOIS: True,
    ExperimentalFeature.RDAP: True,
    ExperimentalFeature.GATEWAY: False,
}

_ALL_ENV = "ENABLE_EXPERIMENTAL"
_ENV_SUFFIXES: dict[ExperimentalFeature, str] = {
    ExperimentalFeature.WHOIS: "ENABLE_EXPERIMENTAL_WHOIS",
    ExperimentalFeature.RDAP: "ENABLE_EXPERIMENTAL_RDAP",
    ExperimentalFeature.GATEWAY: "ENABLE_EXPERIMENTAL_GATEWAY",
}


def lookup_env(suffix: str, environ: Mapping[str, str] | None = None) -> str | None:
    """Read ``REGISTRATA_<suffix>``, falling back to the legacy ``RWHOIS_<suffix>``."""
    environment = os.environ if environ is None else environ
    for prefix in (ENV_PREFIX, LEGACY_ENV_PREFIX):
        value = environment.get(prefix + suffix)
        if value is not None:
            return value
    return None


def env_name(suffix: str) -> str:
    """Return the canonical environment variable name for a suffix."""
    return ENV_PREFIX + suffix


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on", "y"}:
        return True
    if lowered in {"0", "false", "no", "off", "n", ""}:
        return False
    return default


def is_enabled(
    feature: ExperimentalFeature | str, *, env: Mapping[str, str] | None = None
) -> bool:
    resolved = ExperimentalFeature(feature)
    default = _parse_bool(lookup_env(_ALL_ENV, env), _DEFAULTS[resolved])
    return _parse_bool(lookup_env(_ENV_SUFFIXES[resolved], env), default)


def enable(feature: ExperimentalFeature | str, *, value: bool = True) -> None:
    os.environ[env_name(_ENV_SUFFIXES[ExperimentalFeature(feature)])] = (
        "1" if value else "0"
    )


def disable(feature: ExperimentalFeature | str) -> None:
    enable(feature, value=False)


@dataclass(frozen=True)
class FeatureStatus:
    feature: ExperimentalFeature
    enabled: bool
    default: bool
    env_name: str
    legacy_env_name: str


def status(env: Mapping[str, str] | None = None) -> list[FeatureStatus]:
    return [
        FeatureStatus(
            feature=feature,
            enabled=is_enabled(feature, env=env),
            default=_DEFAULTS[feature],
            env_name=env_name(suffix),
            legacy_env_name=LEGACY_ENV_PREFIX + suffix,
        )
        for feature, suffix in _ENV_SUFFIXES.items()
    ]


def require(
    feature: ExperimentalFeature | str, *, env: Mapping[str, str] | None = None
) -> None:
    resolved = ExperimentalFeature(feature)
    if not is_enabled(resolved, env=env):
        raise ExperimentalDisabled(
            f"experimental feature {resolved.value!r} is disabled; "
            f"set {env_name(_ENV_SUFFIXES[resolved])}=1"
        )


__all__ = [
    "ENV_PREFIX",
    "ExperimentalDisabled",
    "ExperimentalFeature",
    "FeatureStatus",
    "LEGACY_ENV_PREFIX",
    "disable",
    "enable",
    "env_name",
    "is_enabled",
    "lookup_env",
    "require",
    "status",
]
