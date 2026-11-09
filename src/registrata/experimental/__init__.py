"""Experimental compatibility and unified lookup features."""

from __future__ import annotations

from .._flags import (
    ExperimentalDisabled,
    ExperimentalFeature,
    FeatureStatus,
    is_enabled,
    require,
    status,
)
from ..model import RegistrationRecord, from_rdap, from_rwhois_object, from_whois_fields
from . import batch, gateway, rdap, whois, whois_adapters
from .batch import BatchItem, BatchResult, batch_lookup, batch_lookup_async
from .gateway import GatewayConfig, GatewayServer
from .lookup import LookupResult, lookup

__all__ = [
    "BatchItem",
    "BatchResult",
    "ExperimentalDisabled",
    "ExperimentalFeature",
    "FeatureStatus",
    "GatewayConfig",
    "GatewayServer",
    "LookupResult",
    "RegistrationRecord",
    "batch",
    "batch_lookup",
    "batch_lookup_async",
    "gateway",
    "from_rdap",
    "from_rwhois_object",
    "from_whois_fields",
    "is_enabled",
    "lookup",
    "rdap",
    "require",
    "status",
    "whois",
    "whois_adapters",
]
