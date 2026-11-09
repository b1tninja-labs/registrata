"""Small dependency-free metrics registry for gateway and operator tooling."""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from typing import Any


def _label_key(labels: dict[str, Any] | None) -> str:
    if not labels:
        return ""
    parts = [f"{key}={value}" for key, value in sorted(labels.items())]
    return ",".join(parts)


def _metric_key(name: str, labels: dict[str, Any] | None) -> str:
    suffix = _label_key(labels)
    return f"{name}{{{suffix}}}" if suffix else name


@dataclass
class MetricsRegistry:
    """Thread-safe counters and numeric observations for operational reporting."""

    _counters: dict[str, int] = field(default_factory=dict, repr=False)
    _observations: dict[str, dict[str, float]] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _started_at: float = field(default_factory=time.time, repr=False)

    def add(
        self, name: str, value: int = 1, labels: dict[str, Any] | None = None
    ) -> None:
        key = _metric_key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + int(value)

    def set(self, name: str, value: int, labels: dict[str, Any] | None = None) -> None:
        key = _metric_key(name, labels)
        with self._lock:
            self._counters[key] = int(value)

    def observe(
        self, name: str, value: float, labels: dict[str, Any] | None = None
    ) -> None:
        key = _metric_key(name, labels)
        numeric = float(value)
        with self._lock:
            stats = self._observations.get(key)
            if stats is None:
                self._observations[key] = {
                    "count": 1,
                    "sum": numeric,
                    "min": numeric,
                    "max": numeric,
                }
                return
            stats["count"] += 1
            stats["sum"] += numeric
            stats["min"] = min(stats["min"], numeric)
            stats["max"] = max(stats["max"], numeric)

    def counter(self, name: str, labels: dict[str, Any] | None = None) -> int:
        with self._lock:
            return int(self._counters.get(_metric_key(name, labels), 0))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            counters = dict(self._counters)
            observations = {
                key: dict(value) for key, value in self._observations.items()
            }
        averages = {}
        for key, stats in observations.items():
            count = stats.get("count", 0)
            averages[key] = {
                **stats,
                "mean": (stats.get("sum", 0.0) / count) if count else None,
            }
        return {
            "uptime_seconds": max(0.0, time.time() - self._started_at),
            "counters": counters,
            "observations": averages,
        }


__all__ = ["MetricsRegistry"]
