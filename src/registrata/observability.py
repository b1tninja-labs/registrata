"""Structured logging helpers for operational diagnostics.

This module intentionally stays lightweight: the CLI can configure Python's
standard logging system, while library code only emits low-noise diagnostics
through normal loggers.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import sys
from typing import Any

MARKER = "_registrata_cli_handler"
# Structured payloads nest under this log-record attribute name.
PAYLOAD_KEY = "registrata"
# Records emitted before the project was renamed to ``registrata`` (and any caller
# still using the old key) nest their payload under ``pyrwhois`` instead.
LEGACY_PAYLOAD_KEY = "pyrwhois"


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        data = getattr(record, PAYLOAD_KEY, None)
        if data is None:
            data = getattr(record, LEGACY_PAYLOAD_KEY, None)
        if isinstance(data, dict):
            payload.update(data)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)
        return json.dumps(payload, default=str, sort_keys=True)


def get_logger(name: str = "registrata") -> logging.Logger:
    logger = logging.getLogger(name)
    if not any(isinstance(handler, logging.NullHandler) for handler in logger.handlers):
        logger.addHandler(logging.NullHandler())
    return logger


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    **fields: Any,
) -> None:
    payload = {"event": event}
    payload.update({k: v for k, v in fields.items() if v is not None})
    if logger.isEnabledFor(level):
        logger.log(level, event, extra={PAYLOAD_KEY: payload})


def configure_logging(
    level: str | int = "warning",
    *,
    stream: Any | None = None,
    json: bool = False,
) -> logging.Handler:
    """Configure the CLI's stderr log handler.

    This is intended for command-line use. Library callers can configure logging
    themselves; this function only adds a marked handler and removes old marked
    CLI handlers to avoid duplicate output after repeated calls.
    """
    root = logging.getLogger()
    if isinstance(level, str):
        normalized = level.upper()
        root.setLevel(getattr(logging, normalized, logging.WARNING))
    else:
        root.setLevel(level)

    for handler in list(root.handlers):
        if getattr(handler, MARKER, False):
            root.removeHandler(handler)
            handler.close()

    handler = logging.StreamHandler(stream or sys.stderr)
    if json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
    setattr(handler, MARKER, True)
    root.addHandler(handler)
    return handler


__all__ = [
    "JsonFormatter",
    "configure_logging",
    "get_logger",
    "log_event",
]
