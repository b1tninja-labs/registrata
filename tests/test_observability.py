import io
import json
import logging

from registrata.observability import MARKER, JsonFormatter, configure_logging, log_event


def test_log_event_json_formatter():
    stream = io.StringIO()
    logger = logging.getLogger("rwhois.test_observability")
    old_level = logger.level
    old_propagate = logger.propagate
    old_handlers = list(logger.handlers)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        log_event(logger, logging.INFO, "cache_hit", key="example", age_seconds=12.5)
    finally:
        logger.handlers = old_handlers
        logger.level = old_level
        logger.propagate = old_propagate
    payload = json.loads(stream.getvalue().strip())
    assert payload["event"] == "cache_hit"
    assert payload["key"] == "example"
    assert payload["age_seconds"] == 12.5
    assert payload["level"] == "info"


def test_configure_logging_replaces_only_cli_handler():
    root = logging.getLogger()
    old_level = root.level
    old_handlers = list(root.handlers)
    stream = io.StringIO()
    try:
        first = configure_logging("debug", stream=stream, json=True)
        assert getattr(first, MARKER, False)
        first_count = sum(1 for h in root.handlers if getattr(h, MARKER, False))
        configure_logging("warning", stream=io.StringIO(), json=False)
        second_count = sum(1 for h in root.handlers if getattr(h, MARKER, False))
        assert first_count == 1
        assert second_count == 1
    finally:
        for handler in list(root.handlers):
            if getattr(handler, MARKER, False):
                root.removeHandler(handler)
        for handler in old_handlers:
            if handler not in root.handlers:
                root.addHandler(handler)
        root.setLevel(old_level)
