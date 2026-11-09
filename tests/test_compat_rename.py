"""Compatibility seams for the ``pyrwhois``/``rwhois`` -> ``registrata`` rename.

Three pre-rename artifacts must keep working: the ``rwhois`` import path, the
``pyrwhois`` structured-log payload key, and SQLite cache files that still store
rows in the ``pyrwhois_cache`` table.
"""

from __future__ import annotations

import importlib
import json
import logging
import sqlite3
import sys

import pytest

import registrata
from registrata.cache import SQLiteCache
from registrata.observability import JsonFormatter


def _fresh_rwhois_import() -> object:
    for name in [n for n in sys.modules if n == "rwhois" or n.startswith("rwhois.")]:
        del sys.modules[name]
    with pytest.warns(DeprecationWarning, match="deprecated"):
        return importlib.import_module("rwhois")


def test_rwhois_import_warns_and_reexports_same_objects() -> None:
    shim = _fresh_rwhois_import()
    assert shim.__version__ == registrata.__version__
    assert shim.RwhoisClient is registrata.RwhoisClient
    assert shim.RegistrationRecord is registrata.RegistrationRecord
    assert set(registrata.__all__) <= set(shim.__all__)


def test_rwhois_submodules_alias_the_registrata_modules() -> None:
    shim = _fresh_rwhois_import()
    assert importlib.import_module(
        "rwhois.experimental.rdap"
    ) is importlib.import_module("registrata.experimental.rdap")
    assert importlib.import_module("rwhois._flags") is importlib.import_module(
        "registrata._flags"
    )
    assert shim.experimental is importlib.import_module("registrata.experimental")
    assert sys.modules["rwhois.cache"] is importlib.import_module("registrata.cache")


def test_json_formatter_still_reads_legacy_pyrwhois_key() -> None:
    record = logging.LogRecord(
        "registrata.test", logging.INFO, __file__, 1, "cache_hit", None, None
    )
    setattr(record, "pyrwhois", {"event": "cache_hit", "key": "example"})
    payload = json.loads(JsonFormatter().format(record))
    assert payload["event"] == "cache_hit"
    assert payload["key"] == "example"


def test_sqlite_cache_adopts_legacy_pyrwhois_table(tmp_path) -> None:
    path = tmp_path / "responses.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE pyrwhois_cache (
            namespace TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            expires_at REAL,
            PRIMARY KEY (namespace, key)
        )
        """
    )
    conn.execute(
        "INSERT INTO pyrwhois_cache VALUES (?, ?, ?, ?)",
        ("registrata", "domain:example.com", json.dumps({"cached": True}), None),
    )
    conn.commit()
    conn.close()

    cache = SQLiteCache(path, namespace="registrata")
    try:
        assert cache.get("domain:example.com") == {"cached": True}
        tables = {
            row[0]
            for row in sqlite3.connect(path).execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert "registrata_cache" in tables
        assert "pyrwhois_cache" not in tables
    finally:
        cache.close()


def test_sqlite_cache_writes_to_renamed_table(tmp_path) -> None:
    cache = SQLiteCache(tmp_path / "fresh.sqlite3", namespace="registrata")
    try:
        cache.set("asn:64496", {"asn": 64496})
        assert cache.get("asn:64496") == {"asn": 64496}
    finally:
        cache.close()
