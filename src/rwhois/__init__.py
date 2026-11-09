"""Deprecated alias for :mod:`registrata`.

The project was renamed from ``rwhois``/``pyrwhois`` to ``registrata`` because the
toolkit covers registration data across RWhois (RFC 2167), classic WHOIS
(RFC 3912) and RDAP (RFC 9082/RFC 9083), not RWhois alone. ``import rwhois`` still
works, emits a :class:`DeprecationWarning`, and every ``rwhois.*`` submodule is
aliased to the same ``registrata.*`` module object so shared state and
``isinstance`` checks keep behaving as one package.

This package is a compatibility seam only; remove it once no caller uses the old
import path.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
import warnings

import registrata as _registrata

_DEPRECATION = (
    "the 'rwhois' package name is deprecated; import 'registrata' instead "
    "(pip install registrata). This alias will be removed in a future release."
)

__version__ = _registrata.__version__
__all__ = list(_registrata.__all__)

for _export in _registrata.__all__:
    globals()[_export] = getattr(_registrata, _export)


def _alias_submodules() -> None:
    """Point every ``rwhois.<name>`` import at the shared ``registrata.<name>`` module."""
    this = sys.modules[__name__]
    names = [
        info.name
        for info in pkgutil.walk_packages(_registrata.__path__, prefix="registrata.")
    ]
    names.append("registrata._flags")
    for name in dict.fromkeys(names):
        try:
            module = importlib.import_module(name)
        except Exception:  # pragma: no cover - keep the alias importable regardless
            continue
        alias = "rwhois" + name[len("registrata") :]
        sys.modules[alias] = module
        parent, _, leaf = alias.rpartition(".")
        setattr(sys.modules.get(parent, this), leaf, module)


warnings.warn(_DEPRECATION, DeprecationWarning, stacklevel=2)
_alias_submodules()
