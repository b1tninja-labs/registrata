"""Special-use domain names: names that no registry can ever serve.

A lookup for ``example.com`` is not a miss, and -- as this project's own
recordings prove -- it is not even refused. Verisign answers it with a complete
object: handle ``2336799_DOMAIN_COM-VRSN``, statuses, two Cloudflare name
servers, a creation date in 1995 and an expiry in 2027 (see
``tests/fixtures/live/rdap_example_com_verisign.json``). That is the problem.
The answer looks exactly like a finding, and belongs to a name that no one, ever,
can register. A sweep that reports it as `ok` with data is worse than one that
reports nothing, because the record is a fixture that quietly teaches whoever
reads the report that the pipeline works.

So a public lookup of a reserved name is settled before any socket opens: it
costs no quota and, more importantly, cannot be mistaken for data.

The list is the IANA "Special-Use Domain Names" registry that RFC 6761
establishes, not RFC 2606 alone. RFC 2606 reserves the three ``example.*``
documentation domains plus ``invalid`` and ``test``; ``example``, ``localhost``,
``local`` (RFC 6762) and ``onion`` (RFC 7686) come from other documents, and the
registry takes new entries. Each label therefore travels with the document that
put it there, so a later refresh can tell a stale entry from a current one.

Two kinds of caller want to ask anyway, and both are legitimate: a private
RWhois tree may hold objects under ``example.com``, and ``example.com`` is the
conventional smoke test that a client and a registry are still talking to each
other. Use ``skip_reserved=False`` (CLI: ``--query-reserved``) for either.
"""

from __future__ import annotations

__all__ = [
    "SPECIAL_USE_TLDS",
    "RESERVED_DOCUMENT_NAMES",
    "special_use_reason",
    "is_special_use",
]

#: Root-adjacent labels whose entire subtree is special use.
SPECIAL_USE_TLDS: dict[str, str] = {
    "alt": "RFC 9476",
    "example": "RFC 6761",
    "invalid": "RFC 6761",
    "local": "RFC 6762",
    "localhost": "RFC 6761",
    "onion": "RFC 7686",
    "test": "RFC 6761",
}

#: Names reserved below the root, together with everything beneath them.
RESERVED_DOCUMENT_NAMES: dict[str, str] = {
    "example.com": "RFC 2606",
    "example.net": "RFC 2606",
    "example.org": "RFC 2606",
}

_MAX_LABEL = 63
_MAX_NAME = 253


def _labels(value: str) -> list[str]:
    """Split a name into lowercase labels, or return [] if it is not one."""
    name = value.strip().rstrip(".").lower()
    if not name or len(name) > _MAX_NAME:
        return []
    labels = name.split(".")
    if any(not label or len(label) > _MAX_LABEL for label in labels):
        return []
    return labels


def special_use_reason(resource: str) -> str | None:
    """Return why ``resource`` can never be registered, or ``None`` if it might.

    Only names are judged; deciding what counts as a name is the caller's job
    (see :func:`registrata.experimental.whois.classify_resource`), because a bare
    ``test`` is just as likely to be a keyword query. Names are matched case
    insensitively and a trailing root dot is ignored, per DNS practice.
    """
    labels = _labels(resource)
    if not labels:
        return None

    for depth in range(min(len(labels), 2), 0, -1):
        suffix = ".".join(labels[-depth:])
        reference = RESERVED_DOCUMENT_NAMES.get(suffix)
        if reference and len(labels) >= depth:
            return f"{suffix} is reserved for documentation ({reference})"

    tld = labels[-1]
    reference = SPECIAL_USE_TLDS.get(tld)
    if reference is not None:
        shown = f".{tld}" if len(labels) > 1 else f"{tld}."
        return f"{shown} is a special-use top-level domain ({reference})"
    return None


def is_special_use(resource: str) -> bool:
    """True when no public registry can ever serve ``resource``."""
    return special_use_reason(resource) is not None
