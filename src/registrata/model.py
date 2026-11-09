"""Normalized registration-data models.

The goal is a small stable-ish internal shape shared by RWhois objects, classic
WHOIS text fields, and RDAP JSON. Field names are deliberately explicit because
these records are intended for automation, diffing, and comparison.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Iterable

_DATE_KEYS = {
    "registration": {
        "creation date",
        "created date",
        "registered date",
        "registration date",
    },
    "expiration": {
        "expiration date",
        "expiry date",
        "registry expiry date",
        "registrar registration expiration date",
    },
    "last changed": {"updated date", "last modified", "last updated", "changed"},
    "deletion": ["deletion date"],
}

_STATUS_KEY = {"status", "domain status", "object status"}
_NAMESERVER_KEYS = {"name server", "nameserver", "host name", "nserver"}
_ROLE_PATTERNS = (
    "registrant",
    "admin",
    "technical",
    "tech",
    "billing",
    "abuse",
    "owner",
    "contact",
)


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _split_values(values: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for value in values:
        text = _clean(value)
        if not text:
            continue
        # WHOIS registries often return several values in one line.
        for token in re.split(r"[,\s]+", text):
            token = token.strip()
            if token:
                out.append(token)
    return out


def _first(values: Iterable[Any]) -> str | None:
    for value in values:
        text = _clean(value)
        if text:
            return text
    return None


def _date_to_iso(value: str) -> dict[str, str]:
    # Keep both the source value and a best-effort ISO value. This is intentionally
    # conservative: WHOIS date formats vary wildly and should not be silently mangled.
    iso = None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    for parser in ("fromisoformat", "strptime"):
        try:
            if parser == "fromisoformat":
                from datetime import datetime

                parsed = datetime.fromisoformat(candidate)
            else:
                from datetime import datetime

                parsed = datetime.strptime(candidate, "%Y-%m-%dT%H:%M:%S%z")
            iso = parsed.isoformat()
            break
        except ValueError:
            continue
    if iso is None:
        iso = candidate
    return {"date": iso, "raw_date": value}


@dataclass
class RegistrationRecord:
    source: str
    kind: str | None = None
    identifier: str | None = None
    handle: str | None = None
    statuses: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    contacts: list[dict[str, Any]] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    registrar: dict[str, Any] | None = None
    dnssec: dict[str, Any] | None = None
    networks: list[dict[str, Any]] = field(default_factory=list)
    port43: str | None = None
    notices: list[dict[str, Any]] = field(default_factory=list)
    links: list[dict[str, Any]] = field(default_factory=list)
    # RDAP extension awareness (RFC 9083 §4.1/§4.3/§4.4/§9, RFC 8982, RFC 9537).
    # Empty for other sources.
    conformance: list[str] = field(default_factory=list)
    lang: str | None = None
    truncated: bool = False
    truncation: list[dict[str, Any]] = field(default_factory=list)
    redacted: list[dict[str, Any]] = field(default_factory=list)
    subsetting: dict[str, Any] | None = None
    context: dict[str, Any] = field(default_factory=dict)
    raw: Any = None

    @property
    def incomplete(self) -> bool:
        """True when the response states that data was withheld from it.

        Two signals say so unambiguously: a typed truncation notice or remark
        (RFC 9083 section 9) and a ``redacted`` entry (RFC 9537). A field set is
        deliberately not folded in here: RFC 8982 subsetting metadata names the
        field set that was applied, and a server may report its default field set
        while still returning everything it holds. Read ``record.subsetting``
        directly when the distinction matters.
        """
        return bool(self.truncated or self.redacted)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "identifier": self.identifier,
            "handle": self.handle,
            "statuses": self.statuses,
            "events": self.events,
            "contacts": self.contacts,
            "nameservers": self.nameservers,
            "registrar": self.registrar,
            "dnssec": self.dnssec,
            "networks": self.networks,
            "port43": self.port43,
            "notices": self.notices,
            "links": self.links,
            "conformance": self.conformance,
            "lang": self.lang,
            "truncated": self.truncated,
            "truncation": self.truncation,
            "redacted": self.redacted,
            "subsetting": self.subsetting,
            "context": self.context,
            "raw": self.raw,
        }

    def referrals(
        self, *, include_self_duplicates: bool = False
    ) -> list[dict[str, Any]]:
        """Return complete ``related`` links a client may legitimately follow.

        RFC 9083 section 4.2 requires "value", "rel" and "href" in a link and
        forbids a "related" href that repeats a "self" href, so incomplete and
        loop-forming links are skipped unless explicitly asked for.
        """
        out: list[dict[str, Any]] = []
        for link in self.links:
            if str(link.get("rel") or "").strip().lower() != "related":
                continue
            if not link.get("complete") or (
                link.get("self_duplicate") and not include_self_duplicates
            ):
                continue
            out.append(link)
        return out

    def links_for(
        self, rel: str, *, include_notice_links: bool = False
    ) -> list[dict[str, Any]]:
        """Return normalized links whose ``rel`` matches, ignoring case.

        Links carried inside notices are only included when asked for, so that
        ``record.links`` stays a faithful view of the object's own link set
        (RFC 9083 §4.2) while service messages remain reachable on demand.
        """
        wanted = str(rel).strip().lower()
        pool = list(self.links)
        if include_notice_links:
            for notice in self.notices:
                if isinstance(notice, dict):
                    pool.extend(
                        link
                        for link in (notice.get("links") or [])
                        if isinstance(link, dict)
                    )
        return [
            link
            for link in pool
            if str(link.get("rel") or "").strip().lower() == wanted
        ]

    def supports(self, token: str) -> bool:
        """Check ``rdapConformance`` for a specification or extension identifier."""
        wanted = str(token).strip().lower()
        return any(str(item).strip().lower() == wanted for item in self.conformance)


def _parse_vcard(vcard: Any) -> dict[str, Any]:

    out: dict[str, Any] = {}
    if not isinstance(vcard, list) or len(vcard) < 2:
        return out
    for prop in vcard[1] or []:
        if not isinstance(prop, list) or not prop:
            continue
        name = str(prop[0]).lower()
        value = prop[3] if len(prop) > 3 else None
        if name == "fn":
            out["name"] = _clean(value) or out.get("name")
        elif name == "org":
            out["organization"] = _clean(value) or out.get("organization")
        elif name == "email":
            emails = out.setdefault("emails", [])
            email = _clean(value)
            if email and email not in emails:
                emails.append(email)
        elif name in {"tel", "phone"}:
            phones = out.setdefault("phones", [])
            phone = _clean(value)
            if phone and phone not in phones:
                phones.append(phone)
        elif name == "adr":
            out["address_raw"] = value
    return out


# ---------------------------------------------------------------------------
# RDAP common data structures (RFC 9083 section 4)
# ---------------------------------------------------------------------------

#: Notice/remark ``type`` values registered in RFC 9083 section 10.2.1 that mark
#: a response or a single object as truncated, i.e. deliberately partial.
RDAP_TRUNCATION_TYPES: tuple[str, ...] = (
    "result set truncated due to authorization",
    "result set truncated due to excessive load",
    "result set truncated due to unexplainable reasons",
    "object truncated due to authorization",
    "object truncated due to excessive load",
    "object truncated due to unexplainable reasons",
)

#: RFC 9083 section 4.2: "value", "rel" and "href" MUST be specified in a link.
RDAP_LINK_REQUIRED_MEMBERS: tuple[str, ...] = ("value", "rel", "href")
RDAP_LINK_MEMBERS: tuple[str, ...] = RDAP_LINK_REQUIRED_MEMBERS + (
    "type",
    "media",
    "title",
    "hreflang",
)
#: RFC 9083 section 4.3: notices and remarks share one shape, of which
#: "description" is the only mandatory member.
RDAP_NOTICE_MEMBERS: tuple[str, ...] = ("title", "type", "description", "links", "lang")
#: The identifier of RFC 9083 itself inside "rdapConformance" (section 4.1).
RDAP_BASE_CONFORMANCE = "rdap_level_0"
#: Conformance identifiers of the RDAP extensions modelled here: partial
#: responses via the "fieldSet" query parameter (RFC 8982 section 2.1.1) and
#: redacted response fields (RFC 9537 section 4.1).
RDAP_SUBSETTING_CONFORMANCE = "subsetting"
RDAP_REDACTED_CONFORMANCE = "redacted"
#: Redaction methods defined by RFC 9537 section 4.2; "removal" is the default.
RDAP_REDACTION_METHODS: frozenset[str] = frozenset(
    {"removal", "emptyValue", "partialValue", "replacementValue"}
)
RDAP_DEFAULT_REDACTION_METHOD = "removal"
#: Default JSON path dialect of "prePath"/"postPath" (RFC 9537 section 4.2).
RDAP_DEFAULT_PATH_LANG = "jsonpath"

#: Top-level RDAP members that the normalized model represents somewhere (in the
#: record itself or in ``raw``). Anything else is reported in
#: ``record.context["unmodelled_members"]`` so that server extensions are visible
#: instead of silently ignored.
_RDAP_MODELLED_MEMBERS = frozenset(
    {
        "objectClassName",
        "handle",
        "id",
        "ldhName",
        "unicodeName",
        "ipAddress",
        "startAddress",
        "endAddress",
        "name",
        "status",
        "events",
        "asEventActor",
        "entities",
        "links",
        "notices",
        "remarks",
        "port43",
        "publicIds",
        "rdapConformance",
        "lang",
        "secureDNS",
        "nameservers",
        "variants",
        "networks",
        "ipNetworks",
        "redacted",
        "subsetting_metadata",
        "errorCode",
        "title",
        "description",
        "termsOfService",
        "idnTableName",
        "idnTableId",
    }
)


def _as_list(value: Any) -> list[Any]:
    """Coerce an RDAP array member to a list without raising.

    Servers do send single strings where an array is specified, and hostile
    input must never escape the normalizer as a ``TypeError``.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _as_str_list(value: Any, *, split: bool = False) -> list[str]:
    out: list[str] = []
    for item in _as_list(value):
        if isinstance(item, str) and split:
            # "hreflang" is an array in RFC 9083 section 4.2 but arrives as a
            # comma-separated list when it comes from an HTTP header field.
            candidates: list[Any] = [
                token for token in re.split(r"[,\s]+", item) if token
            ]
        elif isinstance(item, (str, int, float)):
            candidates = [item]
        elif isinstance(item, dict):
            # Some registries wrap description text in an object; keep the text
            # rather than dropping the whole notice.
            candidates = [item.get("value") or item.get("text") or item.get("content")]
        else:
            candidates = []
        for candidate in candidates:
            text = _clean(candidate)
            if text and text not in out:
                out.append(text)
    return out


def _rdap_lang(value: Any, inherited: str | None) -> str | None:
    # RFC 9083 section 4.4 allows "lang" on any object class or data structure,
    # so the nearest enclosing value wins and outer values are inherited.
    text = _clean(value)
    return text if text is not None else inherited


def _rdap_truncation_scope(value: Any) -> str | None:
    """Classify a notice/remark ``type`` as truncation signalling (§9/§10.2.1)."""
    text = _clean(value)
    if text is None:
        return None
    lowered = text.lower()
    if lowered in RDAP_TRUNCATION_TYPES:
        return "result set" if lowered.startswith("result set") else "object"
    # Deployments have been observed writing "... unexplainable reason"
    # (singular) instead of the registered plural.
    if lowered.startswith("result set truncated"):
        return "result set"
    if lowered.startswith("object truncated"):
        return "object"
    return None


def _normalize_rdap_link(
    item: Any, *, scope: str, lang: str | None = None
) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    link: dict[str, Any] = {
        "value": _clean(item.get("value")),
        "rel": _clean(item.get("rel")),
        "href": _clean(item.get("href")),
        "type": _clean(item.get("type")),
        "media": _clean(item.get("media")),
        "title": _clean(item.get("title")),
        "hreflang": _as_str_list(item.get("hreflang"), split=True),
        "scope": scope,
        "lang": lang,
        # Set by _flag_self_duplicate_links() once the whole response is known.
        "self_duplicate": False,
    }
    link["complete"] = all(
        link[member] is not None for member in RDAP_LINK_REQUIRED_MEMBERS
    )
    extra = {key: value for key, value in item.items() if key not in RDAP_LINK_MEMBERS}
    if extra:
        link["extra"] = extra
    return link


def _normalize_rdap_links(
    value: Any, *, scope: str, lang: str | None = None
) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    for item in _as_list(value):
        link = _normalize_rdap_link(item, scope=scope, lang=lang)
        if link is not None:
            links.append(link)
    return links


def _normalize_rdap_notice(
    item: Any,
    *,
    kind: str,
    scope: str,
    lang: str | None = None,
) -> dict[str, Any] | None:
    """Normalize one entry of a "notices" or "remarks" array (RFC 9083 §4.3)."""
    coerced = not isinstance(item, dict)
    if coerced:
        text = _clean(item)
        if text is None:
            return None
        # A bare string still carries the human-readable text a client wants,
        # but it is not the structure RFC 9083 section 4.3 specifies.
        item = {"description": [text]}
    notice_lang = _rdap_lang(item.get("lang"), lang)
    label = _clean(item.get("title")) or _clean(item.get("type")) or "entry"
    notice: dict[str, Any] = {
        # "notice" describes the service or the whole response and belongs to
        # the topmost object; "remark" describes the object carrying it.
        "context": kind,
        "scope": scope,
        "title": _clean(item.get("title")),
        "type": _clean(item.get("type")),
        "description": _as_str_list(item.get("description")),
        "links": _normalize_rdap_links(
            item.get("links"), scope=f"{scope}/{kind}:{label}", lang=notice_lang
        ),
        "lang": notice_lang,
        "truncation": _rdap_truncation_scope(item.get("type")),
        # RFC 9083 section 4.3: "description" is the only mandatory member.
        "complete": isinstance(item.get("description"), list) and not coerced,
        "coerced": coerced,
    }
    extra = {
        key: value for key, value in item.items() if key not in RDAP_NOTICE_MEMBERS
    }
    if extra:
        notice["extra"] = extra
    return notice


def _variant_label(item: dict[str, Any]) -> str | None:
    # A variant object identifies itself through "variantNames" rather than a
    # name member of its own (RFC 9083 section 5.3).
    for entry in _as_list(item.get("variantNames")):
        if not isinstance(entry, dict):
            continue
        text = _clean(entry.get("ldhName") or entry.get("unicodeName"))
        if text:
            return text
    return None


def _rdap_scope_label(prefix: str, item: dict[str, Any], index: int) -> str:
    label = (
        _clean(item.get("handle"))
        or _clean(item.get("ldhName"))
        or _clean(item.get("unicodeName"))
        or _clean(item.get("name"))
        or _clean(item.get("ipAddress"))
        or _clean(item.get("startAddress"))
        or _variant_label(item)
    )
    return f"{prefix}:{label}" if label else f"{prefix}#{index}"


def _iter_rdap_objects(
    data: dict[str, Any],
    *,
    lang: str | None = None,
    max_depth: int = 2,
) -> list[tuple[dict[str, Any], str, str | None]]:
    """Walk nested object classes, yielding ``(object, scope, effective lang)``.

    Depth is bounded and objects already visited are skipped, so a crafted
    response with self-referencing ``entities`` cannot hang the client.
    """
    found: list[tuple[dict[str, Any], str, str | None]] = []
    seen: set[int] = {id(data)}

    def walk(container: Any, prefix: str, depth: int, parent_lang: str | None) -> None:
        if depth < 0:
            return
        for index, item in enumerate(_as_list(container)):
            if not isinstance(item, dict) or id(item) in seen:
                continue
            seen.add(id(item))
            item_lang = _rdap_lang(item.get("lang"), parent_lang)
            scope = _rdap_scope_label(prefix, item, index)
            found.append((item, scope, item_lang))
            walk(item.get("entities"), f"{scope}/entity", depth - 1, item_lang)

    walk(data.get("entities"), "entity", max_depth, lang)
    walk(data.get("nameservers"), "nameserver", 0, lang)
    walk(data.get("networks"), "network", 0, lang)
    walk(data.get("ipNetworks"), "network", 0, lang)
    walk(data.get("variants"), "variant", 0, lang)
    # A search response carries one object instance per result (RFC 9083
    # section 8), and each of those instances may carry its own notices,
    # remarks, links and "redacted" member.
    for key, value in list(data.items()):
        if key.endswith("SearchResults"):
            walk(value, "search", 1, lang)
    return found


def _collect_rdap_notices(
    data: dict[str, Any], *, lang: str | None = None
) -> list[dict[str, Any]]:
    """Collect notices and remarks from the top object and nested object classes."""
    out: list[dict[str, Any]] = []
    pairs = (("notice", "notices"), ("remark", "remarks"))
    for kind, member in pairs:
        for item in _as_list(data.get(member)):
            notice = _normalize_rdap_notice(item, kind=kind, scope="top", lang=lang)
            if notice is not None:
                out.append(notice)
    for obj, scope, obj_lang in _iter_rdap_objects(data, lang=lang):
        for kind, member in pairs:
            for item in _as_list(obj.get(member)):
                notice = _normalize_rdap_notice(
                    item, kind=kind, scope=scope, lang=obj_lang
                )
                if notice is not None:
                    out.append(notice)
    return out


def _collect_rdap_links(
    data: dict[str, Any], *, lang: str | None = None
) -> list[dict[str, Any]]:
    """Collect the links of the top object and of nested object classes.

    Links carried inside a notice stay inside that notice; they are reachable
    through :meth:`RegistrationRecord.links_for` with ``include_notice_links``.
    """
    out = _normalize_rdap_links(data.get("links"), scope="top", lang=lang)
    for obj, scope, obj_lang in _iter_rdap_objects(data, lang=lang):
        out.extend(_normalize_rdap_links(obj.get("links"), scope=scope, lang=obj_lang))
    return out


def _collect_rdap_redacted(
    data: dict[str, Any], *, lang: str | None = None
) -> list[dict[str, Any]]:
    """Collect "redacted" members of the top object and of nested object instances."""
    out = _normalize_rdap_redacted(data.get("redacted"), scope="top", lang=lang)
    for obj, scope, obj_lang in _iter_rdap_objects(data, lang=lang):
        out.extend(
            _normalize_rdap_redacted(obj.get("redacted"), scope=scope, lang=obj_lang)
        )
    return out


def _rdap_truncation(notices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Project the truncation-signalling entries of a normalized notice list."""
    return [
        {
            "scope": notice["scope"],
            "context": notice["context"],
            "type": notice["type"],
            "truncation": notice["truncation"],
            "title": notice["title"],
            "description": list(notice["description"]),
            "links": list(notice["links"]),
        }
        for notice in notices
        if notice.get("truncation")
    ]


def _normalize_rdap_redacted(
    value: Any,
    *,
    scope: str,
    lang: str | None = None,
) -> list[dict[str, Any]]:
    """Normalize a "redacted" member (RFC 9537 section 4.2).

    The paths are kept as opaque strings: evaluating JSONPath expressions is
    left to callers that actually need it, while the reason, method, and
    registered name are what makes redaction visible to a consumer.
    """
    out: list[dict[str, Any]] = []
    known = {
        "name",
        "prePath",
        "postPath",
        "replacementPath",
        "pathLang",
        "method",
        "reason",
        "lang",
    }
    for entry in _as_list(value):
        if not isinstance(entry, dict):
            continue
        entry_lang = _rdap_lang(entry.get("lang"), lang)
        name = entry.get("name") if isinstance(entry.get("name"), dict) else {}
        if not name and entry.get("name") is not None:
            name = {"description": _clean(entry.get("name"))}
        reason = entry.get("reason") if isinstance(entry.get("reason"), dict) else {}
        if not reason and entry.get("reason") is not None:
            reason = {"description": _clean(entry.get("reason"))}
        method = _clean(entry.get("method"))
        pre_path = _clean(entry.get("prePath"))
        post_path = _clean(entry.get("postPath"))
        item: dict[str, Any] = {
            "scope": scope,
            "lang": entry_lang,
            # "type" carries a registered redacted name, "description" an
            # unregistered one; a server may send either or both.
            "name_type": _clean(name.get("type")),
            "name_description": _clean(name.get("description")),
            "pre_path": pre_path,
            "post_path": post_path,
            "replacement_path": _clean(entry.get("replacementPath")),
            "path_lang": _clean(entry.get("pathLang")) or RDAP_DEFAULT_PATH_LANG,
            # RFC 9537: an absent "method" means removal.
            "method": method
            if method in RDAP_REDACTION_METHODS
            else RDAP_DEFAULT_REDACTION_METHOD,
            "unknown_method": method
            if method and method not in RDAP_REDACTION_METHODS
            else None,
            "reason_type": _clean(reason.get("type")),
            "reason_description": _clean(reason.get("description")),
            # prePath and postPath are mutually exclusive (section 4.2); a server
            # that sets both is wrong, and the entry is flagged rather than dropped.
            "path_conflict": bool(pre_path and post_path),
            "complete": bool(
                _clean(name.get("type")) or _clean(name.get("description"))
            ),
        }
        extra = {key: val for key, val in entry.items() if key not in known}
        if extra:
            item["extra"] = extra
        out.append(item)
    return out


def _normalize_rdap_subsetting(
    value: Any, *, lang: str | None = None
) -> dict[str, Any] | None:
    """Normalize the "subsetting_metadata" member of a partial response (RFC 8982)."""
    if not isinstance(value, dict):
        return None
    available: list[dict[str, Any]] = []
    for entry in _as_list(value.get("availableFieldSets")):
        if not isinstance(entry, dict):
            continue
        default = entry.get("default")
        available.append(
            {
                # "name" is required and "default" is required per field set;
                # exactly one field set may be flagged as the default.
                "name": _clean(entry.get("name")),
                "default": bool(default) if default is not None else None,
                "description": _clean(entry.get("description")),
                "links": _normalize_rdap_links(
                    entry.get("links"),
                    scope=f"subsetting:{_clean(entry.get('name')) or 'fieldSet'}",
                    lang=lang,
                ),
            }
        )
    current = _clean(value.get("currentFieldSet"))
    out: dict[str, Any] = {
        "current_field_set": current,
        "available_field_sets": available,
        "default_field_sets": sorted(
            {str(a["name"]) for a in available if a.get("default") and a.get("name")}
        ),
        "complete": current is not None,
    }
    extra = {
        key: val
        for key, val in value.items()
        if key not in {"currentFieldSet", "availableFieldSets"}
    }
    if extra:
        out["extra"] = extra
    return out


def _flag_self_duplicate_links(links: list[dict[str, Any]]) -> None:
    """Flag "related" links that repeat a "self" href.

    RFC 9083 section 4.2 forbids a "related" link whose href equals the "self"
    href of the same response, because following it can put a client in a
    processing loop. Such links are kept but marked, so referral walking skips
    them. The "self" hrefs of the whole response are considered, which is
    deliberately conservative for links found inside nested objects.
    """
    self_hrefs = {
        link["href"]
        for link in links
        if str(link.get("rel") or "").lower() == "self" and link.get("href")
    }
    if not self_hrefs:
        return
    for link in links:
        rel = str(link.get("rel") or "").lower()
        link["self_duplicate"] = bool(
            rel == "related" and link.get("href") in self_hrefs
        )


def from_rdap(data: dict[str, Any]) -> RegistrationRecord:
    raw = data
    if not isinstance(data, dict):
        # Hostile or truncated servers can return a JSON array or scalar at the
        # top level; keep it in ``raw`` and normalize an empty object instead.
        data = {}
    record = RegistrationRecord(source="rdap", raw=raw)
    record.kind = _clean(data.get("objectClassName"))
    # RFC 9083 section 4.4: "lang" may appear anywhere, so the top-level value
    # acts as the default for the structures below it.
    record.lang = _clean(data.get("lang"))
    # RFC 9083 section 4.1: "rdapConformance" only ever appears in the topmost
    # object; extra identifiers name registered extensions of the response.
    record.conformance = _as_str_list(data.get("rdapConformance"))
    record.identifier = _clean(
        data.get("ldhName")
        or data.get("unicodeName")
        or data.get("ipAddress")
        or data.get("startAddress")
        or data.get("name")
        or data.get("handle")
    )
    record.handle = _clean(data.get("handle"))
    # RFC 9083 section 4.6 says "status" is an array; servers that send a bare
    # string are read as one value rather than shattered into characters.
    record.statuses = _as_str_list(data.get("status"))
    nameservers: list[str] = []
    for entry in _as_list(data.get("nameservers")):
        # The normal case is a nameserver object with "ldhName"/"unicodeName"
        # (RFC 9083 section 5.3); a plain string is tolerated rather than lost.
        value = (
            (entry.get("ldhName") or entry.get("unicodeName"))
            if isinstance(entry, dict)
            else entry
        )
        text = _clean(value)
        if text and text not in nameservers:
            nameservers.append(text)
    record.nameservers = nameservers
    record.port43 = _clean(data.get("port43"))
    record.notices = _collect_rdap_notices(data, lang=record.lang)
    record.links = _collect_rdap_links(data, lang=record.lang)
    _flag_self_duplicate_links(record.links)
    # RFC 9537: servers that redact response fields list them in "redacted".
    record.redacted = _collect_rdap_redacted(data, lang=record.lang)
    # RFC 8982: a partial response produced through the "fieldSet" query
    # parameter describes itself in "subsetting_metadata".
    record.subsetting = _normalize_rdap_subsetting(
        data.get("subsetting_metadata"), lang=record.lang
    )
    # RFC 9083 section 9: a server marks a partial response with a typed notice
    # or remark, so truncation is a property of the body rather than of HTTP.
    record.truncation = _rdap_truncation(record.notices)
    record.truncated = bool(record.truncation)
    dnssec = data.get("secureDNS")
    # RECORD_TYPES requires a mapping; a server that sends a bare value gets it
    # preserved under "raw" instead of producing a record that fails validation.
    record.dnssec = (
        dnssec if dnssec is None or isinstance(dnssec, dict) else {"raw": dnssec}
    )
    networks: list[dict[str, Any]] = []
    for entry in _as_list(data.get("networks")):
        if isinstance(entry, dict):
            networks.append(entry)
            continue
        text = _clean(entry)
        if text:
            # A bare string still names something, and the record schema only
            # allows network objects here.
            networks.append({"name": text})
    record.networks = networks
    record.context = {
        # Identifiers beyond "rdap_level_0" name registered extensions whose JSON
        # members may not be modelled here (RFC 9083 section 4.1).
        "extensions": [
            token
            for token in record.conformance
            if token.lower() != RDAP_BASE_CONFORMANCE
        ],
        "unmodelled_members": sorted(
            key for key in data if key not in _RDAP_MODELLED_MEMBERS
        ),
    }

    for event in data.get("events") or []:
        if not isinstance(event, dict):
            continue
        action = _clean(event.get("eventAction"))
        date = _clean(event.get("eventDate"))
        if action and date:
            normalized = _date_to_iso(date)
            record.events.append(
                {
                    "action": action,
                    "eventAction": action,
                    "date": normalized["date"],
                    "eventDate": normalized["date"],
                    "raw_date": normalized["raw_date"],
                    "actor": _clean(event.get("eventActor")),
                }
            )

    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        vcard_data = (
            entity.get("vcardArray")
            if isinstance(entity.get("vcardArray"), list)
            else None
        )
        parsed = _parse_vcard(vcard_data)
        contact = {
            "roles": [str(r) for r in (entity.get("roles") or []) if _clean(r)],
            "handle": _clean(entity.get("handle")),
        }
        contact.update({k: v for k, v in parsed.items() if v})
        if (
            contact["roles"]
            or contact["handle"]
            or contact.get("name")
            or contact.get("emails")
        ):
            record.contacts.append(contact)

    registrar_entity = None
    for entity in data.get("entities") or []:
        if isinstance(entity, dict) and "registrar" in [
            str(r).lower() for r in (entity.get("roles") or [])
        ]:
            registrar_entity = entity
            break
    if registrar_entity is not None:
        parsed = _parse_vcard(registrar_entity.get("vcardArray"))
        public_id = None
        for item in registrar_entity.get("publicIds") or []:
            if isinstance(item, dict) and item.get("type") == "IANA Registrar ID":
                public_id = _clean(item.get("identifier"))
                break
        record.registrar = {
            "name": parsed.get("name") or _clean(registrar_entity.get("handle")),
            "iana_id": public_id,
            "handle": _clean(registrar_entity.get("handle")),
        }
    return record


def from_whois_fields(
    fields: dict[str, list[str]],
    *,
    resource: str | None = None,
    kind: str | None = None,
    source: str = "whois",
) -> RegistrationRecord:
    lowered = {k.lower().strip(): v for k, v in fields.items()}
    kind = _clean(kind)
    if not kind:
        if _first(lowered.get("domain name", [])) or _first(lowered.get("domain", [])):
            kind = "domain"
        elif (
            _first(lowered.get("network name", []))
            or _first(lowered.get("netname", []))
            or _first(lowered.get("networkname", []))
        ):
            kind = "network"
        elif any(k.startswith("asn") for k in lowered):
            kind = "autnum"
        else:
            kind = "unknown"

    record = RegistrationRecord(
        source=source,
        kind=kind,
        raw=fields,
        identifier=_first(lowered.get("domain name", []))
        or _first(lowered.get("domain", []))
        or _clean(resource),
    )

    statuses: list[str] = []
    for key in _STATUS_KEY:
        statuses.extend(_split_values(lowered.get(key, [])))
    record.statuses = list(dict.fromkeys(statuses))

    for action, keys in _DATE_KEYS.items():
        for key in keys:
            value = _first(lowered.get(key, []))
            if value:
                normalized = _date_to_iso(value)
                record.events.append(
                    {
                        "action": action,
                        "date": normalized["date"],
                        "raw_date": normalized["raw_date"],
                        "actor": None,
                    }
                )
                break

    ns_values: list[str] = []
    for key in _NAMESERVER_KEYS:
        ns_values.extend(_split_values(lowered.get(key, [])))
    record.nameservers = [x.lower() for x in dict.fromkeys(ns_values)]

    dnssec = _first(lowered.get("dnssec", []))
    if dnssec:
        record.dnssec = {
            "raw": dnssec,
            "signed": "signed" in dnssec.lower() or "delegated" in dnssec.lower(),
        }

    registrar_name = _first(lowered.get("registrar", []))
    registrar_iana = _first(lowered.get("registrar iana id", [])) or _first(
        lowered.get("iana id", [])
    )
    registrar_url = _first(lowered.get("registrar url", [])) or _first(
        lowered.get("registrar website", [])
    )
    record.port43 = _first(lowered.get("registrar whois server", [])) or _first(
        lowered.get("whois server", [])
    )
    if registrar_name or registrar_iana or registrar_url or record.port43:
        record.registrar = {
            "name": registrar_name,
            "iana_id": registrar_iana,
            "url": registrar_url,
            "whois_server": record.port43,
        }

    roles: dict[str, dict[str, Any]] = {}
    for key, values in lowered.items():
        lowered_key = key.lower()
        role = next((r for r in _ROLE_PATTERNS if r in lowered_key), None)
        if not role:
            continue
        if role in {"tech", "technical"}:
            role = "technical"
        contact = roles.setdefault(role, {"roles": [role]})
        value = _first(values)
        if not value:
            continue
        if "email" in lowered_key:
            emails = contact.setdefault("emails", [])
            if value not in emails:
                emails.append(value)
        elif "phone" in lowered_key or "fax" in lowered_key:
            phones = contact.setdefault("phones", [])
            if value not in phones:
                phones.append(value)
        elif "name" in lowered_key:
            contact["name"] = contact.get("name") or value
        elif "organization" in lowered_key:
            contact["organization"] = contact.get("organization") or value
        elif "handle" in lowered_key or "id" in lowered_key:
            contact["handle"] = contact.get("handle") or value
    record.contacts = list(roles.values())

    network = (
        _first(lowered.get("network name", []))
        or _first(lowered.get("netname", []))
        or _first(lowered.get("networkname", []))
    )
    if network:
        record.networks = [{"name": network}]
    return record


def from_rwhois_object(obj: Any, *, source: str = "rwhois") -> RegistrationRecord:
    obj_data = obj.as_dict() if hasattr(obj, "as_dict") else obj
    kind = (
        getattr(obj, "class_name", None)
        or _first(obj_data.get("Class-Name", []))
        or "unknown"
    )
    identifier = getattr(obj, "get", lambda *_: None)("ID") or _first(
        obj_data.get("ID", [])
    )
    record = RegistrationRecord(
        source=source,
        kind=str(kind).lower(),
        identifier=_clean(identifier),
        handle=_clean(identifier),
        raw=obj_data,
    )
    updated = getattr(obj, "get", lambda *_: None)("Updated") or _first(
        obj_data.get("Updated", [])
    )
    if updated:
        normalized = _date_to_iso(str(updated))
        record.events.append({"action": "last changed", **normalized, "actor": None})

    nameservers: list[str] = []
    for attr in ("Server", "Nameserver", "Name-Server", "Host-Name"):
        values = getattr(obj, "getall", lambda *_: [])
        nameservers.extend(values(attr))
    record.nameservers = list(dict.fromkeys(str(v) for v in nameservers if _clean(v)))

    contacts: dict[str, dict[str, Any]] = {}
    for attr in (
        "Admin-Contact",
        "Tech-Contact",
        "Billing-Contact",
        "Abuse-Contact",
        "Org-Tech",
        "Guardian",
    ):
        values = getattr(obj, "getall", lambda *_: [])(attr)
        if not values:
            continue
        role = {
            "Admin-Contact": "administrative",
            "Tech-Contact": "technical",
            "Billing-Contact": "billing",
            "Abuse-Contact": "abuse",
            "Org-Tech": "technical",
            "Guardian": "guardian",
        }.get(attr, attr.lower())
        contact = contacts.setdefault(role, {"roles": [role], "handle": None})
        handles = contact.setdefault("handles", [])
        for value in values:
            if value not in handles:
                handles.append(value)
        contact["handle"] = contact["handle"] or values[0]
    record.contacts = list(contacts.values())
    return record


__all__ = [
    "RDAP_BASE_CONFORMANCE",
    "RDAP_DEFAULT_PATH_LANG",
    "RDAP_DEFAULT_REDACTION_METHOD",
    "RDAP_LINK_MEMBERS",
    "RDAP_LINK_REQUIRED_MEMBERS",
    "RDAP_NOTICE_MEMBERS",
    "RDAP_REDACTED_CONFORMANCE",
    "RDAP_REDACTION_METHODS",
    "RDAP_SUBSETTING_CONFORMANCE",
    "RDAP_TRUNCATION_TYPES",
    "RegistrationRecord",
    "from_rdap",
    "from_rwhois_object",
    "from_whois_fields",
]
