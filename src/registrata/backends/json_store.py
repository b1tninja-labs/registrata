"""Load and save :class:`MemoryBackend` contents as JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..records import ObjectRecord
from .memory import MemoryBackend


def save_memory_backend(backend: MemoryBackend, path: str | Path) -> None:
    data: dict[str, Any] = {
        "default_auth_area": backend.default_auth_area,
        "authority_areas": {
            area: {
                "authority": soa.authority,
                "ttl": soa.ttl,
                "serial": soa.serial,
                "refresh": soa.refresh,
                "increment": soa.increment,
                "retry": soa.retry,
                "tech_contact": soa.tech_contact,
                "admin_contact": soa.admin_contact,
                "hostmaster": soa.hostmaster,
                "primary": soa.primary,
                "extra": soa.extra,
            }
            for area, soa in backend.authority_areas.items()
        },
        "objects": {
            area: [
                {
                    "class_name": obj.class_name,
                    "attributes": [
                        {"name": attr.name, "value": attr.value, "type": attr.type}
                        for attr in obj.attributes
                    ],
                }
                for obj in objs
            ]
            for area, objs in backend.objects.items()
        },
        "referrals": [
            {
                "referred_auth_area": rule.referred_auth_area,
                "host": rule.host,
                "port": rule.port,
                "auth_area": rule.auth_area,
                "kind": rule.kind,
            }
            for rule in backend.referral_rules
        ],
        "auth_passwords": sorted(backend.auth_passwords),
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_memory_backend(path: str | Path) -> MemoryBackend:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    backend = MemoryBackend(data.get("default_auth_area"))
    for area, soa_data in data.get("authority_areas", {}).items():
        kwargs = {k: v for k, v in soa_data.items() if k != "authority"}
        backend.add_soa(area, **kwargs)
    for area, obj_data_list in data.get("objects", {}).items():
        for obj_data in obj_data_list:
            obj = ObjectRecord(obj_data["class_name"], [])
            for attr_data in obj_data["attributes"]:
                obj.add(
                    attr_data["name"], attr_data["value"], attr_data.get("type", "T")
                )
            backend.add_object(obj.class_name, obj, auth_area=area)
    for rule_data in data.get("referrals", []):
        backend.add_referral(**rule_data)
    for password in data.get("auth_passwords", []):
        backend.add_password(password)
    return backend


__all__ = ["load_memory_backend", "save_memory_backend"]
