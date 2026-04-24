from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import AdapterInfo
from .packets import PacketBuildError, normalize_mac


def _record_value(record: Any, key: str, default: str | None = None) -> Any:
    if isinstance(record, Mapping):
        return record.get(key, default)
    return getattr(record, key, default)


def adapter_info_from_record(record: Any) -> AdapterInfo:
    name = str(_record_value(record, "name", "") or "")
    description = str(
        _record_value(record, "description", None)
        or _record_value(record, "display_name", None)
        or name
    )
    raw_mac = _record_value(record, "mac", None)
    status = str(_record_value(record, "status", "利用可能") or "利用可能")

    mac: str | None
    if raw_mac:
        try:
            mac = normalize_mac(str(raw_mac))
        except PacketBuildError:
            mac = None
            status = "MAC形式エラー"
    else:
        mac = None
        if status == "利用可能":
            status = "MACなし"

    return AdapterInfo(
        name=name,
        display_name=description,
        mac=mac,
        status=status,
    )


def format_adapter_label(adapter: AdapterInfo) -> str:
    mac_text = adapter.mac if adapter.mac else "MACなし"
    if adapter.display_name and adapter.display_name != adapter.name:
        return f"{adapter.display_name} ({adapter.name}) - {mac_text}"
    return f"{adapter.name} - {mac_text}"
