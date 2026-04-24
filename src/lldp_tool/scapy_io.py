from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from .adapters import adapter_info_from_record
from .models import AdapterInfo, PacketBytes
from .packets import PacketBuildError, parse_ethernet_frame


class ScapyRuntimeError(RuntimeError):
    """Raised when the Scapy/Npcap runtime cannot complete an operation."""


def _load_scapy_api() -> Any:
    try:
        from scapy.all import Ether, conf, sendp, sniff
    except ImportError as exc:
        raise ScapyRuntimeError("Scapy が見つかりません。依存関係をインストールしてください。") from exc
    return SimpleNamespace(Ether=Ether, conf=conf, sendp=sendp, sniff=sniff)


class ScapyLldpRuntime:
    def __init__(self, scapy_api: Any | None = None):
        self._scapy_api = scapy_api

    @property
    def api(self) -> Any:
        if self._scapy_api is None:
            self._scapy_api = _load_scapy_api()
        return self._scapy_api

    def list_adapters(self) -> list[AdapterInfo]:
        try:
            raw_interfaces = self.api.conf.ifaces.values()
            return [adapter_info_from_record(record) for record in raw_interfaces]
        except ScapyRuntimeError:
            raise
        except Exception as exc:
            raise ScapyRuntimeError(f"ネットワークアダプターの取得に失敗しました: {exc}") from exc

    def send_frame(self, interface_name: str, frame: bytes) -> None:
        try:
            packet = self.api.Ether(frame)
            self.api.sendp(packet, iface=interface_name, verbose=False)
        except ScapyRuntimeError:
            raise
        except Exception as exc:
            raise ScapyRuntimeError(f"送信に失敗しました: {exc}") from exc

    def sniff_once(self, interface_name: str, timeout: float = 1.0) -> list[PacketBytes]:
        try:
            packets = self.api.sniff(
                iface=interface_name,
                filter="ether proto 0x88cc",
                timeout=timeout,
                store=True,
            )
        except ScapyRuntimeError:
            raise
        except Exception as exc:
            raise ScapyRuntimeError(f"受信に失敗しました: {exc}") from exc

        lldp_packets: list[PacketBytes] = []
        for packet in packets:
            try:
                lldp_packets.append(parse_ethernet_frame(bytes(packet)))
            except PacketBuildError:
                continue
        return lldp_packets
