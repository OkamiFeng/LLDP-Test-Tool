from __future__ import annotations

import re

from .models import PacketBytes


LLDP_DESTINATION_MAC = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88CC
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class PacketBuildError(ValueError):
    """Raised when packet bytes cannot be built or interpreted as LLDP."""


def normalize_mac(mac: str) -> str:
    mac_text = mac.strip().lower().replace("-", ":")
    if not _MAC_RE.match(mac_text):
        raise PacketBuildError("MACアドレスの形式が正しくありません。")
    return mac_text


def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(normalize_mac(mac).replace(":", ""))


def bytes_to_mac(raw: bytes) -> str:
    if len(raw) != 6:
        raise PacketBuildError("MACアドレスは6byteである必要があります。")
    return ":".join(f"{byte:02x}" for byte in raw)


def build_lldpdu_frame(lldpdu: bytes, source_mac: str) -> PacketBytes:
    if not lldpdu:
        raise PacketBuildError("LLDPDUが空です。")

    src_mac = normalize_mac(source_mac)
    dst_mac = LLDP_DESTINATION_MAC
    header = (
        mac_to_bytes(dst_mac)
        + mac_to_bytes(src_mac)
        + LLDP_ETHERTYPE.to_bytes(2, byteorder="big")
    )
    full_frame = header + lldpdu

    return PacketBytes(
        full_frame=full_frame,
        lldpdu=lldpdu,
        src_mac=src_mac,
        dst_mac=dst_mac,
        ethertype=LLDP_ETHERTYPE,
    )


def parse_ethernet_frame(frame: bytes) -> PacketBytes:
    if len(frame) < 14:
        raise PacketBuildError("Ethernet Frameは14byte以上である必要があります。")

    dst_mac = bytes_to_mac(frame[0:6])
    src_mac = bytes_to_mac(frame[6:12])
    ethertype = int.from_bytes(frame[12:14], byteorder="big")
    if ethertype != LLDP_ETHERTYPE:
        raise PacketBuildError("EtherTypeがLLDP(0x88cc)ではありません。")

    lldpdu = frame[14:]
    if not lldpdu:
        raise PacketBuildError("LLDPDUが空です。")

    return PacketBytes(
        full_frame=frame,
        lldpdu=lldpdu,
        src_mac=src_mac,
        dst_mac=dst_mac,
        ethertype=ethertype,
    )
