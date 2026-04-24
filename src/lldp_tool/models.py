from dataclasses import dataclass


@dataclass(frozen=True)
class PacketBytes:
    full_frame: bytes
    lldpdu: bytes
    src_mac: str
    dst_mac: str
    ethertype: int


@dataclass(frozen=True)
class AdapterInfo:
    name: str
    display_name: str
    mac: str | None
    status: str
