from __future__ import annotations

from enum import StrEnum

from .models import PacketBytes
from .packets import PacketBuildError, build_lldpdu_frame, parse_ethernet_frame


class InputMode(StrEnum):
    LLDPDU = "LLDPDUのみ"
    ETHERNET_FRAME = "Ethernet Frame"


def build_packet_from_input(
    mode: InputMode | str,
    data: bytes,
    source_mac: str | None,
) -> PacketBytes:
    try:
        input_mode = InputMode(mode)
    except ValueError as exc:
        raise PacketBuildError("入力モードが正しくありません。") from exc

    if input_mode == InputMode.LLDPDU:
        if not source_mac:
            raise PacketBuildError("送信元MACアドレスを取得できません。")
        return build_lldpdu_frame(lldpdu=data, source_mac=source_mac)

    if input_mode == InputMode.ETHERNET_FRAME:
        return parse_ethernet_frame(data)

    raise PacketBuildError("入力モードが正しくありません。")
