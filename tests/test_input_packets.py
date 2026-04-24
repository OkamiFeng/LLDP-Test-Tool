import pytest

from lldp_tool.input_packets import InputMode, build_packet_from_input
from lldp_tool.packets import LLDP_ETHERTYPE, PacketBuildError


def test_build_packet_from_input_wraps_lldpdu_mode():
    packet = build_packet_from_input(
        mode=InputMode.LLDPDU,
        data=bytes.fromhex("020704001122334455"),
        source_mac="74:13:ea:66:33:e8",
    )

    assert packet.ethertype == LLDP_ETHERTYPE
    assert packet.full_frame.startswith(bytes.fromhex("0180c200000e7413ea6633e888cc"))


def test_build_packet_from_input_parses_frame_mode():
    frame = bytes.fromhex("0180c200000e7413ea6633e888cc020704001122334455")

    packet = build_packet_from_input(
        mode=InputMode.ETHERNET_FRAME,
        data=frame,
        source_mac=None,
    )

    assert packet.full_frame == frame
    assert packet.lldpdu == bytes.fromhex("020704001122334455")


def test_build_packet_from_input_rejects_unknown_mode():
    with pytest.raises(PacketBuildError) as exc_info:
        build_packet_from_input(mode="unknown", data=b"\x00\x00", source_mac=None)

    assert "入力モード" in str(exc_info.value)
