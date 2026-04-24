import pytest

from lldp_tool.packets import (
    LLDP_DESTINATION_MAC,
    LLDP_ETHERTYPE,
    PacketBuildError,
    build_lldpdu_frame,
    parse_ethernet_frame,
)


def test_build_lldpdu_frame_wraps_payload_with_lldp_ethernet_header():
    lldpdu = bytes.fromhex("0207040011223344550403020006")

    packet = build_lldpdu_frame(lldpdu=lldpdu, source_mac="74-13-EA-66-33-E8")

    assert packet.dst_mac == LLDP_DESTINATION_MAC
    assert packet.src_mac == "74:13:ea:66:33:e8"
    assert packet.ethertype == LLDP_ETHERTYPE
    assert packet.lldpdu == lldpdu
    assert packet.full_frame == bytes.fromhex("0180c200000e7413ea6633e888cc") + lldpdu


def test_parse_ethernet_frame_extracts_header_and_lldpdu():
    frame = bytes.fromhex("0180c200000e7413ea6633e888cc020704001122334455")

    packet = parse_ethernet_frame(frame)

    assert packet.dst_mac == "01:80:c2:00:00:0e"
    assert packet.src_mac == "74:13:ea:66:33:e8"
    assert packet.ethertype == LLDP_ETHERTYPE
    assert packet.lldpdu == bytes.fromhex("020704001122334455")
    assert packet.full_frame == frame


@pytest.mark.parametrize(
    ("frame", "message"),
    [
        (bytes.fromhex("0180c200000e"), "14"),
        (bytes.fromhex("0180c200000e7413ea6633e80800"), "LLDP"),
    ],
)
def test_parse_ethernet_frame_rejects_invalid_lldp_frames(frame, message):
    with pytest.raises(PacketBuildError) as exc_info:
        parse_ethernet_frame(frame)

    assert message in str(exc_info.value)


@pytest.mark.parametrize("source_mac", ["", "zz:13:ea:66:33:e8", "74:13:ea:66:33"])
def test_build_lldpdu_frame_rejects_invalid_source_mac(source_mac):
    with pytest.raises(PacketBuildError) as exc_info:
        build_lldpdu_frame(lldpdu=b"\x00\x00", source_mac=source_mac)

    assert "MAC" in str(exc_info.value)


def test_build_lldpdu_frame_rejects_empty_lldpdu():
    with pytest.raises(PacketBuildError) as exc_info:
        build_lldpdu_frame(lldpdu=b"", source_mac="74:13:ea:66:33:e8")

    assert "空" in str(exc_info.value)
