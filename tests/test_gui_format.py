from datetime import datetime

from lldp_tool.gui import format_periodic_send_status, format_received_packet
from lldp_tool.packets import parse_ethernet_frame


def test_format_received_packet_uses_japanese_labels():
    packet = parse_ethernet_frame(
        bytes.fromhex("0180c200000e7413ea6633e888cc020704001122334455")
    )

    text = format_received_packet(
        packet=packet,
        adapter_name="eth0",
        received_at=datetime(2026, 4, 24, 12, 34, 56),
    )

    assert "受信時刻: 2026-04-24 12:34:56" in text
    assert "インターフェース: eth0" in text
    assert "送信元MAC: 74:13:ea:66:33:e8" in text
    assert "EtherType: 0x88CC" in text
    assert "Ethernet Frame:" in text
    assert "LLDPDU:" in text


def test_format_periodic_send_status_includes_counter_value():
    text = format_periodic_send_status(send_count=2, counter_value=0x02, sent_bytes=64)

    assert "周期送信 2回目に成功しました。" in text
    assert "反映byte値: 0x02" in text
    assert "送信byte数: 64" in text


def test_format_periodic_send_status_omits_counter_when_disabled():
    text = format_periodic_send_status(send_count=1, counter_value=None, sent_bytes=32)

    assert "周期送信 1回目に成功しました。" in text
    assert "反映byte値" not in text
    assert "送信byte数: 32" in text
