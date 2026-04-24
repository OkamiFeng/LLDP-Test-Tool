import pytest

from lldp_tool.input_packets import InputMode
from lldp_tool.periodic import (
    CounterByteRule,
    PeriodicConfigError,
    PeriodicSendConfig,
    apply_counter_byte,
)


@pytest.mark.parametrize("interval", [1, 3600])
def test_periodic_config_accepts_valid_interval(interval):
    config = PeriodicSendConfig(
        interval_seconds=interval,
        mode=InputMode.LLDPDU,
        input_data=b"\x00\x00",
        source_mac="74:13:ea:66:33:e8",
        adapter_name="eth0",
    )

    assert config.interval_seconds == interval


@pytest.mark.parametrize("interval", [0, 3601])
def test_periodic_config_rejects_invalid_interval(interval):
    with pytest.raises(PeriodicConfigError) as exc_info:
        PeriodicSendConfig(
            interval_seconds=interval,
            mode=InputMode.LLDPDU,
            input_data=b"\x00\x00",
            source_mac="74:13:ea:66:33:e8",
            adapter_name="eth0",
        )

    assert "周期" in str(exc_info.value)


def test_apply_counter_byte_uses_one_based_position():
    updated, value = apply_counter_byte(
        b"\x10\x20\x30\x40",
        CounterByteRule(position=3, start_value=0x01),
        send_count=1,
    )

    assert updated == b"\x10\x20\x01\x40"
    assert value == 0x01


@pytest.mark.parametrize(
    ("send_count", "expected"),
    [(1, 0x01), (2, 0x02), (3, 0x03)],
)
def test_counter_byte_rule_increments_from_start_value(send_count, expected):
    updated, value = apply_counter_byte(
        b"\x00",
        CounterByteRule(position=1, start_value=0x01),
        send_count=send_count,
    )

    assert updated == bytes([expected])
    assert value == expected


@pytest.mark.parametrize(
    ("send_count", "expected"),
    [(1, 0xFE), (2, 0xFF), (3, 0x00)],
)
def test_counter_byte_rule_wraps_after_ff(send_count, expected):
    updated, value = apply_counter_byte(
        b"\x00",
        CounterByteRule(position=1, start_value=0xFE),
        send_count=send_count,
    )

    assert updated == bytes([expected])
    assert value == expected


def test_apply_counter_byte_rejects_position_outside_input():
    with pytest.raises(PeriodicConfigError) as exc_info:
        apply_counter_byte(
            b"\x00\x01",
            CounterByteRule(position=3, start_value=0x01),
            send_count=1,
        )

    assert "対象byte位置" in str(exc_info.value)


def test_periodic_lldpdu_mode_applies_counter_before_wrapping_frame():
    config = PeriodicSendConfig(
        interval_seconds=1,
        mode=InputMode.LLDPDU,
        input_data=bytes.fromhex("020704001122334455"),
        source_mac="74:13:ea:66:33:e8",
        adapter_name="eth0",
        counter_enabled=True,
        counter_rule=CounterByteRule(position=3, start_value=0x7A),
    )

    result = config.packet_for_send(send_count=1)

    assert result.counter_value == 0x7A
    assert result.packet.full_frame.startswith(bytes.fromhex("0180c200000e7413ea6633e888cc"))
    assert result.packet.lldpdu == bytes.fromhex("02077a001122334455")


def test_periodic_ethernet_frame_mode_applies_counter_to_full_frame():
    frame = bytes.fromhex("0180c200000e7413ea6633e888cc020704001122334455")
    config = PeriodicSendConfig(
        interval_seconds=1,
        mode=InputMode.ETHERNET_FRAME,
        input_data=frame,
        source_mac=None,
        adapter_name="eth0",
        counter_enabled=True,
        counter_rule=CounterByteRule(position=3, start_value=0x7A),
    )

    result = config.packet_for_send(send_count=1)

    assert result.counter_value == 0x7A
    assert result.packet.full_frame == bytes.fromhex(
        "01807a00000e7413ea6633e888cc020704001122334455"
    )
