from __future__ import annotations

from dataclasses import dataclass

from .input_packets import InputMode, build_packet_from_input
from .models import PacketBytes


class PeriodicConfigError(ValueError):
    """周期送信設定の検証エラー。"""


@dataclass(frozen=True)
class CounterByteRule:
    position: int
    start_value: int

    def __post_init__(self) -> None:
        if self.position < 1:
            raise PeriodicConfigError("対象byte位置は1以上で指定してください。")
        if self.start_value < 0 or self.start_value > 0xFF:
            raise PeriodicConfigError("開始値は0x00から0xFFで指定してください。")

    def value_for_send(self, send_count: int) -> int:
        if send_count < 1:
            raise PeriodicConfigError("送信回数は1以上で指定してください。")
        return (self.start_value + send_count - 1) % 256


@dataclass(frozen=True)
class PeriodicSendResult:
    packet: PacketBytes
    counter_value: int | None


@dataclass(frozen=True)
class PeriodicSendConfig:
    interval_seconds: int
    mode: InputMode | str
    input_data: bytes
    source_mac: str | None
    adapter_name: str
    counter_enabled: bool = False
    counter_rule: CounterByteRule | None = None

    def __post_init__(self) -> None:
        if self.interval_seconds < 1 or self.interval_seconds > 3600:
            raise PeriodicConfigError("周期は1から3600秒で指定してください。")
        if self.counter_enabled and self.counter_rule is None:
            raise PeriodicConfigError("送信回数を反映する対象byte位置を指定してください。")
        if self.counter_enabled and self.counter_rule is not None:
            _validate_counter_position(self.input_data, self.counter_rule)

    def input_for_send(self, send_count: int) -> tuple[bytes, int | None]:
        if not self.counter_enabled:
            return self.input_data, None
        if self.counter_rule is None:
            raise PeriodicConfigError("送信回数を反映する対象byte位置を指定してください。")
        return apply_counter_byte(self.input_data, self.counter_rule, send_count)

    def packet_for_send(self, send_count: int) -> PeriodicSendResult:
        data, counter_value = self.input_for_send(send_count)
        packet = build_packet_from_input(self.mode, data, self.source_mac)
        return PeriodicSendResult(packet=packet, counter_value=counter_value)


def apply_counter_byte(
    data: bytes,
    rule: CounterByteRule,
    send_count: int,
) -> tuple[bytes, int]:
    _validate_counter_position(data, rule)
    value = rule.value_for_send(send_count)
    updated = bytearray(data)
    updated[rule.position - 1] = value
    return bytes(updated), value


def _validate_counter_position(data: bytes, rule: CounterByteRule) -> None:
    if rule.position > len(data):
        raise PeriodicConfigError("対象byte位置が入力データの範囲外です。")
