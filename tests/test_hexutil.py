import pytest

from lldp_tool.hexutil import HexParseError, format_hex, parse_hex_bytes


def test_parse_hex_bytes_accepts_supported_separators():
    assert parse_hex_bytes("01 80\nC2:00-00\t0E") == bytes.fromhex("0180c200000e")


def test_parse_hex_bytes_accepts_contiguous_hex():
    assert parse_hex_bytes("0180c200000e") == bytes.fromhex("0180c200000e")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "空"),
        ("01 8", "偶数"),
        ("01 80 zz", "16進数"),
        ("01_80", "16進数"),
    ],
)
def test_parse_hex_bytes_reports_japanese_errors(text, message):
    with pytest.raises(HexParseError) as exc_info:
        parse_hex_bytes(text)

    assert message in str(exc_info.value)


def test_format_hex_outputs_uppercase_byte_groups():
    assert format_hex(bytes.fromhex("0180c200000e")) == "01 80 C2 00 00 0E"
