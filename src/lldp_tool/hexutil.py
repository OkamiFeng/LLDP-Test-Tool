from __future__ import annotations

import string


class HexParseError(ValueError):
    """Raised when user-entered hexadecimal byte text is invalid."""


_HEX_DIGITS = set(string.hexdigits)
_SEPARATORS = set(" \t\r\n:-")


def parse_hex_bytes(text: str) -> bytes:
    cleaned: list[str] = []
    for char in text:
        if char in _HEX_DIGITS:
            cleaned.append(char)
        elif char in _SEPARATORS:
            continue
        else:
            raise HexParseError("16進数の形式が正しくありません。")

    hex_text = "".join(cleaned)
    if not hex_text:
        raise HexParseError("入力が空です。16進数のbyteを入力してください。")
    if len(hex_text) % 2:
        raise HexParseError("16進数は偶数桁で入力してください。")

    return bytes.fromhex(hex_text)


def format_hex(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)
