"""Canonical JSON for TUF signatures.

TUF specification 1.0.36 (5 August 2026) says metadata digests use the
canonical JSON subdialect: no insignificant whitespace, object keys sorted by
Unicode code point, and UTF-8 strings. Control characters are ``\\u00xx``.
This is the OLPC canonical-JSON shape used by the TUF reference implementation.
Floats are rejected. Booleans are not integers.
"""

from __future__ import annotations


def canonical(value: object) -> bytes:
    parts: list[str] = []
    _write(value, parts)
    return "".join(parts).encode("utf-8")


def _write(value: object, parts: list[str]) -> None:
    if isinstance(value, str):
        parts.append('"')
        for char in value:
            code = ord(char)
            if char == '"':
                parts.append('\\"')
            elif char == "\\":
                parts.append("\\\\")
            elif code < 0x20:
                parts.append(f"\\u{code:04x}")
            else:
                parts.append(char)
        parts.append('"')
        return
    if value is True:
        parts.append("true")
        return
    if value is False:
        parts.append("false")
        return
    if value is None:
        parts.append("null")
        return
    if isinstance(value, int):
        parts.append(str(value))
        return
    if isinstance(value, list):
        parts.append("[")
        for index, item in enumerate(value):
            if index:
                parts.append(",")
            _write(item, parts)
        parts.append("]")
        return
    if isinstance(value, dict):
        parts.append("{")
        for index, key in enumerate(sorted(value)):
            if not isinstance(key, str):
                raise ValueError("Canonical JSON object keys must be strings.")
            if index:
                parts.append(",")
            _write(key, parts)
            parts.append(":")
            _write(value[key], parts)
        parts.append("}")
        return
    raise ValueError("Canonical JSON does not encode this value.")
