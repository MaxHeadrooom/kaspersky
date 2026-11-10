from __future__ import annotations

import re

SEGMENT_WIDTH = 10
_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")


class InvalidVersionError(ValueError):
    pass


def parse_version(text: str) -> tuple[int, ...]:
    text = text.strip()
    if not _VERSION_RE.fullmatch(text):
        raise InvalidVersionError(
            f"некорректная версия {text!r}: ожидаются числа через точку, например 1.2.3"
        )
    parts = [int(part) for part in text.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def version_key(text: str) -> str:
    parts = parse_version(text)
    if any(part >= 10**SEGMENT_WIDTH for part in parts):
        raise InvalidVersionError(f"некорректная версия {text!r}: слишком большой сегмент")
    return ".".join(f"{part:0{SEGMENT_WIDTH}d}" for part in parts)


def branch_start(lower_fixed: str, fixed: str) -> str:
    lower, upper = parse_version(lower_fixed), parse_version(fixed)
    for index, (a, b) in enumerate(zip(lower, upper)):
        if a != b:
            return ".".join(map(str, upper[: index + 1]))
    return ".".join(map(str, lower))
