from __future__ import annotations

import re
import unicodedata

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Bidirectional override / isolate and zero-width characters that can disguise text.
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad]")


def truncate(value: str, limit: int, ellipsis: str = "…") -> str:
    if limit <= 0:
        return ""
    return value if len(value) <= limit else value[: max(0, limit - len(ellipsis))] + ellipsis


def strip_control(value: str) -> str:
    return _CONTROL.sub("", value)


def has_invisible(value: str) -> bool:
    return bool(_INVISIBLE.search(value))


def reveal_invisible(value: str) -> str:
    """Make hidden characters visible (U+202E -> <U+202E>) so evidence strings cannot hide them."""
    return "".join(f"<U+{ord(c):04X}>" if _INVISIBLE.match(c) or _CONTROL.match(c) else c for c in value)


def fold(value: str) -> str:
    """Case/compatibility fold used before comparisons (NFKC + lower)."""
    return unicodedata.normalize("NFKC", value).casefold()
