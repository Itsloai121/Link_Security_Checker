"""Look-alike character handling for homograph and typosquatting detection.

A compact, curated map of the characters attackers actually use (Cyrillic/Greek/Armenian letters that render like
Latin ones) plus ASCII-only swaps (0/o, 1/l, rn/m). Full Unicode confusables are beyond scope; NFKC folding covers
fullwidth, mathematical and circled forms.
"""
from __future__ import annotations

import unicodedata

CROSS_SCRIPT = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "ѵ": "v", "ү": "y", "ё": "e", "ѐ": "e", "ӧ": "o", "ғ": "f",
    # Greek
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y",
    # Armenian
    "օ": "o", "ս": "u", "ո": "n", "հ": "h", "ց": "g", "ԍ": "g",
    # Latin extended / IPA that mimic ASCII
    "ı": "i", "ɑ": "a", "ɡ": "g", "ɩ": "i", "ʋ": "v", "ƅ": "b", "ɴ": "n", "ᴀ": "a", "ᴇ": "e", "ᴏ": "o", "ᴘ": "p",
}
LOOKALIKE_SLASH_DOT = {"∕": "/", "⁄": "/", "／": "/", "․": ".", "‧": ".", "。": ".", "．": ".", "﹒": ".", "‐": "-", "‑": "-", "‒": "-", "–": "-", "−": "-"}
_ASCII_SWAPS = {"0": ("o",), "1": ("l", "i"), "3": ("e",), "4": ("a",), "5": ("s",), "6": ("g",), "7": ("t",), "8": ("b",), "$": ("s",), "@": ("a",)}
_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"), ("nn", "m"))


def script_of(ch: str) -> str:
    if ch.isascii():
        return "Latin" if ch.isalpha() else "Common"
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "Unknown"
    for token in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "DEVANAGARI", "THAI", "HIRAGANA", "KATAKANA", "HANGUL", "CJK", "GEORGIAN", "COMBINING"):
        if name.startswith(token) or f" {token} " in f" {name} ":
            return token.title() if token != "CJK" else "CJK"
    return "Other"


def scripts_in(label: str) -> set[str]:
    return {script_of(c) for c in label if c.isalpha()} - {"Common", "Combining"}


def skeleton(label: str) -> str:
    """Map cross-script look-alikes to ASCII and strip accents: 'pаypаl' (Cyrillic а) -> 'paypal'."""
    folded = unicodedata.normalize("NFKC", label).lower()
    mapped = "".join(CROSS_SCRIPT.get(c, c) for c in folded)
    decomposed = unicodedata.normalize("NFD", mapped)
    return "".join(c for c in decomposed if unicodedata.category(c) != "Mn")


def ascii_variants(label: str, limit: int = 64) -> set[str]:
    """Plausible 'intended' spellings of an ASCII label: paypa1 -> {paypal, paypai}, rnicrosoft -> {microsoft}."""
    out = {label}
    for i, ch in enumerate(label):
        if ch in _ASCII_SWAPS:
            for rep in _ASCII_SWAPS[ch]:
                out |= {v[:i] + rep + v[i + 1:] for v in list(out) if len(v) > i and v[i] == ch}
        if len(out) > limit:
            break
    for src, dst in _MULTI:
        out |= {v.replace(src, dst) for v in list(out) if src in v}
    return {v for v in out if v}


def damerau_levenshtein(a: str, b: str, max_distance: int = 3) -> int:
    """Optimal-string-alignment distance with an early exit once the distance must exceed `max_distance`."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > max_distance:
            return max_distance + 1
        prev2, prev = prev, cur
    return prev[-1]
