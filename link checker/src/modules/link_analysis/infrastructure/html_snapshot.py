"""Turns raw HTML into a PageSnapshot of FACTS. Nothing is rendered or executed; scripts are only read as text.

Defensive by design (USSA pillar 12: file and data handling): bounded sizes everywhere, a hard parse-failure fallback, and the
resulting strings are treated as hostile by every consumer (output is escaped; the UI uses textContent).
"""
from __future__ import annotations

import re
import zlib

from bs4 import BeautifulSoup, Tag

from modules.link_analysis.domain.evidence import AnchorInfo, ElementInfo, FieldInfo, FormInfo, FrameInfo, PageSnapshot

_STYLE_PROPS = re.compile(r"display|visibility|opacity|position|width|height|left|top|right|bottom|clip|z-index|font-size|text-indent|inset|margin", re.I)
_RULE = re.compile(r"([^{}@]+)\{([^{}]*)\}")
_WS = re.compile(r"\s+")
_META_REFRESH = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*[;,]?\s*(?:url\s*=\s*)?['\"]?([^'\"]*)", re.I)
_JS_REDIRECT = re.compile(
    r"""(?:window\.|document\.|top\.|self\.|parent\.)?location(?:\.href)?\s*=\s*(["'])(?P<a>(?:https?:)?//[^"']+|/[^"']*)\1"""
    r"""|location\.(?:replace|assign)\(\s*(["'])(?P<b>[^"']+)\3\s*\)""", re.I)
_CAPS = dict(forms=25, fields=60, anchors=150, frames=30, elements=300, scripts=25, script_len=6000, rules=400, text=8000)


def _clip(s: str | None, n: int) -> str:
    return _WS.sub(" ", s or "").strip()[:n]


def text_fingerprint(text: str, k: int = 300) -> frozenset[int]:
    """Bottom-k sketch of word 3-shingles: comparing two sketches approximates Jaccard similarity of the page text."""
    words = re.findall(r"\w+", text.lower())[:3000]
    if len(words) < 3:
        return frozenset(zlib.crc32(w.encode()) for w in words)
    return frozenset(sorted({zlib.crc32(" ".join(words[i:i + 3]).encode()) for i in range(len(words) - 2)})[:k])


def _attr(el: Tag, name: str) -> str:
    v = el.get(name)
    return " ".join(v) if isinstance(v, list) else (v or "")


def _field(el: Tag, soup: BeautifulSoup) -> FieldInfo:
    ftype = (_attr(el, "type") or ("textarea" if el.name == "textarea" else "select" if el.name == "select" else "text")).lower()
    label = _attr(el, "aria-label")
    if not label and _attr(el, "id"):
        lab = soup.find("label", attrs={"for": _attr(el, "id")})
        label = _clip(lab.get_text(" ") if lab else "", 80)
    if not label:
        parent = el.find_parent("label")
        label = _clip(parent.get_text(" ") if parent else "", 80)
    style = _attr(el, "style").replace(" ", "").lower()
    hidden = el.has_attr("hidden") or ftype == "hidden" or "display:none" in style or "visibility:hidden" in style
    return FieldInfo(ftype[:20], _attr(el, "name")[:60], _attr(el, "id")[:60], _clip(_attr(el, "placeholder"), 80), _attr(el, "autocomplete")[:30], label, hidden)


def build_snapshot(body: bytes, content_type: str | None, truncated: bool = False) -> PageSnapshot:
    try:
        return _build(body, content_type, truncated)
    except (RecursionError, Exception):  # malformed or hostile markup must never crash a scan
        return PageSnapshot(byte_size=len(body), truncated=truncated)


def _build(body: bytes, content_type: str | None, truncated: bool) -> PageSnapshot:
    m = re.search(r"charset=([\w-]+)", content_type or "", re.I)
    soup = BeautifulSoup(body, "html.parser", from_encoding=m.group(1) if m else None)

    def meta(attr: str, value: str) -> str:
        t = soup.find("meta", attrs={attr: re.compile(f"^{re.escape(value)}$", re.I)})
        return _clip(_attr(t, "content"), 300) if t else ""

    canonical = soup.find("link", rel=lambda v: v and "canonical" in (v if isinstance(v, list) else [v]))
    base = soup.find("base", href=True)
    refresh = soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)})
    # read all <head> metadata BEFORE the head/script/style elements are stripped for text extraction
    head = dict(title=_clip(soup.title.get_text() if soup.title else "", 200), description=meta("name", "description"),
                og_site_name=meta("property", "og:site_name"), og_title=meta("property", "og:title"), og_url=meta("property", "og:url"),
                canonical=_attr(canonical, "href")[:300] if canonical else "", base_href=_attr(base, "href")[:300] if base else "",
                lang=_attr(soup.html, "lang")[:10] if soup.html else "", meta_refresh=_attr(refresh, "content")[:300] if refresh else "")
    scripts = [s.get_text()[: _CAPS["script_len"]] for s in soup.find_all("script") if not s.get("src")][: _CAPS["scripts"]]
    script_srcs = tuple(_attr(s, "src")[:200] for s in soup.find_all("script", src=True)[:30])
    rules: list[tuple[str, str]] = []
    for st in soup.find_all("style")[:10]:
        for sel, decl in _RULE.findall(st.get_text()[:60_000]):
            if _STYLE_PROPS.search(decl):
                rules.append((_clip(sel, 120), _clip(decl, 300)))
            if len(rules) >= _CAPS["rules"]:
                break
    sel_names = set(re.findall(r"[.#]([\w-]+)", " ".join(s for s, _ in rules)))

    forms: list[FormInfo] = []
    for f in soup.find_all("form", limit=_CAPS["forms"]):
        fields = tuple(_field(i, soup) for i in f.find_all(["input", "textarea", "select"], limit=_CAPS["fields"]))
        submits = tuple(_clip(b.get_text(" ") or _attr(b, "value"), 40) for b in f.find_all(["button", "input"], limit=40)
                        if (b.name == "button" or _attr(b, "type").lower() in ("submit", "button")))[:3]
        forms.append(FormInfo(f.get("action"), _attr(f, "method").lower() or "get", fields, _attr(f, "style")[:300], submits))
    orphans = [i for i in soup.find_all(["input", "textarea"], limit=300) if i.find_parent("form") is None]
    if orphans:  # script-driven login boxes: inputs outside any <form>
        forms.append(FormInfo(None, "js", tuple(_field(i, soup) for i in orphans[: _CAPS["fields"]])))

    anchors = tuple(AnchorInfo(_attr(a, "href")[:300], _clip(a.get_text(" "), 80)) for a in soup.find_all("a", href=True, limit=_CAPS["anchors"]))
    frames = tuple(FrameInfo(_attr(f, "src")[:300], _attr(f, "style")[:300], _attr(f, "width"), _attr(f, "height"), f.has_attr("hidden"))
                   for f in soup.find_all(["iframe", "frame"], limit=_CAPS["frames"]))
    headings = tuple(_clip(h.get_text(" "), 120) for h in soup.find_all(["h1", "h2"], limit=8))
    alts = tuple(_clip(_attr(i, "alt"), 80) for i in soup.find_all("img", alt=True, limit=40) if len(_attr(i, "alt").strip()) >= 2)[:30]

    elements: list[ElementInfo] = []
    for el in soup.find_all(True):
        if len(elements) >= _CAPS["elements"]:
            break
        if el.name in ("script", "style", "html", "head", "body", "meta", "link", "title"):
            continue
        style = _attr(el, "style")
        interesting = (bool(style) and bool(_STYLE_PROPS.search(style))) or el.has_attr("hidden") or _attr(el, "aria-hidden") == "true" \
            or bool(sel_names & (set(_attr(el, "class").split()) | {_attr(el, "id")}))
        if interesting:
            elements.append(ElementInfo(el.name, _attr(el, "id")[:60], _attr(el, "class")[:120], style[:300], el.has_attr("hidden") or _attr(el, "aria-hidden") == "true",
                                        el.find(["input", "textarea", "select"]) is not None, len(el.find_all("a")), len(el.get_text(strip=True))))
    for t in soup(["script", "style", "noscript", "template", "head"]):
        t.extract()
    visible = _clip(soup.get_text(" ", strip=True), _CAPS["text"])
    input_count = sum(1 for f in forms for fld in f.fields if fld.type not in ("hidden", "submit", "button", "image", "reset", "checkbox", "radio"))
    return PageSnapshot(
        **head, headings=headings, image_alts=alts, visible_text=visible, forms=tuple(forms), anchors=anchors, iframes=frames, elements=tuple(elements),
        style_rules=tuple(rules), inline_scripts=tuple(scripts), script_srcs=script_srcs, input_count=input_count, byte_size=len(body), truncated=truncated)


def detect_client_redirect(page: PageSnapshot) -> tuple[str, str] | None:
    """Meta-refresh or a plain `location = "..."` assignment on a thin page. Returns (via, target) or None."""
    if page.meta_refresh:
        m = _META_REFRESH.match(page.meta_refresh)
        if m and m.group(2).strip() and float(m.group(1)) <= 15:
            return "meta_refresh", m.group(2).strip()
    if len(page.visible_text) < 400 or page.byte_size < 30_000:
        for script in page.inline_scripts:
            m = _JS_REDIRECT.search(script)
            if m:
                return "javascript", (m.group("a") or m.group("b")).strip()
    return None
