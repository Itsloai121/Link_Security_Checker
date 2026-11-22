from __future__ import annotations

import re
from urllib.parse import urljoin

from modules.link_analysis.domain.checks.base import CheckContext
from modules.link_analysis.domain.evidence import FetchResult, FieldInfo, FormInfo, PageSnapshot
from modules.link_analysis.domain.url_model import ParsedUrl, parse_url

SENSITIVE_KINDS = frozenset({"password", "otp", "pin", "card", "cvv", "identity", "bank", "seed"})
_RX = {
    "seed": re.compile(r"seed|mnemonic|recovery[-_ ]?phrase|secret[-_ ]?phrase|private[-_ ]?key|keystore|12[-_ ]?words|24[-_ ]?words", re.I),
    "cvv": re.compile(r"cvv|cvc|cvn|security[-_ ]?code|card[-_ ]?code", re.I),
    "card": re.compile(r"cc[-_ ]?(num|exp)|card[-_ ]?(num|no)|cardnumber|credit[-_ ]?card|expir|رقم البطاقة", re.I),
    "otp": re.compile(r"otp|one[-_ ]?time|2fa|mfa|verification[-_ ]?code|sms[-_ ]?code|auth(entication)?[-_ ]?code|رمز التحقق|كود التحقق", re.I),
    "pin": re.compile(r"(?<![a-z])pin(?![a-z])|الرقم السري", re.I),
    "identity": re.compile(r"\bssn\b|social[-_ ]?security|national[-_ ]?id|passport|الرقم القومي", re.I),
    "bank": re.compile(r"\biban\b|routing|account[-_ ]?number|sort[-_ ]?code|swift", re.I),
    "email": re.compile(r"e-?mail|البريد", re.I),
    "username": re.compile(r"user(name|id)?|login|account|uname|معرف|اسم المستخدم", re.I),
}


def classify_field(f: FieldInfo) -> str | None:
    """Most sensitive data kind a form field asks for, or None."""
    hay = " ".join((f.name, f.id, f.placeholder, f.autocomplete, f.label))
    t = f.type.lower()
    if t == "password":
        return "password"
    if "one-time-code" in f.autocomplete.lower():
        return "otp"
    if f.autocomplete.lower().startswith("cc-"):
        return "cvv" if "csc" in f.autocomplete.lower() else "card"
    for kind in ("seed", "cvv", "card", "otp", "pin", "identity", "bank"):
        if t in ("hidden", "submit", "button", "checkbox", "radio") and kind != "seed":
            continue
        if _RX[kind].search(hay):
            return kind
    if t == "email" or _RX["email"].search(hay):
        return "email"
    if _RX["username"].search(hay):
        return "username"
    if t == "tel":
        return "phone"
    return None


def form_kinds(form: FormInfo) -> set[str]:
    return {k for f in form.fields if (k := classify_field(f))}


def page_kinds(page: PageSnapshot) -> set[str]:
    out: set[str] = set()
    for form in page.forms:
        out |= form_kinds(form)
    return out


def css_props(style: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for decl in style.split(";"):
        if ":" in decl:
            k, v = decl.split(":", 1)
            props[k.strip().lower()] = re.sub(r"\s*!important", "", v.strip().lower())
    return props


def _px(value: str) -> float | None:
    m = re.fullmatch(r"(-?\d+(?:\.\d+)?)(px|em|rem|pt|%|vw|vh)?", value.strip())
    return float(m.group(1)) if m else None


def css_flags(props: dict[str, str]) -> set[str]:
    flags: set[str] = set()
    zero = lambda v: _px(v) == 0 if v else False  # noqa: E731
    if props.get("display") == "none" or props.get("visibility") in ("hidden", "collapse"):
        flags.add("hidden")
    try:
        if float(props.get("opacity", "1")) <= 0.05:
            flags |= {"hidden", "transparent"}
    except ValueError:
        pass
    if (zero(props.get("width", "")) and zero(props.get("height", ""))) or zero(props.get("font-size", "")):
        flags.add("hidden")
    for key in ("left", "top", "margin-left", "text-indent"):
        v = _px(props.get(key, ""))
        if v is not None and v <= -900:
            flags.add("hidden")
    if re.search(r"rect\(\s*0(px)?[ ,]+0(px)?[ ,]+0(px)?[ ,]+0(px)?\s*\)|inset\(\s*(50|100)%", props.get("clip", "") + props.get("clip-path", "")):
        flags.add("hidden")
    bg = props.get("background-color", props.get("background", ""))
    if bg in ("transparent", "none") or re.search(r"rgba\([^)]*,\s*0(\.0+)?\)", bg):
        flags.add("transparent")
    pos = props.get("position", "")
    full = (any(props.get(k, "").replace(" ", "") in ("100%", "100vw", "100vh") for k in ("width", "height")) or
            all(props.get(k, "") in ("0", "0px") for k in ("top", "left", "right", "bottom")) or props.get("inset", "") in ("0", "0px"))
    z = re.match(r"-?\d+", props.get("z-index", ""))
    if pos in ("fixed", "absolute") and full and z and int(z.group()) >= 100:
        flags.add("overlay")
    return flags


def parsed_final(ctx: CheckContext) -> ParsedUrl | None:
    """The page the visitor lands on, if we could follow the link."""
    ev = ctx.evidence("journey") if "journey" in ctx.allowed else None
    if ev is not None and ev.available and ev.value.final_url:
        return parse_url(ev.value.final_url)
    return None


def best_fetch(ctx: CheckContext) -> FetchResult | None:
    for key in ("journey", "journey_browser"):
        if key in ctx.allowed:
            ev = ctx.evidence(key)
            if ev.available and ev.value.page is not None:
                return ev.value
    return None


def resolve(base: str, ref: str | None) -> str | None:
    if ref is None:
        return None
    try:
        return urljoin(base, ref.strip())
    except ValueError:
        return None


def pretty_list(items, limit: int = 4) -> str:
    items = list(dict.fromkeys(items))
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def short(url: str, limit: int = 90) -> str:
    return url if len(url) <= limit else url[: limit - 1] + "…"


_KIND_PHRASE = {"password": "a password", "otp": "a one-time code", "pin": "a PIN", "card": "card details", "cvv": "a card security code",
                "identity": "ID details", "bank": "bank details", "seed": "a crypto recovery phrase"}


def kind_phrase(kinds) -> str:
    """{'password','card'} -> 'card details and a password' (stable order, reads like a sentence)."""
    order = ["seed", "card", "cvv", "bank", "identity", "pin", "otp", "password"]
    items = [_KIND_PHRASE[k] for k in order if k in kinds]
    return items[0] if len(items) == 1 else (", ".join(items[:-1]) + " and " + items[-1]) if items else "personal details"
