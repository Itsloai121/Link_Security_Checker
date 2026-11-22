"""Content sniffing from the first bytes only. Used to catch files that lie about what they are (USSA pillar 12)."""
from __future__ import annotations

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "executable"), (b"\x7fELF", "executable"), (b"\xcf\xfa\xed\xfe", "executable"), (b"\xca\xfe\xba\xbe", "executable"),
    (b"#!", "script"), (b"PK\x03\x04", "archive"), (b"Rar!", "archive"), (b"7z\xbc\xaf\x27\x1c", "archive"),
    (b"\x1f\x8b", "archive"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "office"), (b"%PDF", "pdf"),
    (b"\x89PNG", "image"), (b"\xff\xd8\xff", "image"), (b"GIF8", "image"), (b"MSCF", "archive"),
)
EXEC_EXT = frozenset({"exe", "msi", "scr", "bat", "cmd", "com", "pif", "dll", "apk", "jar", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "dmg", "pkg", "deb", "rpm", "appimage", "msix", "appx", "appinstaller"})
ARCHIVE_EXT = frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "iso", "img", "cab", "z", "bz2", "xz"})
DOC_EXT = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "txt", "jpg", "jpeg", "png", "gif", "csv", "mp3", "mp4"})
EXEC_TYPES = ("application/x-msdownload", "application/x-msdos-program", "application/vnd.microsoft.portable-executable", "application/x-dosexec",
              "application/vnd.android.package-archive", "application/x-msi", "application/java-archive", "application/x-sh",
              "application/x-executable", "application/x-apple-diskimage", "application/hta", "application/x-ms-installer")
ARCHIVE_TYPES = ("application/zip", "application/x-zip-compressed", "application/x-rar-compressed", "application/vnd.rar", "application/x-7z-compressed",
                 "application/gzip", "application/x-gzip", "application/x-iso9660-image", "application/x-tar", "application/vnd.ms-cab-compressed")


def sniff(head: bytes, content_type: str | None = None) -> str:
    for sig, kind in _SIGNATURES:
        if head.startswith(sig):
            return kind
    low = head[:512].lstrip().lower()
    if low.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<?xml", b"<script", b"<meta", b"<title", b"<div")):
        return "html"
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct.startswith("text/html") or ct == "application/xhtml+xml":
        return "html"
    if ct in ("text/javascript", "application/javascript", "application/x-javascript"):
        return "script"
    if ct.startswith("text/"):
        return "text"
    if ct.startswith("image/"):
        return "image"
    return "unknown"


def extension_of(path: str) -> str:
    seg = path.rsplit("/", 1)[-1].split(";")[0]
    return seg.rsplit(".", 1)[-1].lower() if "." in seg else ""
