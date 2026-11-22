# ADR 0005: Pages are read, never rendered or executed

**Date:** 2026-11-22 · **Status:** accepted

**Context.** Phishing pages and malware sites are hostile. Running a headless browser against them adds a large attack surface and heavy dependencies.
**Decision.** Fetch HTML, parse it as data (BeautifulSoup `html.parser`), inspect scripts and styles as text only, never execute JavaScript, never write bodies to disk, never download files (headers and the first bytes only). Every test that depends on the page states this limitation in its report.
**Alternatives.** Headless Chromium in a sandbox (strongest coverage of JavaScript-built pages, but a significant risk and operations cost).
**Consequences.** Pages that build their content with JavaScript are only partially visible; the report says so ("fields or overlays that only appear after JavaScript executes are not seen"). Static detection of common evasion code and HTML smuggling compensates in part. A sandboxed renderer can be added later behind the `PageFetcher` port.
