# ADR 0003: Gather evidence first, then evaluate with pure checks

**Date:** 2026-11-22 · **Status:** accepted

**Context.** Twenty tests need very different data (URL text, redirect chain, DOM, TLS, registry, network). Tests that mix I/O and judgement are slow, flaky and hard to trust.
**Decision.** An application-layer collector gathers seven kinds of evidence concurrently, each wrapped so a failure becomes `Evidence.missing(reason)`. Each check declares the evidence it needs and is a pure function returning findings. A check may only read evidence it declared.
**Alternatives.** Each check fetching what it needs (duplicate requests, untestable); one monolithic analyser.
**Consequences.** All 20 checks are unit-tested offline with hand-built evidence. A failing source degrades only the checks that need it. Checks cannot silently depend on each other. The cost is an explicit evidence model to maintain.
