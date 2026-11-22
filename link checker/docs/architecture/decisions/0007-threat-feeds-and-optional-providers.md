# ADR 0007: Public threat feeds by default; third-party lookups opt-in

**Date:** 2026-11-22 · **Status:** accepted

**Context.** Blocklists catch confirmed bad links fastest, but they come from third parties with licences, and per-URL lookup services receive the links people check.
**Decision.** Default sources are downloaded lists (OpenPhish community feed, Spamhaus DROP/ASN-DROP), matched locally, so no checked link leaves the server. Online lookups (Google Safe Browsing, URLhaus) exist but run only when an operator supplies a key, and the documentation states that links are then sent to that provider. A list that has never been downloaded or that cannot be reached makes the blocklist test "not verified", never "clear". Feed updates that parse too small or shrink drastically are rejected.
**Alternatives.** Query a vendor per link by default (privacy cost); ship a static list (stale).
**Consequences.** Licences must be respected (OpenPhish community feed is non-commercial; Spamhaus requires attribution): see `docs/operations/feeds.md`. Freshness depends on running `update-feeds`.
