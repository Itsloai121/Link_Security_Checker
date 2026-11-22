# ADR 0006: No user accounts; unguessable scan ids are the access right

**Date:** 2026-11-22 · **Status:** accepted

**Context.** The product is a public utility. Accounts would add credentials, recovery flows and personal data that the product does not need.
**Decision.** No sign-in. Each report is addressed by a 128-bit random id; whoever holds the id can read or delete the report. There is no listing endpoint; unknown, malformed and expired ids return the same 404. Reports are deleted after 24 hours. Rate limits are keyed on a hash of the client address held only in memory.
**Alternatives.** Accounts (unneeded data and attack surface); sequential ids (enumerable).
**Consequences.** Sharing the report URL shares access; the page says so and offers immediate deletion. If sign-in is introduced later (history, teams), add an `owner_id` column and an authorization step in `GetScanResult`/`DeleteScan`; nothing else changes.
