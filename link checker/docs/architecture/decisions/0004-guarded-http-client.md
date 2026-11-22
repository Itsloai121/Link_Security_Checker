# ADR 0004: Own SSRF-guarded HTTP client on httpcore

**Date:** 2026-11-22 · **Status:** accepted

**Context.** The scanner fetches attacker-supplied URLs, which makes it a server-side request forgery (SSRF) tool if mishandled: internal addresses, cloud metadata endpoints, DNS rebinding, redirect chains into private space.
**Decision.** All outbound HTTP uses `GuardedHttpClient`, built directly on `httpcore` with a custom network backend that (1) resolves the name itself, (2) refuses the whole answer if *any* address is non-public (including IPv4-mapped, NAT64, 6to4, Teredo), (3) connects to the validated IP while keeping the hostname for SNI, certificate verification and the Host header, (4) allows only configured destination ports, (5) never follows redirects (the fetcher re-validates every hop), (6) caps bytes read and total time, and reads far less for non-HTML responses.
**Alternatives.** Validate then hand the URL to `httpx`/`requests` (DNS can change between check and connect: rebinding); a network sandbox only (defence in depth is still wanted); an allow-list of hosts (impossible for this product).
**Consequences.** One audited path. Tests prove loopback, link-local, ULA and mapped addresses are refused and that nothing reaches a local server. The policy can be relaxed only by `UNMASK_ALLOW_PRIVATE_NETWORKS`, which production settings refuse. Deploy the container with egress rules too (`docs/architecture/security.md`).
