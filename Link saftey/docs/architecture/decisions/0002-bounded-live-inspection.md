# ADR 0002: Bounded live URL inspection

- **Status:** Accepted for local MVP; revisit before public deployment.
- **Date:** 2026-11-20

## Context

The analysis UI displayed several live checks as `NOT CHECKED` because only static URL heuristics were implemented. The app needs real domain age, hosting, TLS, redirect, and page signals, while treating each submitted link as untrusted input and preserving the existing data-minimization rules.

## Decision

Implement a synchronous live-check adapter behind the scan-use-case port for local use. It:

- accepts only credential-free HTTP/HTTPS URLs on default ports 80/443;
- accepts syntactically valid DNS suffixes without a hard-coded TLD allowlist, normalizes trailing-dot hostnames, and treats missing RDAP support as an age-check limitation rather than stopping other checks;
- resolves every destination, rejects any non-public or reserved address, and pins each socket to the validated DNS answer;
- manually follows at most five redirects, reapplying the public-address policy at every hop;
- caps response headers and page content, sets short deadlines, sends no cookies or authorization, and does not execute page scripts;
- reads registration and IP allocation data through IANA bootstrap RDAP, uses Team Cymru's DNS origin service for ASN/prefix context, and verifies HTTPS certificates with Node TLS;
- checks the exact submitted URL against PhishTank’s phishing database. `PHISHTANK_APP_KEY` is optional and raises provider rate limits; without it, the provider may impose stricter limits. A no-match is not treated as proof of safety.

The UI discloses that live checks contact public destinations and registry services and advises users not to submit links containing private tokens. Raw submitted URLs remain unpersisted and unlogged.

## Alternatives considered

- **Keep checks pending:** rejected because it left the main analysis signals nonfunctional.
- **Unrestricted `fetch(userUrl)`:** rejected because it permits SSRF, DNS rebinding, unbounded redirects, and oversized responses.
- **Run a full headless browser:** deferred because it increases attack surface and would execute untrusted page scripts.
- **Use Google Safe Browsing v4:** rejected for a commercial SaaS because Google's official docs direct commercial use to Web Risk.

## Consequences and limits

- Local scans now make outbound requests and may take up to several seconds.
- HTML checks are heuristics over a bounded response, not browser rendering. JavaScript-generated forms, visual overlays, and behavior-based cloaking can be missed.
- Registry country codes are not physical geolocation or abuse reputation.
- PhishTank can rate-limit or deny lookups. Such failures are reported as unavailable rather than clear; cache successful answers briefly to reduce repeated requests.
- A destination blocked by policy is labeled `blocked`; a failed lookup is labeled `error`; only an unconfigured provider remains `pending`. None counts as a clear check.
- These application-level SSRF defenses are not an OS/network egress firewall. Before public deployment, move page inspection to an isolated worker with enforced egress controls, independent security review, and updated privacy/retention terms.

## Implementation note

This ADR records the original bounded-inspection design. The Node.js implementation described in the historical code references was superseded by the Python backend in ADR 0003; the current outbound policy is implemented in `backend/link_safety/network.py` and `backend/link_safety/ip_policy.py`.
