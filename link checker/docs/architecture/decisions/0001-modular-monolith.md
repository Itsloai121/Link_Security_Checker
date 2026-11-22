# ADR 0001: One deployable modular monolith

**Date:** 2026-11-22 · **Status:** accepted

**Context.** The system has two capabilities (link analysis, threat feeds), a web UI and a CLI, for a small team and modest load.
**Decision.** Build one process with strict module boundaries (domain / application / ports / infrastructure per module), in-process workers and an in-process queue.
**Alternatives.** Microservices (more moving parts than the problem needs); a message broker (no consumer outside the process).
**Consequences.** Simple to run on a laptop or one container. Boundaries are enforced by structure and review, not by the network. If load grows, the evidence to split is sustained queue delay with CPU-bound parsing; the ports make that split mechanical.
