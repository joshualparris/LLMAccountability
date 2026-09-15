# LLMAccountability ↔ JoshMemory

Last updated: 15 September 2026

## Boundary

LLMAccountability owns accountability/verification-policy evidence. JoshMemory owns durable project continuity, historical context and provenance-rich references to external evidence.

The current shared JoshMemory backend is an always-available private GitHub append-only store (`joshualparris/JoshDashboard4`, `joshmemory-cloud/v1/`), so accountability context can be resumed without depending on AVANCE-WS7 or another workstation being online.

## Evidence contract

JoshMemory may store an accountability reference containing fields such as project, requirement ID, claim summary, source system, source ID, reviewer, verdict and commit SHA. That record points to the accountability evidence; it does not replace or upgrade the underlying evidence.

A useful flow is:

```text
requirement / claim
      |
      v
LLMAccountability / independent evidence path
      |
      v
verdict + source identifier
      |
      +----> authoritative evidence remains in its source system
      |
      +----> JoshMemory records a durable reference for future agents
```

## Precedence

- Live repository/API/machine evidence outranks memory.
- Independent verification/accountability evidence outranks a JoshMemory summary of it.
- JoshMemory handoffs/facts are context to verify, not a reason to suppress contradictory evidence.

## Do not

- Do not mark something SATISFIED merely because it was written into JoshMemory.
- Do not lose the original source identifier or commit SHA when those are available.
- Do not overwrite history; use supersession and preserve prior records.
- Do not store credentials or sensitive tokens in shared memory.

Canonical JoshMemory implementation/history: https://github.com/joshualparris/JoshMemory
