# Sentinel — Architecture

## Interception Model

```
┌──────────────────────────────────────────────┐
│                  Node Runtime                │
│                                              │
│  ┌──────────────┐      ┌──────────────────┐  │
│  │ global.fetch │ ───► │  Sentinel Guard  │  │
│  └──────────────┘      │  Interceptor     │  │
│                        └────────┬─────────┘  │
│                                 │            │
│                                 ▼            │
│                        ┌──────────────────┐  │
│                        │ Allowlist / PII  │  │
│                        │ Scanner Filters  │  │
│                        └────────┬─────────┘  │
│                                 │            │
│                  ┌──────────────┴──────────┐ │
│                  ▼                         ▼ │
│              [Allowed]                 [Blocked]
│                  │                         │
│                  ▼                         ▼
│          Original fetch()          Throw Egress Error
```
- **Filter Pipeline**: The interceptor acts as middleware, validating target URL syntax first and then scanning payload content sequentially.
- **State Store**: Logs all violations in memory for compliance reporting.
