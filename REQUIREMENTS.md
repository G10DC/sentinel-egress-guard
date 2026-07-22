# Sentinel — Requirements

## Functional
- Intercept global `fetch()` calls.
- Enforce strict hostname validation against allowlist.
- Scan post bodies for secrets and PII.

## Non-Functional
- Interception overhead must be < 5ms per request.
- Must not retain scanned payloads in log files (privacy preservation).
- Zero external package dependencies.
