# Sentinel — Risks and Mitigations

## Risks
- **Egress Bypasses**: Agents using low-level socket APIs (e.g. `net` or `tls`) rather than global `fetch`.
  * *Mitigation*: Run target agent process with OS-level firewall restrictions, using Sentinel as application-level audit guard.
- **Performance Overhead**: Complex regex scanning causing latency on large body transfers.
  * *Mitigation*: Limit scanning to text-based payloads under 5MB.
