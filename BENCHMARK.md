# Sentinel — Benchmark Strategy

## Target Goals
- Proxy intercept overhead: < 1ms for standard HTTP requests.
- Scanner throughput: > 50MB/s scanning speed for PII and secrets patterns.

## Strategy
Run load testing script generating 1000 simulated HTTP requests with various payload sizes (1KB, 10KB, 100KB, 1MB) and calculate latency overhead.
