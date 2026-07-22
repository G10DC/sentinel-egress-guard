# sentinel

Continuous runtime guard and network egress firewall for AI agents. Sentinel intercepts outbound network traffic and scans payloads to prevent secrets exposure, data exfiltration, and prompt injection leaks.

## Features
- **Interception Proxy**: Hooks directly into Node.js runtime transport layer (`globalThis.fetch`) to intercept outbound requests.
- **Domain Allowlisting**: Restricts requests strictly to pre-approved destination hostnames (Deny-by-default strategy).
- **Secrets Scanning**: Scans payload bodies for common API credentials and authentication tokens (e.g., OpenAI, Anthropic key patterns).
- **PII Leakage Prevention**: Identifies and blocks payloads containing Personally Identifiable Information such as email addresses.

## Installation

```bash
npm install
```

## Usage

```javascript
import { SentinelGuard } from './lib/sentinel.js';

// Setup rules and allowlist
const guard = new SentinelGuard({
  allowlist: ['api.github.com', 'registry.npmjs.org'],
  scanSecrets: true,
  scanPII: true
});

// Intercept fetch
guard.activate();

try {
  // This will be allowed
  await fetch('https://api.github.com/users/octocat');

  // This will be blocked (unauthorized domain)
  await fetch('https://untrusted-api.com/exfiltrate');
} catch (error) {
  console.error(error.message); // "Block: domain 'untrusted-api.com' is not allowlisted."
}

try {
  // This will be blocked (contains secret key)
  await fetch('https://api.github.com/log', {
    method: 'POST',
    body: 'My key is sk-proj-1234567890abcdef1234567890abcdef'
  });
} catch (error) {
  console.error(error.message); // "Block: payload contains a suspected API secret."
}

// Restore original fetch
guard.deactivate();
```

## API Reference

### `new SentinelGuard(options)`
- `options.allowlist`: Array of strings containing authorized hostnames.
- `options.scanSecrets`: Boolean. If true, inspects request bodies for keys/secrets.
- `options.scanPII`: Boolean. If true, inspects request bodies for PII (emails).

### `guard.activate()`
Overrides the global `fetch` handler with the security proxy.

### `guard.deactivate()`
Restores the original `fetch` handler.

### `guard.violations`
Array of logs containing caught violations:
```javascript
[
  { type: 'domain', target: 'untrusted-api.com' },
  { type: 'secret', target: 'api.github.com' }
]
```

## Running Tests

```bash
npm test
```

## License

MIT
