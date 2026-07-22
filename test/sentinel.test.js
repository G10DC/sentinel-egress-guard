import test from 'node:test';
import assert from 'node:assert';
import { SentinelGuard } from '../lib/sentinel.js';

test('SentinelGuard blocks unauthorized domains', async () => {
  const guard = new SentinelGuard({
    allowlist: ['api.github.com']
  });

  // Mock global fetch
  globalThis.fetch = () => Promise.resolve({ ok: true });
  guard.activate();

  await assert.rejects(
    () => fetch('https://malicious.com/data'),
    /Block: domain 'malicious.com' is not allowlisted/
  );

  guard.deactivate();
});

test('SentinelGuard blocks sensitive payloads', async () => {
  const guard = new SentinelGuard({
    allowlist: ['api.github.com'],
    scanSecrets: true,
    scanPII: true
  });

  globalThis.fetch = () => Promise.resolve({ ok: true });
  guard.activate();

  await assert.rejects(
    () => fetch('https://api.github.com/log', { body: 'my secret is sk-1234567890abcdef1234567890abcdef' }),
    /Block: payload contains a suspected API secret/
  );

  await assert.rejects(
    () => fetch('https://api.github.com/log', { body: 'contact me at email@example.com' }),
    /Block: payload contains PII/
  );

  guard.deactivate();
});
