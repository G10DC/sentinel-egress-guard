/**
 * Simple runtime guard and egress filter.
 */
export class SentinelGuard {
  constructor(options = {}) {
    this.allowlist = new Set(options.allowlist || []);
    this.scanPII = !!options.scanPII;
    this.scanSecrets = !!options.scanSecrets;
    this.originalFetch = globalThis.fetch;
    this.violations = [];
  }

  /**
   * Activates the egress filter by overriding global fetch.
   */
  activate() {
    globalThis.fetch = async (input, init) => {
      const urlString = typeof input === 'string' ? input : input.url;
      const url = new URL(urlString);
      
      // Egress domain validation
      if (this.allowlist.size > 0 && !this.allowlist.has(url.hostname)) {
        const error = new Error(`Block: domain '${url.hostname}' is not allowlisted.`);
        this.violations.push({ type: 'domain', target: url.hostname });
        throw error;
      }

      // Payload scanning
      if (init && init.body) {
        const bodyStr = String(init.body);
        if (this.scanSecrets && /sk-[a-zA-Z0-9]{32,}/.test(bodyStr)) {
          const error = new Error('Block: payload contains a suspected API secret.');
          this.violations.push({ type: 'secret', target: url.hostname });
          throw error;
        }
        if (this.scanPII && /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/.test(bodyStr)) {
          const error = new Error('Block: payload contains PII (email address).');
          this.violations.push({ type: 'pii', target: url.hostname });
          throw error;
        }
      }

      return this.originalFetch(input, init);
    };
  }

  /**
   * Restores the original fetch implementation.
   */
  deactivate() {
    globalThis.fetch = this.originalFetch;
  }
}
