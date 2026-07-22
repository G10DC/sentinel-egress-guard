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
   * Activates the egress filter by overriding global fetch, http, and https modules.
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

    // Intercept native http/https request
    try {
      const http = await import('node:http');
      const https = await import('node:https');
      this.originalHttpRequest = http.request;
      this.originalHttpsRequest = https.request;

      const createInterceptedRequest = (originalFn) => {
        return (url, options, callback) => {
          const targetUrl = typeof url === 'string' ? new URL(url) : (url instanceof URL ? url : new URL(`http://${options?.host || options?.hostname || 'localhost'}`));
          if (this.allowlist.size > 0 && !this.allowlist.has(targetUrl.hostname)) {
            this.violations.push({ type: 'domain', target: targetUrl.hostname });
            throw new Error(`Block: domain '${targetUrl.hostname}' is not allowlisted.`);
          }
          return originalFn(url, options, callback);
        };
      };

      http.request = createInterceptedRequest(this.originalHttpRequest);
      https.request = createInterceptedRequest(this.originalHttpsRequest);
    } catch (e) {}
  }

  /**
   * Restores the original fetch and http/https implementations.
   */
  deactivate() {
    globalThis.fetch = this.originalFetch;
    if (this.originalHttpRequest) {
      import('node:http').then(http => { http.request = this.originalHttpRequest; }).catch(() => {});
    }
    if (this.originalHttpsRequest) {
      import('node:https').then(https => { https.request = this.originalHttpsRequest; }).catch(() => {});
    }
  }
}
