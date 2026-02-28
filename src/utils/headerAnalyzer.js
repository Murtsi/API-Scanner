/**
 * Analyze HTTP response headers for missing or misconfigured security controls.
 * Returns findings in the same shape as pattern-based detections.
 */

const REQUIRED_HEADERS = [
  {
    name: 'strict-transport-security',
    ruleName: 'Missing HSTS',
    category: 'Security Headers',
    severity: 'high',
    description:
      'HTTP Strict Transport Security not set — browsers may connect over plain HTTP, enabling downgrade attacks and cookie theft.',
    guidance:
      'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
  },
  {
    name: 'content-security-policy',
    ruleName: 'Missing Content-Security-Policy',
    category: 'Security Headers',
    severity: 'high',
    description:
      'No CSP header found — the page has no browser-enforced defence against XSS and data-injection attacks.',
    guidance: "Add: Content-Security-Policy: default-src 'self'",
  },
  {
    name: 'x-content-type-options',
    ruleName: 'Missing X-Content-Type-Options',
    category: 'Security Headers',
    severity: 'medium',
    description:
      'Browser may MIME-sniff responses away from the declared content type, enabling content-type confusion attacks.',
    guidance: 'Add: X-Content-Type-Options: nosniff',
  },
  {
    name: 'x-frame-options',
    ruleName: 'Missing X-Frame-Options',
    category: 'Security Headers',
    severity: 'medium',
    description:
      'Page can be embedded in iframes on any origin — enables clickjacking attacks.',
    guidance:
      'Add: X-Frame-Options: DENY (or use the CSP frame-ancestors directive for more control)',
  },
  {
    name: 'referrer-policy',
    ruleName: 'Missing Referrer-Policy',
    category: 'Security Headers',
    severity: 'low',
    description:
      'No Referrer-Policy — browsers send the full URL (including path and query parameters) to external sites as a referrer.',
    guidance: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
  },
  {
    name: 'permissions-policy',
    ruleName: 'Missing Permissions-Policy',
    category: 'Security Headers',
    severity: 'low',
    description:
      'No Permissions-Policy header — sensitive browser features (camera, microphone, geolocation) are unrestricted.',
    guidance:
      'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
  },
];

const DISCLOSURE_HEADERS = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-runtime',
  'x-version',
];

/**
 * Analyse response headers and return an array of security findings.
 * @param {Headers|null} headers - Fetch API Headers object
 * @param {string} url - The URL whose response was inspected
 * @returns {Array}
 */
export function analyzeSecurityHeaders(headers, url) {
  if (!headers || typeof headers.get !== 'function') return [];
  const findings = [];

  // ── Required headers ──────────────────────────────────────────────────────
  for (const h of REQUIRED_HEADERS) {
    const value = headers.get(h.name);

    if (!value) {
      findings.push({
        id: `header-missing-${h.name}`,
        name: h.ruleName,
        category: h.category,
        severity: h.severity,
        description: h.description,
        guidance: h.guidance,
        matches: ['Header absent from response'],
        sources: [url],
        type: 'header',
      });
      continue;
    }

    // Weak-value checks
    if (h.name === 'content-security-policy') {
      if (value.includes("'unsafe-inline'") && value.includes("'unsafe-eval'")) {
        findings.push({
          id: 'header-weak-csp',
          name: "Weak Content-Security-Policy",
          category: 'Security Headers',
          severity: 'medium',
          description:
            "CSP allows both 'unsafe-inline' and 'unsafe-eval', effectively defeating its XSS protections.",
          guidance:
            "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes for inline scripts instead.",
          matches: [value.slice(0, 150)],
          sources: [url],
          type: 'header',
        });
      }
    }

    if (h.name === 'strict-transport-security') {
      const m = value.match(/max-age=(\d+)/i);
      if (m && parseInt(m[1]) < 31536000) {
        findings.push({
          id: 'header-short-hsts',
          name: 'Short HSTS max-age',
          category: 'Security Headers',
          severity: 'medium',
          description: `HSTS max-age of ${m[1]}s is below the recommended minimum of 1 year (31536000s).`,
          guidance:
            'Increase Strict-Transport-Security max-age to at least 31536000.',
          matches: [value],
          sources: [url],
          type: 'header',
        });
      }
    }
  }

  // ── CORS wildcard ─────────────────────────────────────────────────────────
  const acao = headers.get('access-control-allow-origin');
  if (acao === '*') {
    findings.push({
      id: 'header-cors-wildcard',
      name: 'CORS Wildcard Origin',
      category: 'CORS Misconfiguration',
      severity: 'medium',
      description:
        "Access-Control-Allow-Origin: * permits any origin to read this endpoint's responses, potentially exposing sensitive data to cross-site requests.",
      guidance:
        'Restrict Access-Control-Allow-Origin to specific trusted origins.',
      matches: ['Access-Control-Allow-Origin: *'],
      sources: [url],
      type: 'header',
    });
  }

  // ── Server technology disclosure ──────────────────────────────────────────
  for (const header of DISCLOSURE_HEADERS) {
    const value = headers.get(header);
    if (value) {
      findings.push({
        id: `header-disclosure-${header}`,
        name: 'Server Technology Disclosure',
        category: 'Information Disclosure',
        severity: 'low',
        description: `"${header}: ${value}" reveals server technology, aiding attacker fingerprinting for known CVEs.`,
        guidance: `Remove or redact the "${header}" header in your web server / reverse-proxy config.`,
        matches: [`${header}: ${value}`],
        sources: [url],
        type: 'header',
      });
    }
  }

  return findings;
}
