/**
 * Active vulnerability testing: SQL injection (error-based) and XSS reflection.
 *
 * These tests send crafted HTTP requests to discovered endpoints.
 * Only use on systems you own or have explicit written permission to test.
 */

// ── SQL Injection ─────────────────────────────────────────────────────────────

const SQLI_PAYLOADS = [
  "'",
  "''",
  "`",
  "1' OR '1'='1",
  "1 UNION SELECT NULL--",
];

// Error strings emitted by common databases when a query is malformed
const SQLI_SIGNATURES = [
  /you have an error in your sql syntax/i,
  /warning:\s*mysql/i,
  /mysql_fetch_/i,
  /unclosed quotation mark after the character string/i,
  /quoted string not properly terminated/i,
  /pg_query\(\)/i,
  /warning:\s*pg_/i,
  /valid PostgreSQL result/i,
  /microsoft ole db provider for sql server/i,
  /incorrect syntax near/i,
  /\.net sqlclient data provider/i,
  /\[Microsoft\]\[ODBC/i,
  /ora-\d{4,5}:/i,
  /oracle.*driver/i,
  /sqlite\/jdbcdriver/i,
  /sqlite\.exception/i,
  /system\.data\.sqlite\.sqliteexception/i,
  /PDOException.*SQLSTATE/i,
  /db2 sql error\s*:/i,
  /jdbc\.mysql\.exceptions/i,
  /Fatal error.*SQL/i,
];

// ── XSS Reflection ────────────────────────────────────────────────────────────

// Unique marker that won't appear naturally in any page
const XSS_MARKER = 'xss7331test';

const XSS_PAYLOADS = [
  `<${XSS_MARKER}>`,
  `"><${XSS_MARKER}>`,
  `'><${XSS_MARKER}>`,
];

// ── Shared helpers ────────────────────────────────────────────────────────────

async function tryFetch(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      mode: 'cors',
      credentials: 'omit',
    });
    clearTimeout(timer);
    let body = '';
    try {
      body = await res.text();
    } catch {
      // body unreadable (CORS opaque etc.) — leave empty
    }
    return { ok: true, body, status: res.status };
  } catch {
    clearTimeout(timer);
    return { ok: false, body: '', status: null };
  }
}

/**
 * Build a test URL by injecting a payload into the first query param (or
 * appending `?id=<payload>` when there are no params).
 */
function buildTestUrl(endpoint, payload) {
  const u = new URL(endpoint);
  const params = [...u.searchParams.entries()];
  if (params.length > 0) {
    u.searchParams.set(params[0][0], payload);
  } else {
    u.searchParams.set('id', payload);
  }
  return u.href;
}

// ── SQL Injection ─────────────────────────────────────────────────────────────

/**
 * Test a list of same-origin endpoints for error-based SQL injection.
 * @param {string[]} endpoints
 * @param {number} timeoutMs
 * @returns {Promise<Array>}
 */
export async function testSqliEndpoints(endpoints, timeoutMs = 8000) {
  const results = [];
  // Track base paths so we report at most one finding per distinct endpoint
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try {
      basePath = new URL(endpoint).pathname;
    } catch {
      continue;
    }
    if (done.has(basePath)) continue;

    for (const payload of SQLI_PAYLOADS) {
      let testUrl;
      try {
        testUrl = buildTestUrl(endpoint, payload);
      } catch {
        continue;
      }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok) continue;

      for (const sig of SQLI_SIGNATURES) {
        if (sig.test(body)) {
          done.add(basePath);
          results.push({
            id: `sqli-${results.length}`,
            name: 'SQL Injection (Error-Based)',
            category: 'Injection',
            severity: 'critical',
            description: `A database error was returned when sending the payload "${payload}" to this endpoint. The backend likely concatenates user input directly into a SQL query.`,
            guidance:
              'Use parameterized queries or prepared statements. Never build SQL by string-concatenating user-controlled values.',
            matches: [testUrl],
            sources: [endpoint],
            type: 'vuln',
          });
          break;
        }
      }
      if (done.has(basePath)) break;
    }
  }

  return results;
}

// ── XSS Reflection ────────────────────────────────────────────────────────────

/**
 * Test a list of same-origin endpoints for reflected XSS.
 * @param {string[]} endpoints
 * @param {number} timeoutMs
 * @returns {Promise<Array>}
 */
export async function testXssEndpoints(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try {
      basePath = new URL(endpoint).pathname;
    } catch {
      continue;
    }
    if (done.has(basePath)) continue;

    for (const payload of XSS_PAYLOADS) {
      let testUrl;
      try {
        const u = new URL(endpoint);
        const params = [...u.searchParams.entries()];
        if (params.length > 0) {
          u.searchParams.set(params[0][0], payload);
        } else {
          u.searchParams.set('q', payload);
        }
        testUrl = u.href;
      } catch {
        continue;
      }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok) continue;

      if (body.includes(XSS_MARKER)) {
        done.add(basePath);
        results.push({
          id: `xss-${results.length}`,
          name: 'Reflected XSS',
          category: 'Injection',
          severity: 'high',
          description: `Input was reflected unescaped in the response body using payload "${payload}". An attacker can craft a URL that executes arbitrary JavaScript in a victim's browser.`,
          guidance:
            'Escape all user-supplied output in HTML context. Implement a strict Content-Security-Policy to reduce impact.',
          matches: [testUrl],
          sources: [endpoint],
          type: 'vuln',
        });
        break;
      }
    }
  }

  return results;
}
