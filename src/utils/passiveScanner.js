/**
 * Enhanced passive analysis — JavaScript source analysis, library detection,
 * source map exposure, sensitive storage usage, robots.txt parsing,
 * and Subresource Integrity checks.
 *
 * All methods are purely passive — they read content already fetched by the
 * main scanner and optionally fetch additional public files (robots.txt, sitemap).
 * No attack payloads are sent.
 */

// ── DOM XSS Sink Patterns ─────────────────────────────────────────────────────

const DOM_XSS_SINKS = [
  {
    pattern: /\.innerHTML\s*[+=]/g,
    name: 'innerHTML assignment',
    severity: 'high',
    detail: 'Direct assignment to innerHTML executes any HTML/script in the value. Replace with textContent or use DOMPurify to sanitise HTML.',
  },
  {
    pattern: /\.outerHTML\s*[+=]/g,
    name: 'outerHTML assignment',
    severity: 'high',
    detail: 'outerHTML is identical to innerHTML in terms of XSS risk — it parses and renders HTML including scripts.',
  },
  {
    pattern: /document\.write\s*\(/g,
    name: 'document.write()',
    severity: 'high',
    detail: 'document.write() injects raw HTML into the page. Any unsanitised input passed here leads to XSS. Avoid it entirely.',
  },
  {
    pattern: /document\.writeln\s*\(/g,
    name: 'document.writeln()',
    severity: 'high',
    detail: 'Equivalent to document.write() — same XSS risk.',
  },
  {
    pattern: /\beval\s*\(/g,
    name: 'eval() call',
    severity: 'high',
    detail: 'eval() executes a string as JavaScript. If any user input reaches eval(), it results in arbitrary code execution.',
  },
  {
    pattern: /new\s+Function\s*\(/g,
    name: 'new Function() constructor',
    severity: 'high',
    detail: 'The Function constructor is equivalent to eval() — it compiles and executes a string as code.',
  },
  {
    pattern: /setTimeout\s*\(\s*['"`][^'"`)]/g,
    name: 'setTimeout() with string argument',
    severity: 'medium',
    detail: 'setTimeout() with a string argument behaves like eval(). Pass a function reference instead.',
  },
  {
    pattern: /setInterval\s*\(\s*['"`][^'"`)]/g,
    name: 'setInterval() with string argument',
    severity: 'medium',
    detail: 'setInterval() with a string argument behaves like eval(). Pass a function reference instead.',
  },
  {
    pattern: /\.insertAdjacentHTML\s*\(/g,
    name: 'insertAdjacentHTML()',
    severity: 'high',
    detail: 'insertAdjacentHTML() parses and inserts raw HTML. Any unsanitised input leads to XSS.',
  },
  {
    pattern: /location\.href\s*=\s*[^=]/g,
    name: 'location.href assignment',
    severity: 'medium',
    detail: 'Setting location.href from user input enables open redirect and javascript: URI injection.',
  },
  {
    pattern: /location\.replace\s*\(/g,
    name: 'location.replace()',
    severity: 'medium',
    detail: 'location.replace() with unvalidated user input enables open redirect attacks.',
  },
  {
    pattern: /window\.open\s*\(/g,
    name: 'window.open()',
    severity: 'low',
    detail: 'window.open() with user-controlled URLs can redirect users to malicious sites.',
  },
  {
    pattern: /\$\s*\(\s*['"`][^'"`)]*<[^>]+>/g,
    name: 'jQuery HTML injection',
    severity: 'high',
    detail: 'Passing HTML strings to jQuery selectors or $() executes embedded scripts. Use .text() instead of .html() for user content.',
  },
  {
    pattern: /\.html\s*\(\s*[^)'"`)]/g,
    name: 'jQuery .html() with variable',
    severity: 'medium',
    detail: 'jQuery .html() sets innerHTML. If the argument comes from user input, this is an XSS sink.',
  },
];

// ── Outdated / Vulnerable Library Patterns ────────────────────────────────────

const VULNERABLE_LIBRARIES = [
  {
    pattern: /jquery[./\-_](\d+\.\d+\.\d+)/gi,
    name: 'jQuery',
    check: (ver) => {
      const [maj, min] = ver.split('.').map(Number);
      if (maj < 3) return { vulnerable: true, issue: `jQuery ${ver} is below 3.x — vulnerable to XSS via .html(), prototype pollution, and multiple CVEs (CVE-2019-11358, CVE-2020-11022/23)` };
      if (maj === 3 && min < 6) return { vulnerable: true, issue: `jQuery ${ver} has known XSS issues (CVE-2020-11022/23) — upgrade to 3.6.0+` };
      return { vulnerable: false };
    },
  },
  {
    pattern: /lodash[./\-_@](\d+\.\d+\.\d+)/gi,
    name: 'Lodash',
    check: (ver) => {
      const [maj, min, patch] = ver.split('.').map(Number);
      if (maj < 4 || (maj === 4 && min < 17) || (maj === 4 && min === 17 && patch < 21)) {
        return { vulnerable: true, issue: `Lodash ${ver} is vulnerable to prototype pollution and ReDoS (CVE-2021-23337, CVE-2020-8203) — upgrade to 4.17.21+` };
      }
      return { vulnerable: false };
    },
  },
  {
    pattern: /angular(?:js)?[./\-_@](\d+\.\d+\.\d+)/gi,
    name: 'AngularJS',
    check: (ver) => {
      const [maj] = ver.split('.').map(Number);
      if (maj === 1) return { vulnerable: true, issue: `AngularJS 1.x (${ver}) reached end-of-life in Dec 2021 and has multiple XSS/template injection CVEs. Migrate to Angular 2+ or a modern framework.` };
      return { vulnerable: false };
    },
  },
  {
    pattern: /moment[./\-_@](\d+\.\d+\.\d+)/gi,
    name: 'Moment.js',
    check: (ver) => {
      const [maj, min] = ver.split('.').map(Number);
      if (maj < 2 || (maj === 2 && min < 29)) {
        return { vulnerable: true, issue: `Moment.js ${ver} has ReDoS vulnerabilities (CVE-2022-24785, CVE-2022-31129) — upgrade to 2.29.4+ or migrate to date-fns/day.js (Moment is in maintenance mode)` };
      }
      return { vulnerable: false };
    },
  },
  {
    pattern: /bootstrap[./\-_@](\d+\.\d+\.\d+)/gi,
    name: 'Bootstrap',
    check: (ver) => {
      const [maj, min] = ver.split('.').map(Number);
      if (maj < 4 || (maj === 4 && min < 6)) {
        return { vulnerable: true, issue: `Bootstrap ${ver} has XSS vulnerabilities in data-* attributes and tooltip/popover components — upgrade to 4.6.2+ or 5.3+` };
      }
      return { vulnerable: false };
    },
  },
  {
    pattern: /vue[./\-_@](\d+\.\d+\.\d+)/gi,
    name: 'Vue.js',
    check: (ver) => {
      const [maj, min, patch] = ver.split('.').map(Number);
      if (maj === 2 && (min < 6 || (min === 6 && patch < 14))) {
        return { vulnerable: true, issue: `Vue.js ${ver} has XSS vulnerabilities in the template compiler (CVE-2021-22960) — upgrade to 2.6.14+ or Vue 3` };
      }
      return { vulnerable: false };
    },
  },
];

// ── Sensitive Storage Usage ───────────────────────────────────────────────────

const SENSITIVE_STORAGE_PATTERNS = [
  { pattern: /localStorage\s*\.\s*setItem\s*\(\s*['"`](?:token|auth|jwt|session|password|pass|secret|key|credential|bearer|access_token|refresh_token)['"`]/gi, label: 'localStorage — sensitive key name' },
  { pattern: /sessionStorage\s*\.\s*setItem\s*\(\s*['"`](?:token|auth|jwt|session|password|pass|secret|key|credential|bearer|access_token|refresh_token)['"`]/gi, label: 'sessionStorage — sensitive key name' },
  { pattern: /document\.cookie\s*=\s*[^;]+(?:token|auth|jwt|session|password|secret)/gi, label: 'document.cookie — writing sensitive cookie from JS (may lack HttpOnly)' },
];

// ── Dangerous Function Patterns ───────────────────────────────────────────────

const DANGEROUS_FUNC_PATTERNS = [
  { pattern: /\bexec\s*\(.*require\s*\('child_process'\)/g, name: 'Node.js child_process.exec()', severity: 'critical' },
  { pattern: /crypto\.createCipher\s*\(/g, name: 'Deprecated crypto.createCipher()', severity: 'medium' },
  { pattern: /Math\.random\s*\(\s*\).*(?:token|key|secret|nonce|csrf)/gi, name: 'Math.random() for security token', severity: 'high' },
  { pattern: /JSON\.parse\s*\(\s*(?:localStorage|location\.hash|location\.search|document\.cookie)/g, name: 'JSON.parse() on browser storage/URL', severity: 'medium' },
  { pattern: /postMessage\s*\(\s*.*,\s*['"`]\*['"`]/g, name: 'postMessage() with wildcard targetOrigin', severity: 'high' },
  { pattern: /addEventListener\s*\(\s*['"`]message['"`].*data\./g, name: 'postMessage listener accessing data without origin check', severity: 'medium' },
];

// ── Source Map Detection ──────────────────────────────────────────────────────

const SOURCE_MAP_PATTERN = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)/gi;

// ── SRI Check ─────────────────────────────────────────────────────────────────

const EXTERNAL_SCRIPT_PATTERN = /<script[^>]+src\s*=\s*['"]https?:\/\/(?!(?:your[-.]?domain))[^'"]+['"]/gi;
const INTEGRITY_ATTR_PATTERN = /\bintegrity\s*=/i;

// ── Technology Fingerprinting Patterns ────────────────────────────────────────

const TECH_PATTERNS = [
  { pattern: /wp-content\/|wp-includes\/|wp-json\//i, name: 'WordPress', category: 'CMS', severity: 'info' },
  { pattern: /Drupal\.settings|drupal\.js|\/sites\/default\//i, name: 'Drupal', category: 'CMS', severity: 'info' },
  { pattern: /Joomla!|\/components\/com_/i, name: 'Joomla', category: 'CMS', severity: 'info' },
  { pattern: /Powered by Shopify|shopify\.com\/s\/files/i, name: 'Shopify', category: 'E-Commerce', severity: 'info' },
  { pattern: /cdn\.magento\.com|mage\/cookies/i, name: 'Magento', category: 'E-Commerce', severity: 'info' },
  { pattern: /laravel_session|_token.*csrf/i, name: 'Laravel (PHP)', category: 'Framework', severity: 'info' },
  { pattern: /csrfmiddlewaretoken|django/i, name: 'Django (Python)', category: 'Framework', severity: 'info' },
  { pattern: /rails-ujs|csrf-token.*rails|_rails_/i, name: 'Ruby on Rails', category: 'Framework', severity: 'info' },
  { pattern: /next\.js|__NEXT_DATA__|_next\/static/i, name: 'Next.js', category: 'Framework', severity: 'info' },
  { pattern: /nuxt\.js|__NUXT__|_nuxt\//i, name: 'Nuxt.js', category: 'Framework', severity: 'info' },
  { pattern: /gatsby-image|___gatsby|\/static\/gatsby/i, name: 'Gatsby', category: 'Framework', severity: 'info' },
  { pattern: /spring|springframework|actuator/i, name: 'Spring (Java)', category: 'Framework', severity: 'info' },
  { pattern: /cloudflare|cf-ray/i, name: 'Cloudflare', category: 'CDN / Proxy', severity: 'info' },
  { pattern: /fastly|x-fastly|x-cache.*fastly/i, name: 'Fastly CDN', category: 'CDN / Proxy', severity: 'info' },
  { pattern: /akamai|x-check-cacheable|akamaized\.net/i, name: 'Akamai CDN', category: 'CDN / Proxy', severity: 'info' },
  { pattern: /gtm\.js|GoogleTagManager|googletagmanager\.com/i, name: 'Google Tag Manager', category: 'Tracking', severity: 'info' },
  { pattern: /ga\.js|analytics\.js|gtag\(/i, name: 'Google Analytics', category: 'Tracking', severity: 'info' },
  { pattern: /segment\.com|analytics\.js.*segment/i, name: 'Segment', category: 'Tracking', severity: 'info' },
  { pattern: /sentry\.io|@sentry\/browser/i, name: 'Sentry (Error Tracking)', category: 'Monitoring', severity: 'info' },
  { pattern: /bugsnag\.com|bugsnag\./i, name: 'Bugsnag', category: 'Monitoring', severity: 'info' },
  { pattern: /datadog-rum|DD_RUM/i, name: 'Datadog RUM', category: 'Monitoring', severity: 'info' },
  { pattern: /stripe\.js|js\.stripe\.com/i, name: 'Stripe.js', category: 'Payment', severity: 'info' },
  { pattern: /paypal\.com\/sdk\/js/i, name: 'PayPal SDK', category: 'Payment', severity: 'info' },
  { pattern: /intercom\.io|Intercom\(/i, name: 'Intercom', category: 'Customer Support', severity: 'info' },
  { pattern: /zendesk\.com|zEMediator/i, name: 'Zendesk', category: 'Customer Support', severity: 'info' },
];

// ── Cloud Storage Detection ───────────────────────────────────────────────────

const CLOUD_STORAGE_PATTERNS = [
  { pattern: /https?:\/\/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3[.\-][\w\-]+\.amazonaws\.com/gi, service: 'AWS S3 bucket' },
  { pattern: /https?:\/\/s3[.\-][\w\-]+\.amazonaws\.com\/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])/gi, service: 'AWS S3 bucket (path-style)' },
  { pattern: /https?:\/\/([a-z0-9][a-z0-9\-_]+)\.storage\.googleapis\.com/gi, service: 'GCS bucket' },
  { pattern: /https?:\/\/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.blob\.core\.windows\.net/gi, service: 'Azure Blob Storage' },
  { pattern: /https?:\/\/([a-z0-9][a-z0-9\-]+)\.digitaloceanspaces\.com/gi, service: 'DigitalOcean Spaces' },
];

// ── Async helper ──────────────────────────────────────────────────────────────

async function safeFetch(url, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      mode: 'cors',
      credentials: 'omit',
    });
    clearTimeout(timer);
    const text = await res.text().catch(() => '');
    return { ok: res.status < 400, status: res.status, text };
  } catch {
    clearTimeout(timer);
    return { ok: false, status: null, text: '' };
  }
}

// ── Exported Analysis Functions ───────────────────────────────────────────────

/**
 * Scan JavaScript content for DOM XSS sinks.
 * @param {string} content - JS source code
 * @param {string} sourceUrl
 * @returns {Array}
 */
export function analyzeDomSinks(content, sourceUrl) {
  if (!content) return [];
  const results = [];
  const seen = new Set();

  for (const { pattern, name, severity, detail } of DOM_XSS_SINKS) {
    const re = new RegExp(pattern.source, pattern.flags);
    const match = re.exec(content);
    if (match && !seen.has(name)) {
      seen.add(name);
      // Get a snippet of surrounding context (up to 80 chars)
      const contextStart = Math.max(0, match.index - 20);
      const snippet = content.slice(contextStart, contextStart + 80).replace(/\s+/g, ' ');
      results.push({
        id: `passive-sink-${results.length}`,
        name: `DOM XSS Sink: ${name}`,
        category: 'Client-Side',
        severity,
        type: 'passive',
        technique: 'dom-xss-sink-detection',
        targeting: 'Static analysis of JavaScript source — pattern-matched known DOM XSS sinks (innerHTML, outerHTML, eval, document.write, insertAdjacentHTML, location.href, jQuery .html()) that can execute attacker-controlled content',
        description: `Found "${name}" usage in JavaScript source. ${detail}`,
        guidance: 'Audit all usages of this API. Ensure no user-controlled input reaches this sink. Use textContent/setAttribute for inserting user data, and DOMPurify when HTML is genuinely required.',
        matches: [snippet.trim()],
        sources: [sourceUrl],
      });
    }
  }
  return results;
}

/**
 * Detect outdated or vulnerable third-party libraries in JS content.
 * @param {string} content - HTML + concatenated JS content
 * @param {string} sourceUrl
 * @returns {Array}
 */
export function detectOutdatedLibraries(content, sourceUrl) {
  if (!content) return [];
  const results = [];
  const seen = new Set();

  for (const lib of VULNERABLE_LIBRARIES) {
    const re = new RegExp(lib.pattern.source, lib.pattern.flags);
    let match;
    while ((match = re.exec(content)) !== null) {
      const ver = match[1];
      const key = `${lib.name}-${ver}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const { vulnerable, issue } = lib.check(ver);
      if (vulnerable) {
        results.push({
          id: `passive-lib-${results.length}`,
          name: `Vulnerable Library: ${lib.name} ${ver}`,
          category: 'Supply Chain',
          severity: 'high',
          type: 'passive',
          technique: 'vulnerable-library-detection',
          targeting: `Dependency / supply chain analysis — pattern-matched library version strings in HTML and JavaScript source for known vulnerable versions of jQuery, Lodash, AngularJS, Moment.js, Bootstrap, Vue.js`,
          description: issue,
          guidance: `Update ${lib.name} to its latest stable release. Review the changelog for breaking changes. Consider using a dependency auditing tool (npm audit, Snyk, Dependabot) to catch future vulnerabilities automatically.`,
          matches: [`${lib.name} ${ver}`],
          sources: [sourceUrl],
        });
      }
    }
  }
  return results;
}

/**
 * Detect JavaScript source map references (//# sourceMappingURL=).
 * Source maps expose the original unminified source code.
 * @param {string} content - JS content
 * @param {string} sourceUrl
 * @returns {Array}
 */
export function detectSourceMaps(content, sourceUrl) {
  if (!content) return [];
  const results = [];
  const seen = new Set();
  let match;
  const re = new RegExp(SOURCE_MAP_PATTERN.source, SOURCE_MAP_PATTERN.flags);

  while ((match = re.exec(content)) !== null) {
    const mapFile = match[1];
    if (seen.has(mapFile)) continue;
    seen.add(mapFile);
    results.push({
      id: `passive-map-${results.length}`,
      name: 'Source Map Exposed',
      category: 'Information Disclosure',
      severity: 'medium',
      type: 'passive',
      technique: 'source-map-detection',
      targeting: 'Static analysis of JavaScript bundles for sourceMappingURL comments — source map files (.map) contain the original unminified/un-transpiled source code, exposing business logic, comments, internal paths, and may contain secrets not visible in the minified bundle',
      description: `Source map reference found: "${mapFile}". If the .map file is publicly accessible, attackers can download the original unminified source code, revealing business logic, internal API endpoints, comments, and potentially embedded secrets.`,
      guidance: 'Remove source maps from production deployments or host them on a private, authenticated endpoint. If source maps are needed for error monitoring, configure your error tracking tool (Sentry, Datadog) to upload maps without serving them publicly.',
      matches: [mapFile],
      sources: [sourceUrl],
    });
  }
  return results;
}

/**
 * Detect sensitive data being stored in browser storage.
 * @param {string} content - JS content
 * @param {string} sourceUrl
 * @returns {Array}
 */
export function detectSensitiveStorage(content, sourceUrl) {
  if (!content) return [];
  const results = [];

  for (const { pattern, label } of SENSITIVE_STORAGE_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    const match = re.exec(content);
    if (match) {
      const contextStart = Math.max(0, match.index - 10);
      const snippet = content.slice(contextStart, contextStart + 80).replace(/\s+/g, ' ');
      results.push({
        id: `passive-storage-${results.length}`,
        name: `Sensitive Data in Browser Storage: ${label}`,
        category: 'Client-Side',
        severity: 'medium',
        type: 'passive',
        technique: 'sensitive-storage-detection',
        targeting: 'Static analysis of JavaScript for localStorage/sessionStorage.setItem() and document.cookie assignments with sensitive key names (token, auth, jwt, session, password, secret, bearer, access_token, refresh_token)',
        description: `Found "${label}" in JavaScript source. Data stored in localStorage/sessionStorage is accessible by any JavaScript on the page — a single XSS vulnerability allows an attacker to steal it. Cookies set from JavaScript cannot have the HttpOnly flag.`,
        guidance: 'Store authentication tokens in HttpOnly, Secure, SameSite=Strict cookies managed by the server — not in JavaScript-accessible storage. If client-side storage is required, ensure the most restrictive CSP possible to prevent XSS from accessing it.',
        matches: [snippet.trim()],
        sources: [sourceUrl],
      });
    }
  }
  return results;
}

/**
 * Detect dangerous JavaScript function usage patterns.
 * @param {string} content - JS content
 * @param {string} sourceUrl
 * @returns {Array}
 */
export function detectDangerousFunctions(content, sourceUrl) {
  if (!content) return [];
  const results = [];

  for (const { pattern, name, severity } of DANGEROUS_FUNC_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    const match = re.exec(content);
    if (match) {
      const contextStart = Math.max(0, match.index - 10);
      const snippet = content.slice(contextStart, contextStart + 80).replace(/\s+/g, ' ');
      results.push({
        id: `passive-func-${results.length}`,
        name: `Dangerous Function: ${name}`,
        category: 'Client-Side',
        severity,
        type: 'passive',
        technique: 'dangerous-function-detection',
        targeting: 'Static analysis of JavaScript for dangerous function patterns including child_process.exec(), Math.random() for security tokens, postMessage with wildcard origins, and JSON.parse() on untrusted browser storage',
        description: `Found "${name}" in JavaScript source. This pattern carries security risk if user-controlled data is involved.`,
        guidance: 'Audit this code path carefully to confirm no user-controlled input reaches this function. Replace Math.random() for security tokens with crypto.getRandomValues(). Always validate postMessage origin.',
        matches: [snippet.trim()],
        sources: [sourceUrl],
      });
    }
  }
  return results;
}

/**
 * Detect external scripts without Subresource Integrity (SRI) hashes.
 * @param {string} html - Page HTML
 * @param {string} sourceUrl
 * @returns {Array}
 */
export function detectMissingSri(html, sourceUrl) {
  if (!html) return [];
  const results = [];
  const extScriptRe = new RegExp(EXTERNAL_SCRIPT_PATTERN.source, EXTERNAL_SCRIPT_PATTERN.flags);
  let match;

  while ((match = extScriptRe.exec(html)) !== null) {
    const tag = match[0];
    if (!INTEGRITY_ATTR_PATTERN.test(tag)) {
      const srcMatch = tag.match(/src\s*=\s*['"]([^'"]+)['"]/i);
      const src = srcMatch ? srcMatch[1] : tag.slice(0, 80);
      results.push({
        id: `passive-sri-${results.length}`,
        name: 'External Script Without Subresource Integrity',
        category: 'Supply Chain',
        severity: 'medium',
        type: 'passive',
        technique: 'sri-check',
        targeting: 'HTML analysis for <script src="https://..."> tags from external CDNs without an integrity= attribute — SRI ensures the browser verifies the script hash before executing it, protecting against CDN compromise and script injection',
        description: `External script "${src.slice(0, 100)}" is loaded without an integrity hash. If the CDN serving this script is compromised, an attacker can replace the script with malicious code that executes on all your users' browsers.`,
        guidance: 'Add integrity and crossorigin attributes: integrity="sha384-<hash>" crossorigin="anonymous". Generate the hash with: cat file.js | openssl dgst -sha384 -binary | openssl base64 -A. Most CDNs provide the hash in their documentation.',
        matches: [src.slice(0, 150)],
        sources: [sourceUrl],
      });
      if (results.length >= 5) break; // Limit noise
    }
  }
  return results;
}

/**
 * Fetch and parse robots.txt for interesting disallowed paths.
 * @param {string} baseUrl
 * @returns {Promise<Array>}
 */
export async function analyzeRobotsTxt(baseUrl, timeoutMs = 8000) {
  const results = [];
  let origin;
  try { origin = new URL(baseUrl).origin; } catch { return results; }

  const robotsUrl = `${origin}/robots.txt`;
  const { ok, text } = await safeFetch(robotsUrl, timeoutMs);
  if (!ok || !text) return results;

  // Extract Disallow: paths
  const disallowedPaths = [];
  const lines = text.split('\n');
  for (const line of lines) {
    const m = line.match(/^Disallow:\s*(\/.+)/i);
    if (m) disallowedPaths.push(m[1].trim());
  }

  // Extract sitemap URLs
  const sitemapUrls = [];
  for (const line of lines) {
    const m = line.match(/^Sitemap:\s*(https?:\/\/.+)/i);
    if (m) sitemapUrls.push(m[1].trim());
  }

  const interestingPaths = disallowedPaths.filter(p =>
    /admin|api|backup|config|dashboard|database|debug|dev|internal|private|secret|staff|upload|test|staging|phpmy|phpadmin|wp-admin|manage/i.test(p)
  );

  if (interestingPaths.length > 0) {
    results.push({
      id: 'passive-robots-interesting',
      name: 'Robots.txt — Interesting Disallowed Paths',
      category: 'Information Disclosure',
      severity: 'low',
      type: 'passive',
      technique: 'robots-txt-analysis',
      targeting: 'robots.txt fetch and parse — extracted all Disallow: directives and filtered for paths suggesting administrative interfaces, APIs, debug endpoints, backup files, and internal tools',
      description: `robots.txt at ${robotsUrl} contains ${disallowedPaths.length} Disallow directives, of which ${interestingPaths.length} suggest sensitive paths: ${interestingPaths.slice(0, 5).join(', ')}${interestingPaths.length > 5 ? '...' : ''}.`,
      guidance: 'robots.txt is not a security control — it is public and can guide attackers to sensitive paths. Move sensitive functionality behind authentication. Do not rely on "security through obscurity" via robots.txt.',
      matches: interestingPaths.slice(0, 10),
      sources: [robotsUrl],
    });
  }

  if (sitemapUrls.length > 0) {
    results.push({
      id: 'passive-robots-sitemap',
      name: 'Sitemap URLs Discovered via robots.txt',
      category: 'Information Disclosure',
      severity: 'low',
      type: 'passive',
      technique: 'robots-txt-analysis',
      targeting: 'robots.txt Sitemap: directive extraction — sitemaps provide a complete enumeration of all publicly indexed URLs on the site',
      description: `Found ${sitemapUrls.length} sitemap URL(s) in robots.txt. Sitemaps provide attackers with a comprehensive list of all pages for targeted scanning.`,
      guidance: 'This is expected behaviour — sitemaps are designed to be public. Ensure all pages listed in sitemaps are properly protected if they contain sensitive content.',
      matches: sitemapUrls.slice(0, 5),
      sources: [robotsUrl],
    });
  }

  return results;
}

/**
 * Detect technology stack from HTML content and response headers.
 * @param {string} html - Page HTML
 * @param {Headers|null} headers - Response headers
 * @param {string} sourceUrl
 * @returns {Array}
 */
export function detectTechStack(html, headers, sourceUrl) {
  const combined = html || '';
  const results = [];
  const seen = new Set();

  for (const { pattern, name, category } of TECH_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    if (re.test(combined)) {
      if (!seen.has(name)) {
        seen.add(name);
        results.push({
          id: `passive-tech-${results.length}`,
          name: `Technology Detected: ${name}`,
          category: `Recon — ${category}`,
          severity: 'low',
          type: 'passive',
          technique: 'tech-fingerprinting',
          targeting: `Technology stack fingerprinting — pattern-matched HTML/JS content for signatures of CMS platforms, web frameworks, CDN providers, analytics tools, payment processors, customer support platforms, and error monitoring services`,
          description: `Detected ${name} (${category}) from page content. This confirms the technology stack and can guide targeted vulnerability research (e.g., known CVEs, default configurations, plugin vulnerabilities).`,
          guidance: 'Remove version-revealing comments and meta generator tags. Keep all identified software updated. Review known CVEs for identified components.',
          matches: [name],
          sources: [sourceUrl],
        });
      }
    }
  }

  // Check common server/framework headers
  if (headers && typeof headers.get === 'function') {
    const serverHeader = headers.get('server');
    const poweredBy = headers.get('x-powered-by');
    const generator = headers.get('x-generator');

    for (const [hName, hVal] of [['Server', serverHeader], ['X-Powered-By', poweredBy], ['X-Generator', generator]]) {
      if (hVal && !seen.has(hVal)) {
        seen.add(hVal);
        results.push({
          id: `passive-tech-hdr-${hName}`,
          name: `Server Technology via Header: ${hVal}`,
          category: 'Recon — Server',
          severity: 'low',
          type: 'passive',
          technique: 'tech-fingerprinting',
          targeting: `HTTP response header analysis — checked Server, X-Powered-By, X-Generator headers for technology and version disclosure`,
          description: `"${hName}: ${hVal}" reveals the server technology and potentially its version, enabling targeted CVE lookups.`,
          guidance: `Remove or redact the "${hName}" header in your web server configuration.`,
          matches: [`${hName}: ${hVal}`],
          sources: [sourceUrl],
        });
      }
    }
  }

  return results;
}

/**
 * Detect cloud storage bucket URLs in HTML/JS content.
 * @param {string} content - HTML + JS content
 * @param {string} sourceUrl
 * @returns {Array}
 */
export function detectCloudStorage(content, sourceUrl) {
  if (!content) return [];
  const results = [];
  const seen = new Set();

  for (const { pattern, service } of CLOUD_STORAGE_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = re.exec(content)) !== null) {
      const bucketRef = match[0].slice(0, 100);
      if (seen.has(bucketRef)) continue;
      seen.add(bucketRef);
      results.push({
        id: `passive-cloud-${results.length}`,
        name: `Cloud Storage Reference: ${service}`,
        category: 'Recon — Cloud',
        severity: 'low',
        type: 'passive',
        technique: 'cloud-storage-detection',
        targeting: `Cloud storage enumeration — scanned HTML and JavaScript for direct references to AWS S3, Google Cloud Storage, Azure Blob Storage, and DigitalOcean Spaces bucket URLs`,
        description: `Found a reference to a ${service} in page content: "${bucketRef}". If the bucket's ACL is misconfigured (public read or public write), sensitive files may be accessible or attackers may be able to upload malicious content.`,
        guidance: 'Verify the bucket ACL is not publicly writable. Enable server-side logging on cloud storage buckets. Consider moving sensitive files to private buckets with pre-signed URLs.',
        matches: [bucketRef],
        sources: [sourceUrl],
      });
      if (results.length >= 8) return results;
    }
  }
  return results;
}

/**
 * Discover GraphQL endpoints referenced in HTML/JS content.
 * @param {string} content
 * @param {string} sourceUrl
 * @returns {Array}
 */
export function discoverGraphqlReferences(content, sourceUrl) {
  if (!content) return [];
  const gqlPattern = /['"`]((?:https?:\/\/[^'"` ]+)?\/(?:graphql|graphiql|gql|playground|query|api\/query)[^'"` ]{0,80})['"`]/gi;
  const results = [];
  const seen = new Set();
  let match;

  while ((match = gqlPattern.exec(content)) !== null) {
    const endpoint = match[1];
    if (seen.has(endpoint)) continue;
    seen.add(endpoint);
    results.push({
      id: `passive-graphql-${results.length}`,
      name: 'GraphQL Endpoint Reference Discovered',
      category: 'Recon — API',
      severity: 'low',
      type: 'passive',
      technique: 'graphql-endpoint-discovery',
      targeting: 'Static analysis of HTML and JavaScript for GraphQL endpoint URL patterns (/graphql, /gql, /graphiql, /playground, /query, /api/query) — endpoints discovered passively before active introspection testing',
      description: `Found GraphQL endpoint reference: "${endpoint}". This endpoint may have introspection enabled, batch query support, or other GraphQL-specific vulnerabilities.`,
      guidance: 'Disable GraphQL introspection in production. Implement query depth and complexity limits. Enable authentication on the GraphQL endpoint if not already done.',
      matches: [endpoint],
      sources: [sourceUrl],
    });
    if (results.length >= 5) break;
  }
  return results;
}
