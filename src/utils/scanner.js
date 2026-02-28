import { SCAN_CONFIG, EXPOSED_PATHS } from '../config/constants.js';
import { findHighEntropyStrings } from './entropy.js';

/**
 * Build a safe global RegExp from a pattern.
 * @param {RegExp|string} pattern
 * @param {string} [flags]
 * @returns {RegExp|null}
 */
export function safeRegex(pattern, flags) {
  try {
    if (pattern instanceof RegExp) {
      const f = flags ?? (pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
      return new RegExp(pattern.source, f);
    }
    const f = flags ?? 'g';
    return new RegExp(pattern, f.includes('g') ? f : f + 'g');
  } catch {
    return null;
  }
}

/**
 * Fetch a URL with an AbortController timeout.
 * @param {string} url
 * @param {number} [timeoutMs]
 * @returns {Promise<Response>}
 */
export async function fetchWithTimeout(url, timeoutMs = SCAN_CONFIG.FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, mode: 'cors', credentials: 'omit' });
    clearTimeout(timer);
    return res;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

/**
 * Fetch a URL safely, returning { text, status, headers, error }.
 * @param {string} url
 * @returns {Promise<{text: string, status: number|null, headers: Headers|null, error: string|null}>}
 */
export async function fetchContent(url) {
  try {
    const res = await fetchWithTimeout(url);
    const text = await res.text();
    return { text, status: res.status, headers: res.headers, error: null };
  } catch (err) {
    const error = err.name === 'AbortError' ? 'Timeout (12 s)' : err.message;
    return { text: '', status: null, headers: null, error };
  }
}

/**
 * Apply detection rules to content, returning an array of findings.
 * Each finding: { ...rule, matches: string[], sources: string[] }
 * @param {string} content
 * @param {Array} rules
 * @param {number} [entropyThreshold]
 * @param {number} [maxMatchesPerRule]
 * @returns {Array}
 */
export function extractFindings(
  content,
  rules,
  entropyThreshold = SCAN_CONFIG.ENTROPY_THRESHOLD,
  maxMatchesPerRule = SCAN_CONFIG.MAX_MATCHES_PER_RULE
) {
  const findings = [];

  for (const rule of rules) {
    const re = safeRegex(rule.regex);
    if (!re) continue;

    const matches = [];
    let m;
    re.lastIndex = 0;
    while ((m = re.exec(content)) !== null) {
      const val = (m[1] || m[0]).trim();
      if (val && !matches.includes(val)) matches.push(val);
      if (matches.length >= maxMatchesPerRule) break;
    }

    if (matches.length > 0) {
      findings.push({ ...rule, matches, sources: [] });
    }
  }

  // High-entropy string detection
  const entropyMatches = findHighEntropyStrings(
    content,
    entropyThreshold,
    SCAN_CONFIG.MAX_ENTROPY_MATCHES
  );
  if (entropyMatches.length > 0) {
    findings.push({
      id: 'high-entropy',
      name: 'High-Entropy String',
      category: 'Entropy',
      severity: 'medium',
      description: 'Suspicious random-looking string — may be an undeclared secret.',
      matches: entropyMatches,
      sources: [],
    });
  }

  return findings;
}

/**
 * Parse linked JS asset URLs from HTML.
 * @param {string} html
 * @param {string} baseUrl
 * @returns {string[]}
 */
export function extractAssets(html, baseUrl) {
  try {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const base = new URL(baseUrl);
    const assets = new Set();

    doc.querySelectorAll('script[src]').forEach((el) => {
      const src = el.getAttribute('src');
      if (src) try { assets.add(new URL(src, base).href); } catch {}
    });

    doc.querySelectorAll('link[rel~="preload"][as="script"], link[rel~="modulepreload"]').forEach((el) => {
      const href = el.getAttribute('href');
      if (href) try { assets.add(new URL(href, base).href); } catch {}
    });

    return [...assets]
      .filter((u) => /\.js(\?.*)?$/i.test(u))
      .slice(0, SCAN_CONFIG.MAX_ASSETS);
  } catch {
    return [];
  }
}

/**
 * Check common exposed paths and return those that respond with 200/301/302.
 * Requests are made in parallel batches.
 * @param {string} baseUrl
 * @param {function} [onProgress]
 * @returns {Promise<Array>}
 */
export async function checkExposedFiles(baseUrl, onProgress) {
  const origin = new URL(baseUrl).origin;
  const results = [];
  const concurrency = 6;

  for (let i = 0; i < EXPOSED_PATHS.length; i += concurrency) {
    const batch = EXPOSED_PATHS.slice(i, i + concurrency);
    const settled = await Promise.allSettled(
      batch.map(async (path) => {
        const url = `${origin}/${path}`;
        const { status } = await fetchContent(url);
        return { path, url, status };
      })
    );
    for (const s of settled) {
      if (
        s.status === 'fulfilled' &&
        (s.value.status === 200 || s.value.status === 301 || s.value.status === 302)
      ) {
        results.push(s.value);
      }
    }
    onProgress?.(Math.min(i + concurrency, EXPOSED_PATHS.length), EXPOSED_PATHS.length);
  }

  return results;
}

/**
 * Scan an array of JS asset URLs in parallel batches, merging findings by rule id.
 * @param {string[]} assetUrls
 * @param {Array} rules
 * @param {{ entropyThreshold: number, maxMatchesPerRule: number }} options
 * @param {function} [onAssetDone]  - called with (url) after each asset is done
 * @param {function} [onContent]    - called with (url, text) to collect raw JS for endpoint extraction
 * @returns {Promise<Array>}
 */
export async function scanAssetsParallel(assetUrls, rules, options, onAssetDone, onContent) {
  const { entropyThreshold, maxMatchesPerRule } = options;
  const merged = new Map(); // id -> finding
  const concurrency = SCAN_CONFIG.ASSET_CONCURRENCY;

  for (let i = 0; i < assetUrls.length; i += concurrency) {
    const batch = assetUrls.slice(i, i + concurrency);
    await Promise.allSettled(
      batch.map(async (url) => {
        const { text } = await fetchContent(url);
        if (!text) return;
        onContent?.(url, text);
        const findings = extractFindings(text, rules, entropyThreshold, maxMatchesPerRule);
        for (const f of findings) {
          if (!merged.has(f.id)) {
            merged.set(f.id, { ...f, matches: [...f.matches], sources: [url] });
          } else {
            const ex = merged.get(f.id);
            for (const m of f.matches) {
              if (!ex.matches.includes(m)) ex.matches.push(m);
            }
            if (!ex.sources.includes(url)) ex.sources.push(url);
          }
        }
        onAssetDone?.(url);
      })
    );
  }

  return [...merged.values()].map((f) => ({
    ...f,
    matches: f.matches.slice(0, SCAN_CONFIG.MAX_MATCHES_PER_RULE),
  }));
}
