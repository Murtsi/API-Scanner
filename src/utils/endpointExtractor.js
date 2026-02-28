/**
 * Extract API endpoint URLs and HTML form action URLs from page content.
 * Used to feed discovered targets into active vulnerability tests.
 */

const API_URL_PATTERNS = [
  // fetch('url') / fetch("url") / fetch(`url`)
  /\bfetch\(\s*['"`]([^'"`\s]{4,200})['"`]/g,
  // axios.get/post/put/delete/patch('url')
  /\baxios\.[a-z]+\(\s*['"`]([^'"`\s]{4,200})['"`]/g,
  // $.get / $.post / $.ajax('url')
  /\$\.(?:get|post|ajax)\(\s*['"`]([^'"`\s]{4,200})['"`]/g,
  // XMLHttpRequest .open('METHOD', 'url')
  /\.open\(\s*['"`][A-Z]+['"`]\s*,\s*['"`]([^'"`\s]{4,200})['"`]/g,
  // { url: '...' } inside AJAX config objects
  /\burl\s*:\s*['"`]([^'"`\s]{4,200})['"`]/g,
  // Common relative API path prefixes
  /['"`](\/(?:api|v\d+|graphql|rest|query|endpoint)[^\s'"`]{0,100})['"`]/g,
];

/**
 * Extract API endpoint URLs found in HTML or JS content.
 * Only keeps same-origin URLs to avoid testing third-party services.
 * @param {string} content
 * @param {string} baseUrl
 * @returns {string[]}
 */
export function extractApiEndpoints(content, baseUrl) {
  const endpoints = new Set();
  let base;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }

  for (const pattern of API_URL_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let m;
    while ((m = re.exec(content)) !== null) {
      const raw = m[1];
      if (!raw || raw.length < 2) continue;
      // Skip template literals, data URIs, and static asset paths
      if (
        raw.includes('${') ||
        raw.startsWith('data:') ||
        /\.(js|css|png|jpg|svg|woff|ico)(\?|$)/i.test(raw)
      )
        continue;
      try {
        if (raw.startsWith('http://') || raw.startsWith('https://')) {
          const parsed = new URL(raw);
          if (parsed.origin === base.origin) endpoints.add(raw);
        } else if (raw.startsWith('/')) {
          endpoints.add(`${base.origin}${raw}`);
        }
      } catch {
        // ignore invalid URLs
      }
    }
  }

  return [...endpoints].slice(0, 15);
}

/**
 * Extract form action URLs from HTML.
 * Only keeps same-origin actions.
 * @param {string} html
 * @param {string} baseUrl
 * @returns {string[]}
 */
export function extractFormActions(html, baseUrl) {
  const actions = new Set();
  let base;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }

  const re = /<form[^>]*\baction\s*=\s*['"]([^'"]+)['"]/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const action = new URL(m[1], base.origin).href;
      if (new URL(action).origin === base.origin) {
        actions.add(action);
      }
    } catch {
      // ignore
    }
  }

  return [...actions].slice(0, 5);
}
