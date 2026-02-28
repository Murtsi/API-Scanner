/**
 * Calculate Shannon entropy of a string.
 * Higher entropy = more random = more likely to be a secret.
 * @param {string} str
 * @returns {number}
 */
export function getEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum - p * Math.log2(p);
  }, 0);
}

// Patterns that indicate the string is likely NOT a secret
const FALSE_POSITIVE_PATTERNS = [
  /^[a-zA-Z]+$/,                           // pure letters (class names, words)
  /^\d+$/,                                  // pure digits
  /^(.)\1{9,}/,                             // long repeated character
  /^https?:\/\//,                           // URLs
  /^\d{4}-\d{2}-\d{2}/,                    // ISO dates
  /^[A-Z][a-z]+(?:[A-Z][a-z]+){2,}$/,     // CamelCase identifiers
  /^[a-z]+(?:-[a-z]+){2,}$/,               // kebab-case identifiers
  /^(?:true|false|null|undefined|NaN)$/,   // JS literals
];

/**
 * Determine if a string is suspiciously high entropy.
 * @param {string} str
 * @param {number} threshold
 * @returns {boolean}
 */
export function isHighEntropy(str, threshold = 3.5) {
  if (!str || str.length < 20 || str.length > 100) return false;
  if (FALSE_POSITIVE_PATTERNS.some((p) => p.test(str))) return false;
  return getEntropy(str) >= threshold;
}

// Match strings inside quotes (single, double, backtick)
const QUOTED_STRING_RE = /["'`]([A-Za-z0-9+/=_\-]{20,100})["'`]/g;

/**
 * Scan content for high-entropy quoted strings.
 * @param {string} content
 * @param {number} threshold
 * @param {number} maxMatches
 * @returns {string[]}
 */
export function findHighEntropyStrings(content, threshold = 3.5, maxMatches = 10) {
  const results = [];
  let match;
  QUOTED_STRING_RE.lastIndex = 0;
  while ((match = QUOTED_STRING_RE.exec(content)) !== null) {
    const str = match[1];
    if (isHighEntropy(str, threshold) && !results.includes(str)) {
      results.push(str);
      if (results.length >= maxMatches) break;
    }
  }
  return results;
}
