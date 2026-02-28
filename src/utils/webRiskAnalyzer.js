function addFinding(findings, finding) {
  if (!finding.matches || finding.matches.length === 0) return;
  findings.push(finding);
}

export function analyzeWebRisks({ content, headers, url }) {
  const findings = [];
  const text = content || '';

  const directoryListingMatches = [];
  if (/<title>\s*index of\b/i.test(text)) {
    directoryListingMatches.push('HTML title indicates directory listing (Index of ...)');
  }
  if (/<h1>\s*index of\b/i.test(text)) {
    directoryListingMatches.push('Page heading indicates directory listing (Index of ...)');
  }

  addFinding(findings, {
    id: 'web-directory-listing',
    name: 'Directory Listing Enabled',
    category: 'Information Disclosure',
    severity: 'medium',
    description: 'The response content appears to expose a server directory listing.',
    guidance: 'Disable auto-indexing in your web server and block public listing of directory contents.',
    matches: directoryListingMatches,
    sources: [url],
  });

  const stackTracePatterns = [
    /Traceback \(most recent call last\)/i,
    /Exception in thread/i,
    /Stack trace:/i,
    /Fatal error:\s+Uncaught/i,
    /at\s+[\w$.]+\([^)]+\)/i,
    /SQLSTATE\[[A-Z0-9]+\]/i,
  ];

  const stackTraceMatches = stackTracePatterns
    .filter((pattern) => pattern.test(text))
    .map((pattern) => pattern.toString());

  addFinding(findings, {
    id: 'web-stack-trace-disclosure',
    name: 'Stack Trace Disclosure',
    category: 'Information Disclosure',
    severity: 'medium',
    description: 'The response appears to expose internal stack traces or verbose error details.',
    guidance: 'Disable verbose error pages in production and return generic error responses to clients.',
    matches: stackTraceMatches,
    sources: [url],
  });

  const sourceMapMatches = [];
  if (/sourceMappingURL\s*=\s*[^\s]+\.map/gi.test(text)) {
    sourceMapMatches.push('sourceMappingURL reference to .map file found');
  }
  if (/\.map(\?|"|'|\s|$)/i.test(text) && /\/assets\/|\.js/i.test(text)) {
    sourceMapMatches.push('Potential source map artifact reference detected');
  }

  addFinding(findings, {
    id: 'web-source-map-leak',
    name: 'Potential Source Map Exposure',
    category: 'Information Disclosure',
    severity: 'low',
    description: 'Source map references can leak original source code, comments, and internal paths.',
    guidance: 'Avoid exposing production source maps publicly unless intentionally required.',
    matches: sourceMapMatches,
    sources: [url],
  });

  const debugHeaderNames = [
    'x-debug-token',
    'x-debug-token-link',
    'x-source-map',
    'x-sourcemap',
    'x-runtime',
  ];

  const debugHeaderMatches = [];
  if (headers && typeof headers.get === 'function') {
    for (const name of debugHeaderNames) {
      const value = headers.get(name);
      if (value) {
        debugHeaderMatches.push(`${name}: ${value}`);
      }
    }
  }

  addFinding(findings, {
    id: 'web-debug-header-disclosure',
    name: 'Debug Header Disclosure',
    category: 'Information Disclosure',
    severity: 'low',
    description: 'Debug-oriented response headers may reveal internal routing, tooling, or profiling data.',
    guidance: 'Strip debug headers from production responses at the app or reverse-proxy layer.',
    matches: debugHeaderMatches,
    sources: [url],
    type: 'header',
  });

  return findings;
}
