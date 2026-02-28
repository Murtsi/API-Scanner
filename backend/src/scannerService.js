import { BASE_RULES } from '../../src/utils/patterns.js';
import { EXPOSED_PATHS, SCAN_CONFIG, SEVERITY_ORDER } from '../../src/config/constants.js';
import { analyzeSecurityHeaders } from '../../src/utils/headerAnalyzer.js';
import { findHighEntropyStrings } from '../../src/utils/entropy.js';

const DEFAULT_TIMEOUT = Number.parseInt(process.env.API_SCANNER_TIMEOUT_MS || `${SCAN_CONFIG.FETCH_TIMEOUT_MS}`, 10);

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

function safeRegex(pattern, flags) {
  try {
    if (pattern instanceof RegExp) {
      const computedFlags = flags ?? (pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
      return new RegExp(pattern.source, computedFlags);
    }

    const computedFlags = flags ?? 'g';
    return new RegExp(pattern, computedFlags.includes('g') ? computedFlags : `${computedFlags}g`);
  } catch {
    return null;
  }
}

async function fetchWithTimeout(url, timeoutMs = DEFAULT_TIMEOUT) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'user-agent': 'API-Scanner-Backend/0.1',
      },
    });
    clearTimeout(timer);
    return response;
  } catch (error) {
    clearTimeout(timer);
    throw error;
  }
}

async function fetchContent(url, timeoutMs = DEFAULT_TIMEOUT) {
  try {
    const response = await fetchWithTimeout(url, timeoutMs);
    const text = await response.text();
    return {
      text,
      status: response.status,
      headers: response.headers,
      error: null,
    };
  } catch (error) {
    const message = error?.name === 'AbortError' ? `Timeout (${timeoutMs}ms)` : (error?.message || 'Request failed');
    return {
      text: '',
      status: null,
      headers: null,
      error: message,
    };
  }
}

function extractFindings(content, rules, entropyThreshold, maxMatchesPerRule) {
  const findings = [];

  for (const rule of rules) {
    const regex = safeRegex(rule.regex);
    if (!regex) continue;

    const matches = [];
    regex.lastIndex = 0;

    let hit;
    while ((hit = regex.exec(content)) !== null) {
      const value = (hit[1] || hit[0]).trim();
      if (value && !matches.includes(value)) {
        matches.push(value);
      }
      if (matches.length >= maxMatchesPerRule) {
        break;
      }
    }

    if (matches.length > 0) {
      findings.push({
        ...rule,
        matches,
        sources: [],
      });
    }
  }

  const entropyMatches = findHighEntropyStrings(content, entropyThreshold, SCAN_CONFIG.MAX_ENTROPY_MATCHES);
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

function extractAssets(html, baseUrl) {
  const set = new Set();

  const scriptRe = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  const preloadRe = /<link[^>]+(?:rel=["'][^"']*(?:modulepreload|preload)[^"']*["'])[^>]+href=["']([^"']+)["'][^>]*>/gi;

  const collect = (re) => {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(html)) !== null) {
      try {
        const absolute = new URL(m[1], baseUrl).href;
        if (/\.js(\?.*)?$/i.test(absolute)) {
          set.add(absolute);
        }
      } catch {
      }
    }
  };

  collect(scriptRe);
  collect(preloadRe);

  return [...set].slice(0, SCAN_CONFIG.MAX_ASSETS);
}

async function checkExposed(baseUrl, timeoutMs) {
  const origin = new URL(baseUrl).origin;
  const results = [];
  const concurrency = 6;

  for (let i = 0; i < EXPOSED_PATHS.length; i += concurrency) {
    const chunk = EXPOSED_PATHS.slice(i, i + concurrency);
    const settled = await Promise.allSettled(
      chunk.map(async (path) => {
        const url = `${origin}/${path}`;
        const response = await fetchWithTimeout(url, timeoutMs);
        return { path, url, status: response.status };
      })
    );

    for (const entry of settled) {
      if (entry.status !== 'fulfilled') continue;
      if ([200, 301, 302].includes(entry.value.status)) {
        results.push(entry.value);
      }
    }
  }

  return results;
}

function mergeFindingsWithSource(findingsMap, findings, source) {
  for (const finding of findings) {
    if (findingsMap.has(finding.id)) {
      const existing = findingsMap.get(finding.id);
      for (const match of finding.matches ?? []) {
        if (!existing.matches.includes(match)) {
          existing.matches.push(match);
        }
      }
      if (!existing.sources.includes(source)) {
        existing.sources.push(source);
      }
    } else {
      findingsMap.set(finding.id, {
        ...finding,
        matches: [...(finding.matches ?? [])],
        sources: [source],
      });
    }
  }
}

export async function scanTarget(url, options = {}) {
  const timeoutMs = Number.parseInt(options.fetchTimeoutMs || `${DEFAULT_TIMEOUT}`, 10);
  const entropyThreshold = Number.isFinite(options.entropyThreshold)
    ? clamp(options.entropyThreshold, 2.5, 5)
    : SCAN_CONFIG.ENTROPY_THRESHOLD;
  const maxMatchesPerRule = Number.isFinite(options.maxMatchesPerRule)
    ? clamp(options.maxMatchesPerRule, 1, 25)
    : SCAN_CONFIG.MAX_MATCHES_PER_RULE;

  const targetResult = {
    url,
    findings: [],
    assets: [],
    exposedFiles: [],
    duration: 0,
    status: 'ok',
    error: null,
    notes: [],
  };

  const startedAt = Date.now();
  const main = await fetchContent(url, timeoutMs);

  if (main.error || !main.text) {
    targetResult.status = 'error';
    targetResult.error = main.error || `HTTP ${main.status}`;
    targetResult.duration = Date.now() - startedAt;
    return targetResult;
  }

  const findingsMap = new Map();

  const baseFindings = extractFindings(main.text, BASE_RULES, entropyThreshold, maxMatchesPerRule);
  mergeFindingsWithSource(findingsMap, baseFindings, url);

  if (options.checkHeaders !== false) {
    const headerFindings = analyzeSecurityHeaders(main.headers, url);
    for (const finding of headerFindings) {
      findingsMap.set(finding.id, finding);
    }
  }

  if (options.scanAssets) {
    const assets = extractAssets(main.text, url);
    targetResult.assets = assets;

    for (const assetUrl of assets) {
      const assetResponse = await fetchContent(assetUrl, timeoutMs);
      if (!assetResponse.text) continue;
      const assetFindings = extractFindings(assetResponse.text, BASE_RULES, entropyThreshold, maxMatchesPerRule);
      mergeFindingsWithSource(findingsMap, assetFindings, assetUrl);
    }
  }

  if (options.checkExposed) {
    try {
      targetResult.exposedFiles = await checkExposed(url, timeoutMs);
    } catch {
      targetResult.notes.push('Exposed-path checks partially failed due to network/timeouts.');
    }
  }

  const requestedActive = [
    options.testSqliError,
    options.testSqliBlind,
    options.testNosql,
    options.testXss,
  ].some(Boolean);

  if (requestedActive) {
    targetResult.notes.push('Active exploit-style tests are not enabled in backend MVP yet.');
  }

  targetResult.findings = [...findingsMap.values()].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  targetResult.duration = Date.now() - startedAt;
  return targetResult;
}

export async function runScanJob(job, handlers) {
  const results = [];
  const startedAt = Date.now();

  for (let index = 0; index < job.targets.length; index += 1) {
    const target = job.targets[index];

    if (handlers.shouldCancel()) {
      throw new Error('Job cancelled');
    }

    handlers.onProgress({
      currentTarget: target,
      completedTargets: index,
    });

    handlers.onLog(`Scanning ${target}`);
    const result = await scanTarget(target, job.options);
    results.push(result);

    handlers.onProgress({
      currentTarget: null,
      completedTargets: index + 1,
    });
  }

  return {
    summary: {
      totalTargets: results.length,
      totalFindingTypes: results.reduce((acc, item) => acc + item.findings.length, 0),
      totalExposedFiles: results.reduce((acc, item) => acc + item.exposedFiles.length, 0),
      durationMs: Date.now() - startedAt,
    },
    targets: results,
  };
}
