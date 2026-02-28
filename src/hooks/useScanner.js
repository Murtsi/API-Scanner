import { useState, useCallback, useRef } from 'react';
import { BASE_RULES } from '../utils/patterns.js';
import {
  safeRegex,
  fetchContent,
  extractFindings,
  extractAssets,
  checkExposedFiles,
  scanAssetsParallel,
} from '../utils/scanner.js';
import { SCAN_CONFIG, SEVERITY_ORDER } from '../config/constants.js';
import { analyzeSecurityHeaders } from '../utils/headerAnalyzer.js';
import { extractApiEndpoints, extractFormActions } from '../utils/endpointExtractor.js';
import { testSqliEndpoints, testXssEndpoints } from '../utils/vulnScanner.js';

/**
 * Parse custom rules from a textarea string.
 * Format: "Name::/pattern/flags"  (one per line)
 * @param {string} text
 * @returns {Array}
 */
function parseCustomRules(text) {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      let name = `Custom Rule ${index + 1}`;
      let patternText = line;
      let flags = 'gi';

      if (line.includes('::')) {
        const sep = line.indexOf('::');
        name = line.slice(0, sep).trim() || name;
        patternText = line.slice(sep + 2).trim();
      }

      if (!patternText) return null;

      // Support /pattern/flags syntax
      if (patternText.startsWith('/') && patternText.lastIndexOf('/') > 0) {
        const lastSlash = patternText.lastIndexOf('/');
        flags = patternText.slice(lastSlash + 1) || 'g';
        patternText = patternText.slice(1, lastSlash);
      }

      const re = safeRegex(patternText, flags);
      if (!re) return null;

      return {
        id: `custom-${index}`,
        name,
        category: 'Custom',
        severity: 'medium',
        regex: re,
        description: 'Custom detection rule',
        custom: true,
      };
    })
    .filter(Boolean);
}

/**
 * React hook that manages all scanning state and logic.
 */
export function useScanner() {
  const [results, setResults] = useState([]);
  const [log, setLog] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const abortRef = useRef(false);

  const addLog = useCallback((msg, type = 'info') => {
    setLog((prev) => [...prev, { id: `${Date.now()}-${Math.random()}`, msg, type }]);
  }, []);

  const scanUrl = useCallback(
    async (url, options, rules) => {
      const eThreshold = options.entropyThreshold ?? SCAN_CONFIG.ENTROPY_THRESHOLD;
      const maxMatches = options.maxMatchesPerRule ?? SCAN_CONFIG.MAX_MATCHES_PER_RULE;
      const result = { url, findings: [], assets: [], exposedFiles: [], error: null, duration: 0 };
      const t0 = Date.now();

      addLog(`Fetching ${url}`, 'info');
      const { text: html, status, headers, error } = await fetchContent(url);

      if (error || !html) {
        result.error = error || `HTTP ${status}`;
        addLog(`  ✗ ${result.error}`, 'error');
        result.duration = Date.now() - t0;
        return result;
      }

      addLog(`  ✓ ${html.length.toLocaleString()} bytes (HTTP ${status})`, 'success');

      // Scan main HTML
      const mainFindings = extractFindings(html, rules, eThreshold, maxMatches);
      const findingsMap = new Map();
      for (const f of mainFindings) {
        findingsMap.set(f.id, { ...f, sources: [url] });
      }

      // Collect JS content chunks for endpoint extraction
      const jsContentChunks = [];

      // Scan linked JS assets in parallel
      if (options.scanAssets) {
        const assetUrls = extractAssets(html, url);
        result.assets = assetUrls;
        if (assetUrls.length > 0) {
          addLog(`  → Scanning ${assetUrls.length} JS asset(s) in parallel`, 'info');
          const assetFindings = await scanAssetsParallel(
            assetUrls,
            rules,
            { entropyThreshold: eThreshold, maxMatchesPerRule: maxMatches },
            (assetUrl) => {
              const name = assetUrl.split('/').pop()?.slice(0, 55) || assetUrl;
              addLog(`    ✓ ${name}`, 'info');
            },
            (_assetUrl, text) => {
              // Collect first 40 KB of each JS file for endpoint extraction
              jsContentChunks.push(text.slice(0, 40000));
            }
          );
          for (const af of assetFindings) {
            if (findingsMap.has(af.id)) {
              const ex = findingsMap.get(af.id);
              af.matches.forEach((m) => { if (!ex.matches.includes(m)) ex.matches.push(m); });
              af.sources.forEach((s) => { if (!ex.sources.includes(s)) ex.sources.push(s); });
            } else {
              findingsMap.set(af.id, af);
            }
          }
        }
      }

      // Security headers analysis (passive — uses headers already received)
      if (options.checkHeaders) {
        addLog(`  → Analysing security headers`, 'info');
        const headerFindings = analyzeSecurityHeaders(headers, url);
        for (const hf of headerFindings) {
          findingsMap.set(hf.id, hf);
        }
        if (headerFindings.length > 0) {
          addLog(`  ⚠ ${headerFindings.length} header issue(s) found`, 'warn');
        }
      }

      // Check exposed files
      if (options.checkExposed) {
        addLog(`  → Checking exposed paths`, 'info');
        const exposed = await checkExposedFiles(url);
        result.exposedFiles = exposed;
        if (exposed.length > 0) {
          addLog(`  ⚠ ${exposed.length} exposed file(s) found`, 'warn');
        }
      }

      // Active testing — extract endpoints from HTML + collected JS
      const needsActive = options.testSqli || options.testXss;
      if (needsActive) {
        const combinedContent = [html, ...jsContentChunks].join('\n');
        const apiEndpoints = extractApiEndpoints(combinedContent, url);
        const formEndpoints = extractFormActions(html, url);
        const allEndpoints = [...new Set([...apiEndpoints, ...formEndpoints])];

        if (allEndpoints.length > 0) {
          addLog(`  → Found ${allEndpoints.length} endpoint(s) for active testing`, 'info');
        }

        if (options.testSqli && allEndpoints.length > 0) {
          addLog(`  → SQL injection testing (error-based)`, 'info');
          const sqliFindings = await testSqliEndpoints(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
          for (const sf of sqliFindings) {
            findingsMap.set(sf.id, sf);
          }
          if (sqliFindings.length > 0) {
            addLog(`  ⚠ ${sqliFindings.length} SQLi finding(s)`, 'warn');
          }
        }

        if (options.testXss && allEndpoints.length > 0) {
          addLog(`  → XSS reflection testing`, 'info');
          const xssFindings = await testXssEndpoints(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
          for (const xf of xssFindings) {
            findingsMap.set(xf.id, xf);
          }
          if (xssFindings.length > 0) {
            addLog(`  ⚠ ${xssFindings.length} XSS finding(s)`, 'warn');
          }
        }
      }

      // Sort findings by severity
      result.findings = [...findingsMap.values()].sort(
        (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
      );

      result.duration = Date.now() - t0;
      const fc = result.findings.length;
      addLog(
        `  ✓ Done — ${fc} finding type(s) in ${(result.duration / 1000).toFixed(1)}s`,
        'success'
      );
      return result;
    },
    [addLog]
  );

  const startScan = useCallback(
    async (urlsText, customRulesText, options) => {
      const urls = urlsText
        .split('\n')
        .map((u) => u.trim())
        .filter((u) => u.startsWith('http'));

      if (urls.length === 0) return;

      abortRef.current = false;
      setIsScanning(true);
      setResults([]);
      setLog([]);

      const customRules = parseCustomRules(customRulesText || '');
      const rules = [...BASE_RULES, ...customRules];

      addLog(
        `Starting scan — ${urls.length} target(s), ${rules.length} rules (${customRules.length} custom)`,
        'info'
      );

      const allResults = [];
      for (const url of urls) {
        if (abortRef.current) {
          addLog('Scan stopped by user', 'warn');
          break;
        }
        const r = await scanUrl(url, options, rules);
        allResults.push(r);
        setResults([...allResults]);
      }

      const totalTypes = allResults.reduce((n, r) => n + r.findings.length, 0);
      addLog(
        `Scan complete — ${totalTypes} finding type(s) across ${allResults.length} target(s)`,
        'success'
      );
      setIsScanning(false);
    },
    [scanUrl, addLog]
  );

  const stopScan = useCallback(() => {
    abortRef.current = true;
  }, []);

  const clearAll = useCallback(() => {
    setResults([]);
    setLog([]);
  }, []);

  return { results, log, isScanning, startScan, stopScan, clearAll };
}
