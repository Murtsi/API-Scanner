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
import {
  testSqliEndpoints,
  testSqliTimeBased,
  testNoSqlEndpoints,
  testXssEndpoints,
  testPathTraversal,
  testCommandInjection,
  testSsti,
  testOpenRedirect,
  testSsrf,
  testHostHeaderInjection,
  testCorsMisconfiguration,
  testVerbTampering,
  testCrlfInjection,
  testGraphqlIntrospection,
  testXxe,
  testIdorEnumeration,
  testParameterPollution,
} from '../utils/vulnScanner.js';
import {
  analyzeDomSinks,
  detectOutdatedLibraries,
  detectSourceMaps,
  detectSensitiveStorage,
  detectDangerousFunctions,
  detectMissingSri,
  analyzeRobotsTxt,
  detectTechStack,
  detectCloudStorage,
  discoverGraphqlReferences,
} from '../utils/passiveScanner.js';

/**
 * Parse custom rules from a textarea string.
 * Format: "Name::/pattern/flags"  (one per line)
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

      // Collect JS content for endpoint extraction + passive analysis
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

      // Security headers analysis
      if (options.checkHeaders) {
        addLog(`  → Analysing security headers`, 'info');
        const headerFindings = analyzeSecurityHeaders(headers, url);
        for (const hf of headerFindings) findingsMap.set(hf.id, hf);
        if (headerFindings.length > 0) {
          addLog(`  ⚠ ${headerFindings.length} header issue(s) found`, 'warn');
        }
      }

      // Check exposed files / paths
      if (options.checkExposed) {
        addLog(`  → Checking exposed paths (${options.checkExposed ? 'expanded list' : ''})`, 'info');
        const exposed = await checkExposedFiles(url);
        result.exposedFiles = exposed;
        if (exposed.length > 0) {
          addLog(`  ⚠ ${exposed.length} exposed file(s) found`, 'warn');
        }
      }

      // ── Enhanced Passive Analysis ─────────────────────────────────────────────
      const combinedJsContent = jsContentChunks.join('\n');
      const combinedContent = html + '\n' + combinedJsContent;

      if (options.checkDomSinks && combinedJsContent) {
        addLog(`  → Analysing DOM XSS sinks`, 'info');
        const sinkFindings = analyzeDomSinks(combinedJsContent, url);
        for (const f of sinkFindings) findingsMap.set(f.id, f);
        if (sinkFindings.length > 0) addLog(`  ⚠ ${sinkFindings.length} DOM sink(s) found`, 'warn');
      }

      if (options.checkOutdatedLibs && combinedContent) {
        addLog(`  → Checking for vulnerable libraries`, 'info');
        const libFindings = detectOutdatedLibraries(combinedContent, url);
        for (const f of libFindings) findingsMap.set(f.id, f);
        if (libFindings.length > 0) addLog(`  ⚠ ${libFindings.length} vulnerable library/ies found`, 'warn');
      }

      if (options.checkSourceMaps && combinedJsContent) {
        addLog(`  → Checking for source map exposure`, 'info');
        const mapFindings = detectSourceMaps(combinedJsContent, url);
        for (const f of mapFindings) findingsMap.set(f.id, f);
        if (mapFindings.length > 0) addLog(`  ⚠ ${mapFindings.length} source map reference(s) found`, 'warn');
      }

      if (options.checkSensitiveStorage && combinedJsContent) {
        addLog(`  → Checking for sensitive browser storage usage`, 'info');
        const storageFindings = detectSensitiveStorage(combinedJsContent, url);
        const funcFindings = detectDangerousFunctions(combinedJsContent, url);
        for (const f of [...storageFindings, ...funcFindings]) findingsMap.set(f.id, f);
        const total = storageFindings.length + funcFindings.length;
        if (total > 0) addLog(`  ⚠ ${total} storage/function issue(s) found`, 'warn');
      }

      if (options.checkSri && html) {
        addLog(`  → Checking Subresource Integrity`, 'info');
        const sriFindings = detectMissingSri(html, url);
        for (const f of sriFindings) findingsMap.set(f.id, f);
        if (sriFindings.length > 0) addLog(`  ⚠ ${sriFindings.length} script(s) missing SRI`, 'warn');
      }

      if (options.checkRobots) {
        addLog(`  → Analysing robots.txt`, 'info');
        const robotsFindings = await analyzeRobotsTxt(url);
        for (const f of robotsFindings) findingsMap.set(f.id, f);
        if (robotsFindings.length > 0) addLog(`  ⚠ robots.txt has interesting paths`, 'warn');
      }

      // ── Reconnaissance ────────────────────────────────────────────────────────

      if (options.reconFingerprint && combinedContent) {
        addLog(`  → Technology stack fingerprinting`, 'info');
        const techFindings = detectTechStack(html, headers, url);
        for (const f of techFindings) findingsMap.set(f.id, f);
        if (techFindings.length > 0) addLog(`  → ${techFindings.length} technology/ies identified`, 'info');
      }

      if (options.reconCloud && combinedContent) {
        addLog(`  → Detecting cloud storage references`, 'info');
        const cloudFindings = detectCloudStorage(combinedContent, url);
        for (const f of cloudFindings) findingsMap.set(f.id, f);
        if (cloudFindings.length > 0) addLog(`  → ${cloudFindings.length} cloud storage reference(s) found`, 'warn');
      }

      if (options.reconGraphql && combinedContent) {
        addLog(`  → Discovering GraphQL endpoint references`, 'info');
        const gqlRefs = discoverGraphqlReferences(combinedContent, url);
        for (const f of gqlRefs) findingsMap.set(f.id, f);
        if (gqlRefs.length > 0) addLog(`  → ${gqlRefs.length} GraphQL reference(s) found`, 'info');
      }

      // ── Active Testing ────────────────────────────────────────────────────────

      const needsActive =
        options.testSqliError || options.testSqliBlind || options.testNosql || options.testXss ||
        options.testPathTraversal || options.testCmdi || options.testSsti || options.testXxe ||
        options.testOpenRedirect || options.testCorsAbuse || options.testCrlf ||
        options.testSsrf || options.testHostHeader || options.testVerbTampering ||
        options.testIdor || options.testHpp || options.testGraphqlIntrospect;

      let allEndpoints = [];
      if (needsActive) {
        const apiEndpoints = extractApiEndpoints(combinedContent, url);
        const formEndpoints = extractFormActions(html, url);
        allEndpoints = [...new Set([...apiEndpoints, ...formEndpoints])];

        if (allEndpoints.length > 0) {
          addLog(`  → Found ${allEndpoints.length} endpoint(s) for active testing`, 'info');
        } else {
          addLog(`  → No testable endpoints found — using base URL`, 'info');
          allEndpoints = [url];
        }
      }

      // Injection attacks
      if (options.testSqliError) {
        addLog(`  → SQL injection — error-based`, 'info');
        const r = await testSqliEndpoints(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} SQLi finding(s)`, 'warn');
      }

      if (options.testSqliBlind) {
        addLog(`  → SQL injection — time-based blind`, 'info');
        const r = await testSqliTimeBased(allEndpoints, 12000);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} blind SQLi finding(s)`, 'warn');
      }

      if (options.testNosql) {
        addLog(`  → NoSQL injection — MongoDB operators`, 'info');
        const r = await testNoSqlEndpoints(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} NoSQL finding(s)`, 'warn');
      }

      if (options.testCmdi) {
        addLog(`  → Command injection — OS shell metacharacters`, 'info');
        const r = await testCommandInjection(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} command injection finding(s)`, 'warn');
      }

      if (options.testPathTraversal) {
        addLog(`  → Path traversal / local file inclusion`, 'info');
        const r = await testPathTraversal(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} path traversal finding(s)`, 'warn');
      }

      if (options.testSsti) {
        addLog(`  → Server-side template injection (SSTI)`, 'info');
        const r = await testSsti(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} SSTI finding(s)`, 'warn');
      }

      if (options.testXxe) {
        addLog(`  → XML external entity (XXE) injection`, 'info');
        const r = await testXxe(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} XXE finding(s)`, 'warn');
      }

      // Client-side attacks
      if (options.testXss) {
        addLog(`  → XSS reflection testing`, 'info');
        const r = await testXssEndpoints(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} XSS finding(s)`, 'warn');
      }

      if (options.testOpenRedirect) {
        addLog(`  → Open redirect testing`, 'info');
        const r = await testOpenRedirect(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} open redirect finding(s)`, 'warn');
      }

      if (options.testCorsAbuse) {
        addLog(`  → CORS origin reflection testing`, 'info');
        const r = await testCorsMisconfiguration(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} CORS finding(s)`, 'warn');
      }

      if (options.testCrlf) {
        addLog(`  → CRLF / response splitting`, 'info');
        const r = await testCrlfInjection(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} CRLF finding(s)`, 'warn');
      }

      // Infrastructure
      if (options.testSsrf) {
        addLog(`  → SSRF — internal network probing`, 'info');
        const r = await testSsrf(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} SSRF finding(s)`, 'warn');
      }

      if (options.testHostHeader) {
        addLog(`  → Host header injection`, 'info');
        const r = await testHostHeaderInjection(url, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} host header finding(s)`, 'warn');
      }

      if (options.testVerbTampering) {
        addLog(`  → HTTP verb tampering`, 'info');
        const r = await testVerbTampering(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} verb tampering finding(s)`, 'warn');
      }

      // Business logic
      if (options.testIdor) {
        addLog(`  → IDOR enumeration`, 'info');
        const r = await testIdorEnumeration(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} IDOR finding(s)`, 'warn');
      }

      if (options.testHpp) {
        addLog(`  → HTTP parameter pollution`, 'info');
        const r = await testParameterPollution(allEndpoints, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} HPP finding(s)`, 'warn');
      }

      if (options.testGraphqlIntrospect) {
        addLog(`  → GraphQL introspection`, 'info');
        const r = await testGraphqlIntrospection(url, SCAN_CONFIG.FETCH_TIMEOUT_MS);
        for (const f of r) findingsMap.set(f.id, f);
        if (r.length > 0) addLog(`  ⚠ ${r.length} GraphQL finding(s)`, 'warn');
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
