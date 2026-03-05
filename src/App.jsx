
import { useEffect, useRef, useState } from 'react';
import ScannerDashboard from './components/ScannerDashboard.jsx';
import ScannerPanel from './components/ScannerPanel.jsx';
import ResultsPanel from './components/ResultsPanel.jsx';
import RulesPanel from './components/RulesPanel.jsx';
import LoginPanel from './components/LoginPanel.jsx';
import AdminPanel from './components/AdminPanel.jsx';
import HistoryPanel from './components/HistoryPanel.jsx';
import { useScanner } from './hooks/useScanner.js';
import { exportJson, exportCsv } from './utils/export.js';
import { SCAN_CONFIG } from './config/constants.js';
import { PASSIVE_MODULES, passiveModuleDefaults, normalizePassiveOptions } from './utils/passiveModules.js';
import { isAdminUser, getSession, signInWithEmail, signOut } from './utils/auth.js';
import { sanitizeInput, getCSRFToken } from './utils/security.js';
import './globals.css';


function mergeScanOptions(previousOptions, incomingOptions) {
  return normalizePassiveOptions({
    ...previousOptions,
    ...(incomingOptions || {}),
    passiveSeverityThresholds: {
      ...(previousOptions.passiveSeverityThresholds || {}),
      ...((incomingOptions && incomingOptions.passiveSeverityThresholds) || {}),
    },
  });
}

export default function App() {
  // Supabase authentication removed. Implement Railway/PostgreSQL-based auth state here if needed.
  const [historyRefreshToken, setHistoryRefreshToken] = useState(0);

  const [urlsInput, setUrlsInput] = useState('');
  const [customRulesInput, setCustomRulesInput] = useState('');
  const [options, setOptions] = useState(normalizePassiveOptions({
    scanAssets: true,
    checkExposed: true,
    checkHeaders: true,
    ...passiveModuleDefaults(),
    checkDomSinks: false,
    checkOutdatedLibs: false,
    checkSourceMaps: false,
    checkSensitiveStorage: false,
    checkSri: false,
    checkRobots: false,
    reconFingerprint: false,
    reconCloud: false,
    reconGraphql: false,
    testSqliError: false,
    testSqliBlind: false,
    testNosql: false,
    testCmdi: false,
    testPathTraversal: false,
    testSsti: false,
    testXxe: false,
    // Active — client-side
    testXss: false,
    testOpenRedirect: false,
    testCorsAbuse: false,
    testCrlf: false,
    // Active — infrastructure
    testSsrf: false,
    testHostHeader: false,
    testVerbTampering: false,
    // Active — business logic
    testIdor: false,
    testHpp: false,
    testGraphqlIntrospect: false,
    testTraversal: false,
    entropyThreshold: SCAN_CONFIG.ENTROPY_THRESHOLD,
    maxMatchesPerRule: SCAN_CONFIG.MAX_MATCHES_PER_RULE,
  }));

  const { results, log, isScanning, startScan, stopScan, clearAll, hydrateFromHistory } = useScanner();
  const runCounterRef = useRef(0);
  const lastCompletedRunRef = useRef(0);

  // Authentication logic removed. Add Railway/PostgreSQL-based authentication if needed.

  const handleScan = () => {
    runCounterRef.current += 1;
    startScan(urlsInput, customRulesInput, options);
  };
  const handleClear = () => {
    clearAll();
    setUrlsInput('');
    setCustomRulesInput('');
  };

  // Login and sign-out logic removed. Add Railway/PostgreSQL-based authentication if needed.

  useEffect(() => {
    const saveCompletedRun = async () => {
      if (!session?.user?.id || isScanning) return;
      if (results.length === 0) return;

      const runId = runCounterRef.current;
      if (runId === 0 || runId === lastCompletedRunRef.current) return;

      const payload = {
        urlsInput,
        customRulesInput,
        options,
        results,
        log,
        savedAt: new Date().toISOString(),
      };

      const targets = urlsInput
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.startsWith('http'));

      try {
        await createScanRun({
          userId: session.user.id,
          targets,
          options,
          result: payload,
        });
        lastCompletedRunRef.current = runId;
        setHistoryRefreshToken((v) => v + 1);
      } catch {
      }
    };

    saveCompletedRun();
  }, [session, isScanning, results, log, urlsInput, customRulesInput, options]);

    const handleLoadHistoryRun = (run) => {
      const snapshot = run?.result || {};
      hydrateFromHistory({
        results: snapshot.results || [],
        log: snapshot.log || [],
      });
      if (typeof snapshot.urlsInput === 'string') {
        setUrlsInput(snapshot.urlsInput);
      } else if (Array.isArray(run?.targets)) {
        setUrlsInput(run.targets.join('\n'));
      }
      if (typeof snapshot.customRulesInput === 'string') {
        setCustomRulesInput(snapshot.customRulesInput);
      }
      if (snapshot.options && typeof snapshot.options === 'object') {
        setOptions((prev) => mergeScanOptions(prev, snapshot.options));
      }
    };

  // Authentication UI removed. Add Railway/PostgreSQL-based authentication UI if needed.

  const isAdmin = isAdminUser(session.user);

  return (
    <div className="page">
      <Header user={session.user} isAdmin={isAdmin} onSignOut={handleSignOut} />
      <div className="layout">
        <div className="left-col">
          {isAdmin ? <AdminPanel /> : null}
          <HistoryPanel refreshToken={historyRefreshToken} onLoadRun={handleLoadHistoryRun} />
          <ScannerPanel
            urlsInput={urlsInput}
            setUrlsInput={setUrlsInput}
            customRulesInput={customRulesInput}
            setCustomRulesInput={setCustomRulesInput}
            passiveModules={PASSIVE_MODULES}
            options={options}
            setOptions={setOptions}
            isScanning={isScanning}
            log={log}
            onScan={handleScan}
            onStop={stopScan}
            onClear={handleClear}
          />
          <RulesPanel />
        </div>

        <div className="right-col">
          <ResultsPanel
            results={results}
            isScanning={isScanning}
            onExportJson={() => exportJson(results)}
            onExportCsv={() => exportCsv(results)}
          />
        </div>
      </div>

      <footer>
        Professional security scanner for authorised use only. Scan only targets you own or have explicit written permission to test. Handle all discoveries responsibly and in accordance with applicable law.
      </footer>
    </div>
  );
}
