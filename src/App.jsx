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

  export default function App() {
    const [session, setSession] = useState(null);
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
      testXss: false,
      testOpenRedirect: false,
      testCorsAbuse: false,
      testCrlf: false,
      testSsrf: false,
      testHostHeader: false,
      testVerbTampering: false,
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
    const [scanStats, setScanStats] = useState({
      endpoint: '-',
      status: 200,
      responseTime: 0,
      vulnScore: 'A',
      scanCount: 0
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    // On mount, fetch session
    useEffect(() => {
      getSession().then(sess => setSession(sess));
    }, []);

    // Handle login
    const handleLogin = async ({ email, password }) => {
      setLoading(true);
      setError(null);
      try {
        const csrfToken = getCSRFToken();
        const user = await signInWithEmail(sanitizeInput(email), sanitizeInput(password), csrfToken);
        setSession({ user });
      } catch (e) {
        setError('Login failed');
      } finally {
        setLoading(false);
      }
    };

    // Handle logout
    const handleLogout = async () => {
      const csrfToken = getCSRFToken();
      await signOut(csrfToken);
      setSession(null);
    };

    // Scan logic (update scanStats for dashboard)
    const handleScan = () => {
      runCounterRef.current += 1;
      setScanStats(s => ({ ...s, scanCount: s.scanCount + 1 }));
      startScan(urlsInput, customRulesInput, options);
    };
    const handleClear = () => {
      clearAll();
      setUrlsInput('');
      setCustomRulesInput('');
    };

    // Save completed run (if session)
    useEffect(() => {
      const saveCompletedRun = async () => {
        if (!session?.user?.id || isScanning) return;
        if (results.length === 0) return;
        const runId = runCounterRef.current;
        if (runId === 0 || runId === lastCompletedRunRef.current) return;
        // ...existing code...
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

    const isAdmin = isAdminUser(session?.user);

    // If not logged in, show premium login panel
    if (!session) {
      return <LoginPanel onLogin={handleLogin} loading={loading} error={error} />;
    }

    // Premium hero + dashboard
    return (
      <div className="page">
        <ScannerDashboard stats={scanStats} />
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
