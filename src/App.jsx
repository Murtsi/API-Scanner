import { useEffect, useRef, useState } from 'react';
import Header from './components/Header.jsx';
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
import { supabase } from './lib/supabaseClient.js';
import { isAdminUser, signInWithEmail, signOut } from './lib/auth.js';
import { createScanRun } from './lib/scanHistory.js';

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
  const [session, setSession] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [loginLoading, setLoginLoading] = useState(false);
  const [authError, setAuthError] = useState('');
  const [historyRefreshToken, setHistoryRefreshToken] = useState(0);

  const [urlsInput, setUrlsInput] = useState('');
  const [customRulesInput, setCustomRulesInput] = useState('');
  const [options, setOptions] = useState(normalizePassiveOptions({
    scanAssets: true,
    checkExposed: true,
    ...passiveModuleDefaults(),
    testSqliError: false,
    testSqliBlind: false,
    testNosql: false,
    testXss: false,
    testTraversal: false,
    testCmdi: false,
    entropyThreshold: SCAN_CONFIG.ENTROPY_THRESHOLD,
    maxMatchesPerRule: SCAN_CONFIG.MAX_MATCHES_PER_RULE,
  }));

  const { results, log, isScanning, startScan, stopScan, clearAll, hydrateFromHistory } = useScanner();
  const runCounterRef = useRef(0);
  const lastCompletedRunRef = useRef(0);

  useEffect(() => {
    let mounted = true;

    supabase.auth.getSession().then(({ data }) => {
      if (!mounted) return;
      setSession(data.session ?? null);
      setAuthLoading(false);
    });

    const { data: listener } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession ?? null);
    });

    return () => {
      mounted = false;
      listener.subscription.unsubscribe();
    };
  }, []);

  const handleScan = () => {
    runCounterRef.current += 1;
    startScan(urlsInput, customRulesInput, options);
  };
  const handleClear = () => {
    clearAll();
    setUrlsInput('');
    setCustomRulesInput('');
  };

  const handleLogin = async ({ email, password }) => {
    setAuthError('');
    setLoginLoading(true);
    const { error } = await signInWithEmail(email, password);
    if (error) {
      setAuthError(error.message);
    }
    setLoginLoading(false);
  };

  const handleSignOut = async () => {
    await signOut();
    clearAll();
  };

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

  if (authLoading) {
    return (
      <div className="auth-wrap">
        <div className="card auth-card">
          <h2>Loading authentication…</h2>
          <p className="muted small">Connecting to Supabase.</p>
        </div>
      </div>
    );
  }

  if (!session) {
    return <LoginPanel onLogin={handleLogin} loading={loginLoading} error={authError} />;
  }

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
        Scan only targets you own or have explicit permission to test. Handle all discoveries responsibly.
      </footer>
    </div>
  );
}
