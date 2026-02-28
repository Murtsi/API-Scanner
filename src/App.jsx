import { useState } from 'react';
import Header from './components/Header.jsx';
import ScannerPanel from './components/ScannerPanel.jsx';
import ResultsPanel from './components/ResultsPanel.jsx';
import RulesPanel from './components/RulesPanel.jsx';
import { useScanner } from './hooks/useScanner.js';
import { exportJson, exportCsv } from './utils/export.js';
import { SCAN_CONFIG } from './config/constants.js';

export default function App() {
  const [urlsInput, setUrlsInput] = useState('');
  const [customRulesInput, setCustomRulesInput] = useState('');
  const [options, setOptions] = useState({
    // Passive — core
    scanAssets: true,
    checkExposed: true,
    checkHeaders: true,
    // Passive — enhanced
    checkDomSinks: false,
    checkOutdatedLibs: false,
    checkSourceMaps: false,
    checkSensitiveStorage: false,
    checkSri: false,
    checkRobots: false,
    // Reconnaissance
    reconFingerprint: false,
    reconCloud: false,
    reconGraphql: false,
    // Active — injection
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
    // Advanced
    entropyThreshold: SCAN_CONFIG.ENTROPY_THRESHOLD,
    maxMatchesPerRule: SCAN_CONFIG.MAX_MATCHES_PER_RULE,
  });

  const { results, log, isScanning, startScan, stopScan, clearAll } = useScanner();

  const handleScan = () => startScan(urlsInput, customRulesInput, options);
  const handleClear = () => {
    clearAll();
    setUrlsInput('');
    setCustomRulesInput('');
  };

  return (
    <div className="page">
      <Header />
      <div className="layout">
        <div className="left-col">
          <ScannerPanel
            urlsInput={urlsInput}
            setUrlsInput={setUrlsInput}
            customRulesInput={customRulesInput}
            setCustomRulesInput={setCustomRulesInput}
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
