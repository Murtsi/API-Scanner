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
    scanAssets: true,
    checkExposed: true,
    checkHeaders: true,
    testSqliError: false,
    testSqliBlind: false,
    testNosql: false,
    testXss: false,
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
        Scan only targets you own or have explicit permission to test. Handle all discoveries responsibly.
      </footer>
    </div>
  );
}
