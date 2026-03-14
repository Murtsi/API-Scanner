import React, { useState, useCallback } from 'react'
import Header from './components/Header'
import ScannerPanel from './components/ScannerPanel'
import MethodsPanel from './components/MethodsPanel'
import ResultsPanel from './components/ResultsPanel'
import HistoryPanel from './components/HistoryPanel'
import RulesPanel from './components/RulesPanel'
import { useScanner } from './hooks/useScanner'
import { PASSIVE_MODULES, passiveModuleDefaults } from './utils/passiveModules'
import { exportJson, exportCsv } from './utils/export'
// NO CSS import — app.css is loaded in main.jsx

function App() {
  const [urlsInput, setUrlsInput] = useState('')
  const [customRulesInput, setCustomRulesInput] = useState('')
  const [options, setOptions] = useState(passiveModuleDefaults)
  const [historyRefreshToken, setHistoryRefreshToken] = useState(0)

  const { results, log, isScanning, startScan, stopScan, clearAll, hydrateFromHistory } =
    useScanner()

  const handleScan = useCallback(async () => {
    await startScan(urlsInput, customRulesInput, options)
    setHistoryRefreshToken((t) => t + 1)
  }, [startScan, urlsInput, customRulesInput, options])

  const handleClear = useCallback(() => {
    clearAll()
    setUrlsInput('')
  }, [clearAll])

  const handleLoadRun = useCallback((run) => {
    hydrateFromHistory(run.result)
  }, [hydrateFromHistory])

  return (
    <div id="app" className="app-layout">
      <Header />

      {/* Top row: Target card + Methods card */}
      <div className="top-row">
        <div className="col-scanner">
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
        </div>
        <div className="col-methods">
          <MethodsPanel
            options={options}
            setOptions={setOptions}
            isScanning={isScanning}
            passiveModules={PASSIVE_MODULES}
          />
        </div>
      </div>

      {/* Full-width results */}
      <div className="results-row">
        <ResultsPanel
          results={results}
          isScanning={isScanning}
          onExportJson={() => exportJson(results)}
          onExportCsv={() => exportCsv(results)}
        />
      </div>

      {/* Bottom panels */}
      <div className="bottom-panels">
        <RulesPanel />
        <HistoryPanel
          refreshToken={historyRefreshToken}
          onLoadRun={handleLoadRun}
        />
      </div>
    </div>
  )
}

export default App
