import React, { useState, useCallback } from 'react'
import Header from './components/Header'
import LoginPanel from './components/LoginPanel'
import ScannerPanel from './components/ScannerPanel'
import ResultsPanel from './components/ResultsPanel'
import HistoryPanel from './components/HistoryPanel'
import RulesPanel from './components/RulesPanel'
import AdminPanel from './components/AdminPanel'
import { useScanner } from './hooks/useScanner'
import { getSession, signOut, isAdminUser } from './lib/auth'
import { PASSIVE_MODULES, passiveModuleDefaults } from './utils/passiveModules'
import { exportJson, exportCsv } from './utils/export'
// NO CSS import — app.css is loaded in main.jsx

function App() {
  const [session, setSession] = useState(() => getSession())
  const [urlsInput, setUrlsInput] = useState('')
  const [customRulesInput, setCustomRulesInput] = useState('')
  const [options, setOptions] = useState(passiveModuleDefaults)
  const [historyRefreshToken, setHistoryRefreshToken] = useState(0)

  const { results, log, isScanning, startScan, stopScan, clearAll, hydrateFromHistory } =
    useScanner()

  // getSession() returns { user: {...} } — extract the user object
  const user = session?.user ?? session
  const isAdmin = isAdminUser(user)

  const handleLogin = (user) => setSession({ user })

  const handleSignOut = () => {
    signOut()
    setSession(null)
  }

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

  if (!session) {
    return <LoginPanel onLogin={handleLogin} />
  }

  return (
    <div id="app">
      <Header user={user} isAdmin={isAdmin} onSignOut={handleSignOut} />

      <main className="main-grid">
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

        <div className="col-results">
          <ResultsPanel
            results={results}
            isScanning={isScanning}
            onExportJson={() => exportJson(results)}
            onExportCsv={() => exportCsv(results)}
          />
        </div>
      </main>

      <div className="bottom-panels">
        <RulesPanel />
        <HistoryPanel
          refreshToken={historyRefreshToken}
          onLoadRun={handleLoadRun}
        />
        {isAdmin && <AdminPanel />}
      </div>
    </div>
  )
}

export default App
