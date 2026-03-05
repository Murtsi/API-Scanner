
import React, { useState, useEffect } from 'react'
import LoginPanel from './components/LoginPanel'
import ScannerDashboard from './components/ScannerDashboard'
import ErrorBoundary from './components/ErrorBoundary'
import './App.css'

function App() {
  const [session, setSession] = useState(null)
  const [stats, setStats] = useState({ scanCount: 0, totalApis: 0, vulnsFound: 0 })
  const [loading, setLoading] = useState(true)

  const handleLogin = (userData) => setSession(userData)
  const handleSignOut = () => {
    setSession(null)
    localStorage.clear()
  }

  useEffect(() => {
    // Load stats from localStorage/API
    setLoading(false)
  }, [])

  if (loading) return <div className="loading">Loading...</div>
  return (
    <ErrorBoundary>
      <div className="App">
        {!session ? (
          <LoginPanel onLogin={handleLogin} />
        ) : (
          <>
            <header>API Scanner Pro | Scans: {stats?.scanCount || 0}</header>
            <button onClick={handleSignOut}>Logout</button>
            <ScannerDashboard session={session} stats={stats} />
          </>
        )}
      </div>
    </ErrorBoundary>
  )
}

export default App
