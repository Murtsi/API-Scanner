
import React, { useState, useEffect } from 'react'
import LoginPanel from './components/LoginPanel'
import ScannerDashboard from './components/ScannerDashboard'
import { getSession, signOut } from './lib/auth.js'
// NO CSS import - use Tailwind only

function App() {
  const [session, setSession] = useState(() => getSession())
  const [stats] = useState({ scanCount: 0, totalApis: 0, vulnsFound: 0 })

  const handleLogin = (user) => setSession(user)

  const handleSignOut = () => {
    signOut()
    setSession(null)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-8">
      {!session ? (
        <div className="max-w-md mx-auto mt-20">
          <LoginPanel onLogin={handleLogin} />
        </div>
      ) : (
        <div>
          <header className="text-3xl font-bold text-white mb-8">
            API Scanner Pro
          </header>
          <button
            onClick={handleSignOut}
            className="bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700 mb-8"
          >
            Logout
          </button>
          <ScannerDashboard session={session} stats={stats} />
        </div>
      )}
    </div>
  )
}

export default App
