
import { useState } from 'react'
import LoginPanel from './components/LoginPanel'
import ScannerDashboard from './components/ScannerDashboard'


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

function App() {
  const [session, setSession] = useState(null)

  const handleLogin = (userData) => {
    setSession({ user: { id: userData.id, email: userData.email } })
  }

  const handleSignOut = () => {
    setSession(null)
    localStorage.removeItem('token')
  }

  if (!session) {
    return <LoginPanel onLogin={handleLogin} onSignOut={handleSignOut} />
  }

  return (
    <div className="App">
      <header>API Scanner Pro</header>
      <button onClick={handleSignOut}>Logout</button>
      <ScannerDashboard session={session} />
    </div>
  )
}

export default App
