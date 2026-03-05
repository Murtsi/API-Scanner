
import { useState } from 'react';

// Accept onSignOut for compatibility with App.jsx
export default function LoginPanel({ onLogin, onSignOut, loading, error }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!email || !password) return;
    await onLogin({ email, password });
  };

  return (
    <div className="auth-wrap">
      <div className="auth-card" style={{ boxShadow: '0 8px 32px 0 #06B6D4', background: 'rgba(30,30,46,0.7)', backdropFilter: 'blur(16px)' }}>
        <h1 className="hero-title" style={{ fontSize: '2.5rem', marginBottom: 8 }}>Sign in</h1>
        <p className="muted small auth-subtitle" style={{ marginBottom: 24 }}>Use the account provisioned by your admin.</p>
        <form onSubmit={handleSubmit} className="auth-form" style={{ width: '100%' }}>
          <label className="auth-label" htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            className="auth-input"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            required
            style={{ animation: 'shimmer 2s infinite linear' }}
          />
          <label className="auth-label" htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            className="auth-input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            style={{ animation: 'shimmer 2s infinite linear' }}
          />
          {error ? <div className="auth-error">{error}</div> : null}
          <button type="submit" className="btn-primary" disabled={loading} style={{ width: '100%', marginTop: 8, background: 'linear-gradient(90deg, #8B5CF6 0%, #06B6D4 100%)', boxShadow: '0 2px 8px 0 #06B6D4' }}>
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        {/* Optional: sign out button for completeness, but not required for login */}
        {onSignOut && (
          <button type="button" className="btn-secondary" style={{ marginTop: 16 }} onClick={onSignOut}>
            Sign out
          </button>
        )}
      </div>
    </div>
  );
}
