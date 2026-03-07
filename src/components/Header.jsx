import { BASE_RULES } from '../utils/patterns.js';

export default function Header() {
  return (
    <header className="header">
      {/* Brand */}
      <div className="brand">
        <div className="logo" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path
              d="M12 2L4 6V12C4 16.42 7.61 20.57 12 22C16.39 20.57 20 16.42 20 12V6L12 2Z"
              fill="rgba(232,64,74,0.15)"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M9 12L11 14L15 10"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <div className="brand-text">
          <h1>API<span className="brand-scanner">Scanner</span></h1>
          <span className="subtitle">Professional Security Assessment Platform</span>
        </div>
      </div>

      {/* Center stats */}
      <div className="header-stats">
        <div className="hstat">
          <span className="hstat-val">{BASE_RULES.length}</span>
          <span className="hstat-lbl">Detection Rules</span>
        </div>
        <div className="hstat-divider" />
        <div className="hstat">
          <span className="hstat-val">18</span>
          <span className="hstat-lbl">Attack Methods</span>
        </div>
        <div className="hstat-divider" />
        <div className="hstat">
          <span className="hstat-val">130+</span>
          <span className="hstat-lbl">Exposed Paths</span>
        </div>
      </div>

      <div className="header-user" />
    </header>
  );
}
