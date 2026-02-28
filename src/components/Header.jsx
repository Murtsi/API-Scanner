import { BASE_RULES } from '../utils/patterns.js';

export default function Header() {
  return (
    <header className="header">
      <div className="brand">
        <div className="logo" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path
              d="M12 2L4 6V12C4 16.42 7.61 20.57 12 22C16.39 20.57 20 16.42 20 12V6L12 2Z"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M9 12L11 14L15 10"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <div>
          <h1>API-Scanner</h1>
          <span className="subtitle">Secret &amp; credential detector for public websites</span>
        </div>
      </div>
      <div className="header-badges">
        <span className="pill">v2.0</span>
        <span className="pill">{BASE_RULES.length} rules</span>
        <span className="pill">Client-side</span>
      </div>
    </header>
  );
}
