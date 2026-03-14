import { useState } from 'react';

// ── Active test definitions ──────────────────────────────────────────────────
const ACTIVE_GROUPS = [
  {
    label: 'Injection',
    icon: '💉',
    accent: '#f43f5e',
    tests: [
      { key: 'testSqliError',     label: 'SQL Injection',      sub: 'Error-Based' },
      { key: 'testSqliBlind',     label: 'SQL Injection',      sub: 'Time-Based Blind' },
      { key: 'testNosql',         label: 'NoSQL Injection',    sub: 'MongoDB Operators' },
      { key: 'testCmdi',          label: 'Command Injection',  sub: 'OS Shell' },
      { key: 'testPathTraversal', label: 'Path Traversal',     sub: 'LFI / File Read' },
      { key: 'testSsti',          label: 'Template Injection', sub: 'SSTI' },
      { key: 'testXxe',           label: 'XXE',                sub: 'XML Entity' },
    ],
  },
  {
    label: 'Client-Side',
    icon: '🌐',
    accent: '#fb923c',
    tests: [
      { key: 'testXss',           label: 'XSS Reflection',    sub: 'Reflected' },
      { key: 'testOpenRedirect',  label: 'Open Redirect',     sub: 'URL Parameter' },
      { key: 'testCorsAbuse',     label: 'CORS',              sub: 'Origin Reflection' },
      { key: 'testCorsNullOrigin',label: 'CORS',              sub: 'Null Origin' },
      { key: 'testCrlf',          label: 'CRLF Injection',    sub: 'Header Splitting' },
      { key: 'testJsonp',         label: 'JSONP',             sub: 'Callback Detection' },
    ],
  },
  {
    label: 'Infrastructure',
    icon: '🏗',
    accent: '#fbbf24',
    tests: [
      { key: 'testSsrf',           label: 'SSRF',            sub: 'Internal Network' },
      { key: 'testHostHeader',     label: 'Host Header',     sub: 'Injection' },
      { key: 'testVerbTampering',  label: 'Verb Tampering',  sub: 'TRACE / DELETE' },
      { key: 'testApiVersionEnum', label: 'API Versions',    sub: 'Enumeration' },
    ],
  },
  {
    label: 'Auth & Access',
    icon: '🔐',
    accent: '#a78bfa',
    tests: [
      { key: 'testJwtAnalysis',       label: 'JWT Analysis',        sub: 'alg:none / Expired' },
      { key: 'testForbiddenBypass',   label: '403/401 Bypass',      sub: 'Path & Header Tricks' },
      { key: 'testRateLimitBypass',   label: 'Rate Limit Bypass',   sub: 'IP Header Spoofing' },
      { key: 'testMassAssignment',    label: 'Mass Assignment',     sub: 'Privileged Fields' },
      { key: 'testContentTypeSwitch', label: 'Content-Type Switch', sub: 'Parser Confusion' },
    ],
  },
  {
    label: 'Business Logic',
    icon: '⚙',
    accent: '#34d399',
    tests: [
      { key: 'testIdor',              label: 'IDOR',            sub: 'ID Enumeration' },
      { key: 'testHpp',               label: 'Param Pollution', sub: 'Duplicate Params' },
      { key: 'testGraphqlIntrospect', label: 'GraphQL',         sub: 'Introspection' },
    ],
  },
];

const ENHANCED_PASSIVE = [
  { key: 'checkDomSinks',         label: 'DOM XSS Sinks',        hint: 'innerHTML, eval, document.write…' },
  { key: 'checkOutdatedLibs',     label: 'Vulnerable Libraries', hint: 'jQuery, Lodash, Bootstrap, Vue…' },
  { key: 'checkSourceMaps',       label: 'Source Map Exposure',  hint: '.map files reveal original source' },
  { key: 'checkSensitiveStorage', label: 'Sensitive Storage',    hint: 'localStorage tokens, unsafe cookies' },
  { key: 'checkSri',              label: 'Missing SRI',          hint: 'External scripts without integrity hash' },
  { key: 'checkRobots',           label: 'robots.txt Analysis',  hint: 'Disallowed paths, sitemap discovery' },
];

const RECON_OPTIONS = [
  { key: 'reconFingerprint', label: 'Tech Fingerprinting', hint: 'CMS, framework, CDN, analytics, payment' },
  { key: 'reconCloud',       label: 'Cloud Storage',       hint: 'S3, GCS, Azure Blob bucket references' },
  { key: 'reconGraphql',     label: 'GraphQL Discovery',   hint: 'Endpoint references in HTML/JS' },
];

const ALL_ACTIVE_KEYS = ACTIVE_GROUPS.flatMap((g) => g.tests.map((t) => t.key));
const ALL_PASSIVE_KEYS = ['scanAssets', 'checkExposed', ...ENHANCED_PASSIVE.map((o) => o.key)];
const ALL_RECON_KEYS = RECON_OPTIONS.map((o) => o.key);

export default function MethodsPanel({ options, setOptions, isScanning, passiveModules }) {
  const [passiveOpen, setPassiveOpen]   = useState(false);
  const [reconOpen,   setReconOpen]     = useState(false);
  const [activeOpen,  setActiveOpen]    = useState(false);

  const setOpt = (key, val) => setOptions((p) => ({ ...p, [key]: val }));

  // counts
  const passiveCount = ALL_PASSIVE_KEYS.filter((k) => options[k]).length;
  const reconCount   = ALL_RECON_KEYS.filter((k) => options[k]).length;
  const activeCount  = ALL_ACTIVE_KEYS.filter((k) => options[k]).length;
  const someActive   = activeCount > 0;

  const passiveOn = passiveCount > 0;
  const reconOn   = reconCount > 0;
  const activeOn  = activeCount > 0;

  function toggleAll(keys, currentCount) {
    const next = currentCount === 0;
    setOptions((p) => ({
      ...p,
      ...Object.fromEntries(keys.map((k) => [k, next])),
    }));
  }

  return (
    <div className="methods-card">
      <div className="methods-card-title">What to Check</div>

      {/* ── Passive Analysis ───────────────────────────────────────────────── */}
      <div className={`method-row${passiveOn ? ' passive-on' : ''}`}>
        <button
          className={`method-switch sw-on${passiveOn ? ' sw-passive' : ''}`}
          onClick={() => toggleAll(ALL_PASSIVE_KEYS, passiveCount)}
          disabled={isScanning}
          title={passiveOn ? 'Disable passive analysis' : 'Enable passive analysis'}
          aria-label="Toggle passive analysis"
        />
        <div className="method-body">
          <div className="method-name">🔍 Passive Analysis</div>
          <div className="method-desc">
            Reads HTML &amp; JavaScript — finds exposed secrets, insecure headers, vulnerable
            libraries. <strong>No requests sent.</strong> Safe to run on any site.
            {passiveOn && <span style={{color:'var(--passive-color)',marginLeft:'6px'}}>({passiveCount} checks on)</span>}
          </div>
        </div>
        <span className="method-risk risk-safe">SAFE</span>
        <button
          className={`method-expand${passiveOpen ? ' open' : ''}`}
          onClick={() => setPassiveOpen((v) => !v)}
          aria-label="Expand passive options"
        >›</button>
      </div>

      {passiveOpen && (
        <div className="method-detail">
          <div className="method-detail-desc">
            Select which passive checks to run. All are safe — they only analyse data already fetched.
          </div>
          <div className="method-detail-grid">
            {[
              { key: 'scanAssets',   label: 'JS Assets',     sub: 'Scan linked JavaScript bundles' },
              { key: 'checkExposed', label: 'Exposed Files',  sub: 'Test 130+ common paths' },
              ...passiveModules.map((m) => ({ key: m.optionKey, label: m.label, sub: '' })),
              ...ENHANCED_PASSIVE.map((o) => ({ key: o.key, label: o.label, sub: o.hint })),
            ].map(({ key, label, sub }) => (
              <label
                key={key}
                className={`method-detail-item${options[key] ? ' item-on' : ''}`}
                style={{ '--group-accent': 'var(--passive-color)' }}
              >
                <input
                  type="checkbox"
                  checked={!!options[key]}
                  onChange={(e) => setOpt(key, e.target.checked)}
                  disabled={isScanning}
                />
                <span>
                  <span className="method-detail-name">{label}</span>
                  {sub && <span className="method-detail-sub"> — {sub}</span>}
                </span>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* ── Reconnaissance ─────────────────────────────────────────────────── */}
      <div className={`method-row${reconOn ? ' recon-on' : ''}`}>
        <button
          className={`method-switch sw-on${reconOn ? ' sw-recon' : ''}`}
          onClick={() => toggleAll(ALL_RECON_KEYS, reconCount)}
          disabled={isScanning}
          title={reconOn ? 'Disable reconnaissance' : 'Enable reconnaissance'}
          aria-label="Toggle reconnaissance"
        />
        <div className="method-body">
          <div className="method-name">🗺 Reconnaissance</div>
          <div className="method-desc">
            Identifies technology stack, cloud storage references, and API endpoints.
            Uses only data already fetched — <strong>no new requests.</strong>
            {reconOn && <span style={{color:'var(--recon-color)',marginLeft:'6px'}}>({reconCount} checks on)</span>}
          </div>
        </div>
        <span className="method-risk risk-passive">PASSIVE</span>
        <button
          className={`method-expand${reconOpen ? ' open' : ''}`}
          onClick={() => setReconOpen((v) => !v)}
          aria-label="Expand recon options"
        >›</button>
      </div>

      {reconOpen && (
        <div className="method-detail">
          <div className="method-detail-desc">
            Passive intelligence gathering from already-fetched content. No additional requests.
          </div>
          <div className="method-detail-grid">
            {RECON_OPTIONS.map(({ key, label, hint }) => (
              <label
                key={key}
                className={`method-detail-item${options[key] ? ' item-on' : ''}`}
                style={{ '--group-accent': 'var(--recon-color)' }}
              >
                <input
                  type="checkbox"
                  checked={!!options[key]}
                  onChange={(e) => setOpt(key, e.target.checked)}
                  disabled={isScanning}
                />
                <span>
                  <span className="method-detail-name">{label}</span>
                  {hint && <span className="method-detail-sub"> — {hint}</span>}
                </span>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* ── Active Testing ─────────────────────────────────────────────────── */}
      <div className={`method-row${activeOn ? ' active-on' : ' method-off'}`}>
        <button
          className={`method-switch sw-on${activeOn ? ' sw-active' : ''}`}
          onClick={() => toggleAll(ALL_ACTIVE_KEYS, activeCount)}
          disabled={isScanning}
          title={activeOn ? 'Disable active testing' : 'Enable active testing'}
          aria-label="Toggle active testing"
        />
        <div className="method-body">
          <div className="method-name">⚠ Active Attack Testing</div>
          <div className="method-desc">
            Sends real attack payloads — SQL injection, XSS, SSRF and {ALL_ACTIVE_KEYS.length - 3} more tests.{' '}
            <span className="warn-red">Only use on sites you own or have explicit written permission to test.</span>
            {activeOn && <span style={{color:'var(--accent)',marginLeft:'6px'}}>({activeCount} tests on)</span>}
          </div>
        </div>
        <span className="method-risk risk-danger">{ALL_ACTIVE_KEYS.length} TESTS</span>
        <button
          className={`method-expand${activeOpen ? ' open' : ''}`}
          onClick={() => setActiveOpen((v) => !v)}
          aria-label="Expand active test options"
        >›</button>
      </div>

      {activeOpen && (
        <div className="method-detail">
          {someActive && (
            <div className="method-warn-banner">
              <span>⚠</span>
              <span>Sends real attack payloads to discovered endpoints — {activeCount} test{activeCount !== 1 ? 's' : ''} enabled. Only scan targets you own or have explicit written permission to test.</span>
            </div>
          )}
          {ACTIVE_GROUPS.map((group) => {
            const groupKeys = group.tests.map((t) => t.key);
            const allGroupOn = groupKeys.every((k) => options[k]);
            return (
              <div key={group.label} style={{ marginTop: '6px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{ fontSize: '0.68rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: group.accent }}>
                    {group.icon} {group.label}
                  </span>
                  <button
                    className={`panel-select-all${allGroupOn ? ' panel-select-on' : ''}`}
                    style={{ '--passive-color': group.accent }}
                    onClick={() => {
                      setOptions((p) => ({
                        ...p,
                        ...Object.fromEntries(groupKeys.map((k) => [k, !allGroupOn])),
                      }));
                    }}
                    disabled={isScanning}
                  >{allGroupOn ? 'Off' : 'All'}</button>
                </div>
                <div className="method-detail-grid">
                  {group.tests.map(({ key, label, sub }) => (
                    <label
                      key={key}
                      className={`method-detail-item${options[key] ? ' item-on' : ''}`}
                      style={{ '--group-accent': group.accent }}
                    >
                      <input
                        type="checkbox"
                        checked={!!options[key]}
                        onChange={(e) => setOpt(key, e.target.checked)}
                        disabled={isScanning}
                      />
                      <span>
                        <span className="method-detail-name">{label}</span>
                        <span className="method-detail-sub"> — {sub}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
