import { useState } from 'react';
import { SCAN_CONFIG } from '../config/constants.js';

const SEVERITY_LEVELS = ['low', 'medium', 'high', 'critical'];

// ── Active test definitions, grouped by category ──────────────────────────────

const ACTIVE_GROUPS = [
  {
    label: 'Injection',
    tests: [
      { key: 'testSqliError',    label: 'SQL Injection',     sub: 'Error-Based' },
      { key: 'testSqliBlind',    label: 'SQL Injection',     sub: 'Time-Based Blind' },
      { key: 'testNosql',        label: 'NoSQL Injection',   sub: 'MongoDB Operators' },
      { key: 'testCmdi',         label: 'Command Injection', sub: 'OS Shell' },
      { key: 'testPathTraversal',label: 'Path Traversal',    sub: 'LFI / File Read' },
      { key: 'testSsti',         label: 'Template Injection',sub: 'SSTI' },
      { key: 'testXxe',          label: 'XML Injection',     sub: 'XXE' },
    ],
  },
  {
    label: 'Client-Side',
    tests: [
      { key: 'testXss',          label: 'XSS Reflection',   sub: 'Reflected' },
      { key: 'testOpenRedirect', label: 'Open Redirect',     sub: 'URL Parameter' },
      { key: 'testCorsAbuse',    label: 'CORS Abuse',        sub: 'Origin Reflection' },
      { key: 'testCrlf',         label: 'CRLF Injection',    sub: 'Header Splitting' },
    ],
  },
  {
    label: 'Infrastructure',
    tests: [
      { key: 'testSsrf',         label: 'SSRF',              sub: 'Internal Network' },
      { key: 'testHostHeader',   label: 'Host Header',       sub: 'Injection' },
      { key: 'testVerbTampering',label: 'Verb Tampering',    sub: 'TRACE / DELETE' },
    ],
  },
  {
    label: 'Business Logic',
    tests: [
      { key: 'testIdor',              label: 'IDOR',           sub: 'ID Enumeration' },
      { key: 'testHpp',               label: 'Param Pollution',sub: 'Duplicate Params' },
      { key: 'testGraphqlIntrospect', label: 'GraphQL',        sub: 'Introspection' },
    ],
  },
];

const ALL_ACTIVE_KEYS = ACTIVE_GROUPS.flatMap((g) => g.tests.map((t) => t.key));

// ── Enhanced passive analysis options ─────────────────────────────────────────

const ENHANCED_PASSIVE = [
  { key: 'checkDomSinks',        label: 'DOM XSS Sinks',        hint: 'innerHTML, eval, document.write, etc.' },
  { key: 'checkOutdatedLibs',    label: 'Vulnerable Libraries', hint: 'jQuery, Lodash, Bootstrap, Vue…' },
  { key: 'checkSourceMaps',      label: 'Source Map Exposure',  hint: '.map files reveal original source' },
  { key: 'checkSensitiveStorage',label: 'Sensitive Storage',    hint: 'localStorage tokens, unsafe cookies' },
  { key: 'checkSri',             label: 'Missing SRI',          hint: 'External scripts without integrity hash' },
  { key: 'checkRobots',          label: 'robots.txt Analysis',  hint: 'Disallowed paths, sitemap discovery' },
];

// ── Reconnaissance options ─────────────────────────────────────────────────────

const RECON_OPTIONS = [
  { key: 'reconFingerprint', label: 'Tech Fingerprinting', hint: 'CMS, framework, CDN, analytics, payment' },
  { key: 'reconCloud',       label: 'Cloud Storage',       hint: 'S3, GCS, Azure Blob bucket references' },
  { key: 'reconGraphql',     label: 'GraphQL Discovery',   hint: 'Endpoint references in HTML/JS' },
];

// ── Helper component ──────────────────────────────────────────────────────────

function CheckOption({ optKey, label, hint, checked, onChange, disabled }) {
  return (
    <label className="option-toggle" title={hint}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(optKey, e.target.checked)}
        disabled={disabled}
      />
      <span>
        {label}
        {hint && <span className="option-hint"> — {hint}</span>}
      </span>
    </label>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ScannerPanel({
  urlsInput,
  setUrlsInput,
  customRulesInput,
  setCustomRulesInput,
  passiveModules,
  options,
  setOptions,
  isScanning,
  log,
  onScan,
  onStop,
  onClear,
}) {
  const [showAdvanced, setShowAdvanced]         = useState(false);
  const [showEnhanced, setShowEnhanced]         = useState(false);
  const [showRecon, setShowRecon]               = useState(false);
  const [activeGroupsOpen, setActiveGroupsOpen] = useState({ Injection: true, 'Client-Side': false, Infrastructure: false, 'Business Logic': false });

  const setOpt = (key, val) => setOptions((p) => ({ ...p, [key]: val }));

  const activeCount = ALL_ACTIVE_KEYS.filter((k) => options[k]).length;
  const allActive   = activeCount === ALL_ACTIVE_KEYS.length;
  const someActive  = activeCount > 0;

  function toggleSelectAllActive() {
    const next = !allActive;
    setOptions((p) => ({
      ...p,
      ...Object.fromEntries(ALL_ACTIVE_KEYS.map((k) => [k, next])),
    }));
  }

  function toggleGroup(groupLabel, groupTests) {
    const groupKeys = groupTests.map((t) => t.key);
    const allOn = groupKeys.every((k) => options[k]);
    setOptions((p) => ({
      ...p,
      ...Object.fromEntries(groupKeys.map((k) => [k, !allOn])),
    }));
  }

  return (
    <section className="card scanner-card">
      <h2>Target URLs</h2>
      <p className="muted small">
        One URL per line — HTTP/HTTPS only. The scanner fetches HTML, linked JS bundles, and optional active tests from each target.
      </p>

      <textarea
        className="url-input"
        value={urlsInput}
        onChange={(e) => setUrlsInput(e.target.value)}
        placeholder={'https://example.com\nhttps://api.example.com'}
        spellCheck={false}
        disabled={isScanning}
        aria-label="Target URLs"
      />

      {/* ── Core passive options ───────────────────────────────────────────── */}
      <div className="section-label">Passive Scanning</div>
      <div className="options-row">
        {[
          { key: 'scanAssets',   label: 'JS assets',     hint: 'Scan all linked JavaScript bundles' },
          { key: 'checkExposed', label: 'Exposed files', hint: 'Test 130+ common exposed paths' },
          ...passiveModules.map((m) => ({ key: m.optionKey, label: m.label, hint: '' })),
        ].map(({ key, label, hint }) => (
          <label key={key} className="option-toggle" title={hint || undefined}>
            <input
              type="checkbox"
              checked={options[key]}
              onChange={(e) => setOpt(key, e.target.checked)}
              disabled={isScanning}
            />
            {label}
            {hint && <span className="option-hint"> — {hint}</span>}
          </label>
        ))}
      </div>

      {/* ── Enhanced passive analysis ──────────────────────────────────────── */}
      <div className="passive-panel">
        <button
          className="panel-toggle-btn"
          onClick={() => setShowEnhanced((v) => !v)}
        >
          <span className="passive-dot" />
          Enhanced Passive Analysis
          <span className="active-count-badge">
            {ENHANCED_PASSIVE.filter((o) => options[o.key]).length}/{ENHANCED_PASSIVE.length}
          </span>
          <span className="toggle-arrow">{showEnhanced ? '▲' : '▼'}</span>
        </button>

        {showEnhanced && (
          <div className="passive-body">
            <p className="muted small panel-desc">
              Deep JavaScript source analysis — no payloads sent. Detects dangerous code patterns, vulnerable dependencies, and information disclosures in fetched assets.
            </p>
            <div className="passive-grid">
              {ENHANCED_PASSIVE.map(({ key, label, hint }) => (
                <CheckOption
                  key={key}
                  optKey={key}
                  label={label}
                  hint={null}
                  checked={options[key]}
                  onChange={setOpt}
                  disabled={isScanning}
                />
              ))}
            </div>
            <div className="hint-list">
              {ENHANCED_PASSIVE.map(({ key, hint }) => options[key] && (
                <span key={key} className="hint-tag">{hint}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Reconnaissance ────────────────────────────────────────────────── */}
      <div className="recon-panel">
        <button
          className="panel-toggle-btn"
          onClick={() => setShowRecon((v) => !v)}
        >
          <span className="recon-dot" />
          Reconnaissance
          <span className="active-count-badge recon-badge">
            {RECON_OPTIONS.filter((o) => options[o.key]).length}/{RECON_OPTIONS.length}
          </span>
          <span className="toggle-arrow">{showRecon ? '▲' : '▼'}</span>
        </button>

        {showRecon && (
          <div className="recon-body">
            <p className="muted small panel-desc">
              Passive information gathering from already-fetched content — technology stack fingerprinting, cloud storage references, and API endpoint mapping. No additional requests.
            </p>
            <div className="passive-grid">
              {RECON_OPTIONS.map(({ key, label, hint }) => (
                <CheckOption
                  key={key}
                  optKey={key}
                  label={label}
                  hint={null}
                  checked={options[key]}
                  onChange={setOpt}
                  disabled={isScanning}
                />
              ))}
            </div>
            <div className="hint-list">
              {RECON_OPTIONS.map(({ key, hint }) => options[key] && (
                <span key={key} className="hint-tag recon-hint-tag">{hint}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Active testing ─────────────────────────────────────────────────── */}
      <div className="active-panel">
        <div className="active-panel-header">
          <div className="active-panel-title">
            <span className="active-dot" />
            Active Testing
            <span className="active-count-badge">
              {activeCount}/{ALL_ACTIVE_KEYS.length}
            </span>
          </div>
          <button
            className={`select-all-btn ${allActive ? 'select-all-on' : ''}`}
            onClick={toggleSelectAllActive}
            disabled={isScanning}
          >
            {allActive ? 'Deselect All' : 'Select All'}
          </button>
        </div>

        {ACTIVE_GROUPS.map((group) => {
          const groupKeys = group.tests.map((t) => t.key);
          const groupCount = groupKeys.filter((k) => options[k]).length;
          const isOpen = activeGroupsOpen[group.label];

          return (
            <div key={group.label} className="active-group">
              <div className="active-group-header">
                <button
                  className="active-group-toggle"
                  onClick={() => setActiveGroupsOpen((p) => ({ ...p, [group.label]: !p[group.label] }))}
                >
                  <span className={`group-arrow ${isOpen ? 'open' : ''}`}>›</span>
                  <span className="group-label-text">{group.label}</span>
                  <span className="group-count">{groupCount}/{group.tests.length}</span>
                </button>
                <button
                  className="group-select-all"
                  onClick={() => toggleGroup(group.label, group.tests)}
                  disabled={isScanning}
                >
                  {groupKeys.every((k) => options[k]) ? 'Off' : 'All'}
                </button>
              </div>

              {isOpen && (
                <div className="active-grid">
                  {group.tests.map(({ key, label, sub }) => (
                    <label
                      key={key}
                      className={`active-test-item ${options[key] ? 'active-test-on' : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={options[key]}
                        onChange={(e) => setOpt(key, e.target.checked)}
                        disabled={isScanning}
                      />
                      <span className="active-test-text">
                        <span className="active-test-name">{label}</span>
                        <span className="active-test-sub">{sub}</span>
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          );
        })}

        {someActive && (
          <div className="active-warning">
            <span className="warning-icon">⚠</span>
            Sends real attack payloads to discovered endpoints — {activeCount} test category/ies enabled.
            Only scan targets you own or have explicit written permission to test.
          </div>
        )}
      </div>

      {/* ── Advanced settings ──────────────────────────────────────────────── */}
      <button className="btn-link" onClick={() => setShowAdvanced((v) => !v)}>
        {showAdvanced ? 'Hide advanced ▲' : 'Advanced settings ▼'}
      </button>

      {showAdvanced && (
        <div className="advanced-panel">
          <div className="advanced-row">
            <label className="option-toggle">
              <input
                type="checkbox"
                checked={!!options.enableExperimentalModules}
                onChange={(e) =>
                  setOptions((p) => ({
                    ...p,
                    enableExperimentalModules: e.target.checked,
                  }))
                }
                disabled={isScanning}
              />
              Enable experimental passive modules
            </label>
          </div>

          {passiveModules.length > 0 && (
            <div className="advanced-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: '8px' }}>
              <span className="muted small">Passive module minimum severity</span>
              {passiveModules.map((module) => {
                const thresholds = options.passiveSeverityThresholds || {};
                const current = thresholds[module.id] || 'low';
                return (
                  <label key={`${module.id}-threshold`}>
                    {module.label}
                    <select
                      value={current}
                      onChange={(e) =>
                        setOptions((p) => ({
                          ...p,
                          passiveSeverityThresholds: {
                            ...(p.passiveSeverityThresholds || {}),
                            [module.id]: e.target.value,
                          },
                        }))
                      }
                      disabled={isScanning}
                    >
                      {SEVERITY_LEVELS.map((level) => (
                        <option key={level} value={level}>
                          {level}
                        </option>
                      ))}
                    </select>
                  </label>
                );
              })}
            </div>
          )}

          <div className="advanced-row">
            <label>
              Entropy threshold
              <input
                type="number"
                min="2.0"
                max="5.0"
                step="0.1"
                value={options.entropyThreshold}
                onChange={(e) =>
                  setOptions((p) => ({
                    ...p,
                    entropyThreshold: parseFloat(e.target.value) || SCAN_CONFIG.ENTROPY_THRESHOLD,
                  }))
                }
                disabled={isScanning}
              />
            </label>
            <label>
              Max matches / rule
              <input
                type="number"
                min="1"
                max="20"
                value={options.maxMatchesPerRule}
                onChange={(e) =>
                  setOptions((p) => ({
                    ...p,
                    maxMatchesPerRule: parseInt(e.target.value, 10) || SCAN_CONFIG.MAX_MATCHES_PER_RULE,
                  }))
                }
                disabled={isScanning}
              />
            </label>
          </div>

          <div className="custom-rules">
            <label className="muted small">
              Custom regex rules
              <span className="muted"> — format: <code>Name::/pattern/flags</code></span>
            </label>
            <textarea
              value={customRulesInput}
              onChange={(e) => setCustomRulesInput(e.target.value)}
              placeholder="MyRule::/sk_live_[A-Za-z0-9]{24,}/g"
              spellCheck={false}
              disabled={isScanning}
              style={{ minHeight: '80px' }}
            />
          </div>
        </div>
      )}

      {/* ── Actions ────────────────────────────────────────────────────────── */}
      <div className="actions">
        {isScanning ? (
          <button className="btn-danger" onClick={onStop}>Stop scan</button>
        ) : (
          <button className="btn-primary" onClick={onScan}>Start scan</button>
        )}
        <button className="btn-secondary" onClick={onClear} disabled={isScanning}>
          Clear
        </button>
      </div>

      {/* ── Scan log ───────────────────────────────────────────────────────── */}
      {log.length > 0 && (
        <div className="log" aria-live="polite" aria-label="Scan log">
          <div className="log-header">
            <span className="log-dot" />
            <span className="log-title">Scan log</span>
          </div>
          <div className="log-entries">
            {log.map((entry) => (
              <div key={entry.id} className={`log-entry log-${entry.type}`}>
                {entry.msg}
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
