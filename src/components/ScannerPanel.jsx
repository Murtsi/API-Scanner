import { useState } from 'react';
import { SCAN_CONFIG } from '../config/constants.js';

const SEVERITY_LEVELS = ['low', 'medium', 'high', 'critical'];

const ACTIVE_TESTS = [
  { key: 'testSqliError', label: 'SQL Injection',        sub: 'Error-Based' },
  { key: 'testSqliBlind', label: 'SQL Injection',        sub: 'Time-Based Blind' },
  { key: 'testNosql',     label: 'NoSQL Injection',      sub: 'MongoDB Operators' },
  { key: 'testXss',       label: 'XSS Reflection',       sub: 'Reflected Input' },
  { key: 'testTraversal', label: 'Path Traversal',       sub: 'Local File Inclusion' },
  { key: 'testCmdi',      label: 'Command Injection',    sub: 'Error / Output Based' },
];

const ACTIVE_KEYS = ACTIVE_TESTS.map((t) => t.key);

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
  const [showAdvanced, setShowAdvanced] = useState(false);

  const activeCount  = ACTIVE_KEYS.filter((k) => options[k]).length;
  const allActive    = activeCount === ACTIVE_KEYS.length;
  const someActive   = activeCount > 0;

  function toggleSelectAll() {
    const next = !allActive;
    setOptions((p) => Object.fromEntries([
      ...Object.entries(p),
      ...ACTIVE_KEYS.map((k) => [k, next]),
    ]));
  }

  return (
    <section className="card scanner-card">
      <h2>Target URLs</h2>
      <p className="muted small">One URL per line — HTTP/HTTPS only.</p>

      <textarea
        className="url-input"
        value={urlsInput}
        onChange={(e) => setUrlsInput(e.target.value)}
        placeholder={'https://example.com\nhttps://api.example.com'}
        spellCheck={false}
        disabled={isScanning}
        aria-label="Target URLs"
      />

      {/* Passive options */}
      <div className="options-row">
        {[
          { key: 'scanAssets',   label: 'JS assets'        },
          { key: 'checkExposed', label: 'Exposed files'    },
          ...passiveModules.map((module) => ({ key: module.optionKey, label: module.label })),
        ].map(({ key, label }) => (
          <label key={key} className="option-toggle">
            <input
              type="checkbox"
              checked={options[key]}
              onChange={(e) => setOptions((p) => ({ ...p, [key]: e.target.checked }))}
              disabled={isScanning}
            />
            {label}
          </label>
        ))}
        <button className="btn-link" onClick={() => setShowAdvanced((v) => !v)}>
          {showAdvanced ? 'Hide advanced ▲' : 'Advanced ▼'}
        </button>
      </div>

      {/* Active testing panel */}
      <div className="active-panel">
        <div className="active-panel-header">
          <div className="active-panel-title">
            <span className="active-dot" />
            Active Testing
            <span className="active-count-badge">
              {activeCount}/{ACTIVE_KEYS.length}
            </span>
          </div>
          <button
            className={`select-all-btn ${allActive ? 'select-all-on' : ''}`}
            onClick={toggleSelectAll}
            disabled={isScanning}
          >
            {allActive ? 'Deselect All' : 'Select All'}
          </button>
        </div>

        <div className="active-grid">
          {ACTIVE_TESTS.map(({ key, label, sub }) => (
            <label
              key={key}
              className={`active-test-item ${options[key] ? 'active-test-on' : ''}`}
            >
              <input
                type="checkbox"
                checked={options[key]}
                onChange={(e) => setOptions((p) => ({ ...p, [key]: e.target.checked }))}
                disabled={isScanning}
              />
              <span className="active-test-text">
                <span className="active-test-name">{label}</span>
                <span className="active-test-sub">{sub}</span>
              </span>
            </label>
          ))}
        </div>

        {someActive && (
          <div className="active-warning">
            <span className="warning-icon">⚠</span>
            Sends real payloads to discovered endpoints. Only scan targets you own or have explicit written permission to test.
          </div>
        )}
      </div>

      {/* Advanced settings */}
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
