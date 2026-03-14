import { useState } from 'react';
import { SCAN_CONFIG } from '../config/constants.js';

const SEVERITY_LEVELS = ['low', 'medium', 'high', 'critical'];

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

  return (
    <section className="card scanner-card">
      <h2 className="scanner-title">Target URLs</h2>
      <p className="target-hint">
        One URL per line — HTTP/HTTPS only. The scanner fetches each page and
        linked JavaScript files, then runs your selected checks against them.
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
                  setOptions((p) => ({ ...p, enableExperimentalModules: e.target.checked }))
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
                        <option key={level} value={level}>{level}</option>
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
        <div className={`log${isScanning ? ' scanning' : ''}`} aria-live="polite" aria-label="Scan log">
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
