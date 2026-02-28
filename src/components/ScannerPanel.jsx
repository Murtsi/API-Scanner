import { useState } from 'react';
import { SCAN_CONFIG } from '../config/constants.js';

export default function ScannerPanel({
  urlsInput,
  setUrlsInput,
  customRulesInput,
  setCustomRulesInput,
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
      <h2>Target URLs</h2>
      <p className="muted small">One URL per line — HTTP/HTTPS only.</p>

      <textarea
        className="url-input"
        value={urlsInput}
        onChange={(e) => setUrlsInput(e.target.value)}
        placeholder={'https://example.com\nhttps://api.example.com/docs'}
        spellCheck={false}
        disabled={isScanning}
        aria-label="Target URLs"
      />

      <div className="options-row">
        <label className="option-toggle">
          <input
            type="checkbox"
            checked={options.scanAssets}
            onChange={(e) => setOptions((p) => ({ ...p, scanAssets: e.target.checked }))}
            disabled={isScanning}
          />
          Scan linked JS assets
        </label>
        <label className="option-toggle">
          <input
            type="checkbox"
            checked={options.checkExposed}
            onChange={(e) => setOptions((p) => ({ ...p, checkExposed: e.target.checked }))}
            disabled={isScanning}
          />
          Check exposed files
        </label>
        <label className="option-toggle">
          <input
            type="checkbox"
            checked={options.checkHeaders}
            onChange={(e) => setOptions((p) => ({ ...p, checkHeaders: e.target.checked }))}
            disabled={isScanning}
          />
          Security headers
        </label>
        <button className="btn-link" onClick={() => setShowAdvanced((v) => !v)}>
          {showAdvanced ? 'Hide advanced ▲' : 'Advanced ▼'}
        </button>
      </div>

      <div className="options-row options-row-active">
        <span className="active-label">Active testing</span>
        <label className="option-toggle option-toggle-active">
          <input
            type="checkbox"
            checked={options.testSqli}
            onChange={(e) => setOptions((p) => ({ ...p, testSqli: e.target.checked }))}
            disabled={isScanning}
          />
          SQL injection
        </label>
        <label className="option-toggle option-toggle-active">
          <input
            type="checkbox"
            checked={options.testXss}
            onChange={(e) => setOptions((p) => ({ ...p, testXss: e.target.checked }))}
            disabled={isScanning}
          />
          XSS reflection
        </label>
        {(options.testSqli || options.testXss) && (
          <span className="active-warning">
            ⚠ Sends payloads — only scan targets you own or have permission to test.
          </span>
        )}
      </div>

      {showAdvanced && (
        <div className="advanced-panel">
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
              Custom regex rules (optional)
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
          <button className="btn-danger" onClick={onStop}>
            Stop
          </button>
        ) : (
          <button className="btn-primary" onClick={onScan}>
            Start scan
          </button>
        )}
        <button className="btn-secondary" onClick={onClear} disabled={isScanning}>
          Clear
        </button>
      </div>

      {log.length > 0 && (
        <div className="log" aria-live="polite" aria-label="Scan log">
          {log.map((entry) => (
            <div key={entry.id} className={`log-entry log-${entry.type}`}>
              {entry.msg}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
