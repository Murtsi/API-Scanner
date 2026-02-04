export default function ScannerPanel({
  urlsInput,
  setUrlsInput,
  customRulesInput,
  setCustomRulesInput,
  scanOptions,
  setScanOptions,
  scanSummary,
  statusRows,
  onScan,
  onClear,
  onExportJson,
  onExportCsv,
}) {
  return (
    <div className="scanner">
      <h2>Scan websites</h2>
      <p className="muted">
        Paste one URL per line. The scanner fetches HTML and searches for
        common API key, token, and secret patterns.
      </p>

      <textarea
        value={urlsInput}
        onChange={(event) => setUrlsInput(event.target.value)}
        placeholder="https://example.com\nhttps://api.example.com/docs"
      />

      <div className="options">
        <label className="option">
          <input
            type="checkbox"
            checked={scanOptions.scanAssets}
            onChange={(event) =>
              setScanOptions((prev) => ({
                ...prev,
                scanAssets: event.target.checked,
              }))
            }
          />
          Scan linked JS assets
        </label>
        <label className="option">
          <input
            type="checkbox"
            checked={scanOptions.checkExposed}
            onChange={(event) =>
              setScanOptions((prev) => ({
                ...prev,
                checkExposed: event.target.checked,
              }))
            }
          />
          Check common exposed files
        </label>
      </div>

      <div className="custom-rules">
        <label className="muted small">Custom regex rules (one per line, optional name with Name::/pattern/flags)</label>
        <textarea
          value={customRulesInput}
          onChange={(event) => setCustomRulesInput(event.target.value)}
          placeholder="MyRule::/sk_live_[A-Za-z0-9]{24,}/g"
        />
      </div>

      <div className="actions">
        <button onClick={onScan}>Start scan</button>
        <button className="secondary" onClick={onClear}>
          Clear
        </button>
        <button className="secondary" onClick={onExportJson}>
          Export JSON
        </button>
        <button className="secondary" onClick={onExportCsv}>
          Export CSV
        </button>
        <span className="pill" aria-live="polite">
          {scanSummary}
        </span>
      </div>

      <div className="status" aria-live="polite">
        {statusRows.map((row) => (
          <div className="status-row" key={row.url}>
            <strong>{row.url}</strong>
            <span className={`badge ${row.badge}`}>{row.status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
