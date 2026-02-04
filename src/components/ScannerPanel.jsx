export default function ScannerPanel({
  urlsInput,
  setUrlsInput,
  scanSummary,
  statusRows,
  onScan,
  onClear,
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

      <div className="actions">
        <button onClick={onScan}>Start scan</button>
        <button className="secondary" onClick={onClear}>
          Clear
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
