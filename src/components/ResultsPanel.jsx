export default function ResultsPanel({ results }) {
  return (
    <div className="results">
      {results.map((result) => {
        if (result.error) {
          return (
            <div className="result-card" key={result.url}>
              <h3>{result.url}</h3>
              <div className="result-meta">
                <span className="badge danger">Fetch error</span>
              </div>
              <div className="result-list muted">{result.error}</div>
            </div>
          );
        }

        const totalFindings = result.findings.reduce(
          (sum, item) => sum + item.total,
          0
        );
        const severity = result.findings.some(
          (item) => item.severity === "danger"
        )
          ? "danger"
          : totalFindings
          ? "warning"
          : "success";

        const exposedCount = result.exposedFiles?.length || 0;

        return (
          <div className="result-card" key={result.url}>
            <h3>{result.url}</h3>
            <div className="result-meta">
              <span className={`badge ${severity}`}>
                {totalFindings
                  ? `${totalFindings} findings`
                  : "No findings"}
              </span>
              {result.assetsScanned > 0 && (
                <span className="badge warning">
                  {result.assetsScanned} assets scanned
                </span>
              )}
              {exposedCount > 0 && (
                <span className="badge danger">
                  {exposedCount} exposed files
                </span>
              )}
            </div>

            {result.findings.length ? (
              result.findings.map((item) => (
                <div className="result-list" key={item.rule}>
                  <strong>{item.rule}</strong>
                  <div className="muted small">
                    {item.total} matches · {item.source}
                  </div>
                  {item.matches.map((match) => (
                    <div className="highlight" key={match}>
                      {match}
                    </div>
                  ))}
                </div>
              ))
            ) : (
              <div className="muted">
                No secrets detected in accessible HTML.
              </div>
            )}

            {exposedCount > 0 && (
              <div className="exposed">
                <strong>Exposed files</strong>
                <ul>
                  {result.exposedFiles.map((file) => (
                    <li key={file.path}>
                      <span>{file.path}</span>
                      <span className="muted small">HTTP {file.status}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
