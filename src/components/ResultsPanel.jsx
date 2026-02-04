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

        return (
          <div className="result-card" key={result.url}>
            <h3>{result.url}</h3>
            <div className="result-meta">
              <span className={`badge ${severity}`}>
                {totalFindings
                  ? `${totalFindings} findings`
                  : "No findings"}
              </span>
            </div>

            {result.findings.length ? (
              result.findings.map((item) => (
                <div className="result-list" key={item.rule}>
                  <strong>{item.rule}</strong>
                  <div className="muted small">{item.total} matches</div>
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
          </div>
        );
      })}
    </div>
  );
}
