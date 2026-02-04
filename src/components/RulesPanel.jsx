export default function RulesPanel({ patterns }) {
  return (
    <aside className="card">
      <h2>Detection rules</h2>
      <p className="muted">
        This scanner detects common patterns. It does not guarantee
        completeness.
      </p>

      <div className="legend">
        {patterns.map((rule) => (
          <div className="legend-item" key={rule.name}>
            <span>{rule.name}</span>
            <span className={`badge ${rule.severity}`}>{rule.severity}</span>
          </div>
        ))}
      </div>

      <div className="notes muted small">
        <strong>Notes:</strong>
        <ul>
          <li>Some sites block cross-origin requests. Those URLs will show a fetch error.</li>
          <li>Only content accessible without authentication is scanned.</li>
          <li>Never scan targets without permission.</li>
        </ul>
      </div>
    </aside>
  );
}
