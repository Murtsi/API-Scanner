import { useState } from 'react';
import { BASE_RULES } from '../utils/patterns.js';
import { SEVERITY_ORDER, SEVERITY_LABELS } from '../config/constants.js';

const CATEGORIES = ['All', ...new Set(BASE_RULES.map((r) => r.category))];

export default function RulesPanel() {
  const [activeCategory, setActiveCategory] = useState('All');
  const [collapsed, setCollapsed] = useState(false);

  const filtered =
    activeCategory === 'All'
      ? BASE_RULES
      : BASE_RULES.filter((r) => r.category === activeCategory);

  const sorted = [...filtered].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <aside className="card rules-panel">
      <button className="rules-header" onClick={() => setCollapsed((v) => !v)}>
        <h2>Detection Rules ({BASE_RULES.length})</h2>
        <span className="collapse-icon">{collapsed ? '▼' : '▲'}</span>
      </button>

      {!collapsed && (
        <>
          <div className="category-tabs">
            {CATEGORIES.map((cat) => (
              <button
                key={cat}
                className={`tab-btn ${activeCategory === cat ? 'active' : ''}`}
                onClick={() => setActiveCategory(cat)}
              >
                {cat}
              </button>
            ))}
          </div>

          <div className="rules-list">
            {sorted.map((rule) => (
              <div key={rule.id} className="rule-item">
                <div className="rule-name-row">
                  <span className="rule-name">{rule.name}</span>
                  <span className={`badge sev-${rule.severity}`}>
                    {SEVERITY_LABELS[rule.severity]}
                  </span>
                </div>
                {rule.description && (
                  <p className="rule-desc muted small">{rule.description}</p>
                )}
              </div>
            ))}
          </div>

          <div className="rules-notes muted small">
            <strong>Notes:</strong>
            <ul>
              <li>Cross-origin requests may be blocked by target servers (CORS).</li>
              <li>Only publicly accessible content without authentication is scanned.</li>
              <li>High-entropy detection may include false positives.</li>
              <li>Always obtain explicit permission before scanning any target.</li>
            </ul>
          </div>
        </>
      )}
    </aside>
  );
}
