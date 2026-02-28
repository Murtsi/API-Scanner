import { useState } from 'react';
import { SEVERITY_ORDER, SEVERITY_LABELS } from '../config/constants.js';

// Risk guidance text keyed by rule name
const GUIDANCE = {
  'AWS Access Key ID':
    'Pair with the Secret Access Key to fully authenticate as the IAM user — grants broad cloud access.',
  'AWS Secret Access Key':
    'Combined with an Access Key ID this enables full programmatic AWS access including billing.',
  'AWS Session Token':
    'Temporary credential — still grants AWS access until it expires.',
  'Stripe Live Secret Key':
    'Enables real payment charges and read access to live customer billing data.',
  'Stripe Test Key':
    'Test-mode only, but reveals integration details and can disrupt test pipelines.',
  'Stripe Webhook Secret':
    'Allows forging webhook events to your backend, bypassing signature validation.',
  'Google API Key':
    'Can call paid Google APIs (Maps, Vision, Translate) incurring charges on the owner\'s account.',
  'Google OAuth Token':
    'Short-lived but grants live Google API access as the authorizing user.',
  'Google Service Account':
    'Full service-account credentials — can escalate to any role bound to the account.',
  'GitHub Personal Token':
    'Grants repository and org access matching the token\'s scopes. Rotate immediately.',
  'GitHub OAuth Token':
    'OAuth token granting access scoped to the app\'s permissions.',
  'GitHub App Token':
    'App installation token — access scoped to repo/org permissions.',
  'GitHub Classic Token':
    'Classic 40-char PAT — may have broad repo/org access.',
  'GitLab Personal Token':
    'Full API access to GitLab projects, issues, and CI/CD pipelines.',
  'GitLab Runner Token':
    'Can register new runners and intercept CI jobs.',
  'Slack Bot Token':
    'Can read/post messages, access DMs, and manage workspace resources.',
  'Slack User Token':
    'Acts on behalf of the authorizing user — read DMs, post messages.',
  'Slack Incoming Webhook':
    'Can post arbitrary messages to the configured channel.',
  'Twilio Account SID':
    'Identifier needed alongside Auth Token for full Twilio access.',
  'Twilio Auth Token':
    'Full Twilio access — can send SMS/voice and incur charges.',
  'SendGrid API Key':
    'Can send email on behalf of the domain — spam, phishing, and reputation risk.',
  'Mailgun API Key':
    'Can send email and access message logs.',
  'Firebase Server Key':
    'Can push notifications to all app users; may also access Firebase data depending on rules.',
  'Azure Storage Key':
    'Full read/write/delete access to Azure Blob, Table, and Queue storage.',
  'Azure Client Secret':
    'Authenticates an Azure AD application — scope depends on assigned roles.',
  'Heroku API Key':
    'Manage apps, view config vars, and deploy code on Heroku.',
  'Shopify Access Token':
    'Grants store API access — orders, customers, products depending on scopes.',
  'Discord Bot Token':
    'Full bot control — can read/send messages and manage servers.',
  'Discord Webhook URL':
    'Can post messages to the configured Discord channel.',
  'NPM Access Token':
    'Can publish packages or read private packages depending on access level.',
  'Terraform Cloud Token':
    'Can read state files and trigger runs — state may contain secrets.',
  'Datadog API Key':
    'Can submit metrics, read monitors, and access logs.',
  'HashiCorp Vault Token':
    'Grants access to Vault secrets — scope depends on policy.',
  'JSON Web Token':
    'Decode to check claims and expiry — may grant session or API access.',
  'JWT Refresh Token':
    'Can mint new access tokens, extending unauthorized access.',
  'Bearer Token':
    'Direct API authorization — equivalent to a password for the API.',
  'RSA Private Key':
    'Can authenticate as the key owner or decrypt data encrypted to the public key.',
  'EC Private Key':
    'Elliptic curve private key used for signing or ECDH key exchange.',
  'Generic Private Key':
    'Private key material must never be public — rotate and revoke immediately.',
  'PGP Private Key':
    'Can sign or decrypt PGP messages as the key owner.',
  'PostgreSQL Connection String':
    'Contains database credentials — direct read/write access to the database.',
  'MySQL Connection String':
    'Contains database credentials — direct read/write access to the database.',
  'MongoDB Connection String':
    'Contains database credentials — direct read/write access to the cluster.',
  'Redis Connection String':
    'Contains Redis password — can read/write all cache data.',
  'Hardcoded Password':
    'Literal password in code — likely shared or reused across systems.',
  'High-Entropy String':
    'Appears randomly generated — may be an undeclared API key or secret.',
};

function copyToClipboard(text) {
  navigator.clipboard?.writeText(text).catch(() => {});
}

function SeverityBadge({ severity }) {
  return (
    <span className={`badge sev-${severity}`}>
      {SEVERITY_LABELS[severity] ?? severity}
    </span>
  );
}

const TYPE_LABELS = {
  header: { label: 'Header', cls: 'type-header' },
  vuln:   { label: 'Active', cls: 'type-vuln' },
};

function FindingCard({ finding }) {
  const [open, setOpen] = useState(true);
  const guidance = GUIDANCE[finding.name];
  const typeInfo = finding.type ? TYPE_LABELS[finding.type] : null;

  return (
    <div className={`finding-card sev-border-${finding.severity}`}>
      <button className="finding-header" onClick={() => setOpen((v) => !v)}>
        <div className="finding-title">
          <SeverityBadge severity={finding.severity} />
          {typeInfo && (
            <span className={`type-badge ${typeInfo.cls}`}>{typeInfo.label}</span>
          )}
          <strong>{finding.name}</strong>
          {finding.category && (
            <span className="category-tag">{finding.category}</span>
          )}
        </div>
        <span className="finding-toggle">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="finding-body">
          {finding.description && (
            <p className="muted small finding-desc">{finding.description}</p>
          )}
          {guidance && (
            <div className="guidance muted small">
              <strong>Risk:</strong> {guidance}
            </div>
          )}
          <div className="matches">
            {finding.matches.map((m, i) => (
              <div key={i} className="match-row">
                <code className="match-value">{m}</code>
                <button
                  className="btn-copy"
                  onClick={() => copyToClipboard(m)}
                  title="Copy to clipboard"
                >
                  ⧉
                </button>
              </div>
            ))}
          </div>
          {finding.sources && finding.sources.length > 0 && (
            <div className="muted small sources">
              Found in:{' '}
              {finding.sources.map((s) => (
                <span key={s} className="source-tag">
                  {s.split('/').pop() || s}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SeveritySummary({ findings }) {
  const counts = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  const hasCounts = SEVERITY_ORDER.some((s) => counts[s]);
  if (!hasCounts) return null;

  return (
    <div className="sev-summary">
      {SEVERITY_ORDER.map((sev) =>
        counts[sev] ? (
          <span key={sev} className={`sev-pill sev-${sev}`}>
            {counts[sev]} {SEVERITY_LABELS[sev]}
          </span>
        ) : null
      )}
    </div>
  );
}

function ResultCard({ result }) {
  if (result.error) {
    return (
      <div className="result-card result-error">
        <div className="result-header">
          <span className="result-url">{result.url}</span>
          <span className="badge sev-high">Error</span>
        </div>
        <p className="muted small" style={{ marginTop: '6px' }}>{result.error}</p>
      </div>
    );
  }

  const hasCritical = result.findings.some((f) => f.severity === 'critical');
  const hasFindings = result.findings.length > 0;
  const cardClass = hasCritical
    ? 'result-card result-critical'
    : hasFindings
    ? 'result-card result-has-findings'
    : 'result-card result-clean';

  return (
    <div className={cardClass}>
      <div className="result-header">
        <div className="result-url-row">
          <span className="result-url" title={result.url}>
            {result.url}
          </span>
          {result.duration > 0 && (
            <span className="muted small">{(result.duration / 1000).toFixed(1)}s</span>
          )}
        </div>
        <div className="result-meta-row">
          {result.assets?.length > 0 && (
            <span className="meta-tag">{result.assets.length} JS assets</span>
          )}
          {result.exposedFiles?.length > 0 && (
            <span className="meta-tag meta-exposed">
              {result.exposedFiles.length} exposed file
              {result.exposedFiles.length !== 1 ? 's' : ''}
            </span>
          )}
          {!hasFindings && <span className="badge sev-none">Clean</span>}
        </div>
      </div>

      {hasFindings && <SeveritySummary findings={result.findings} />}

      <div className="findings-list">
        {result.findings.map((f) => (
          <FindingCard key={f.id} finding={f} />
        ))}
      </div>

      {result.exposedFiles?.length > 0 && (
        <div className="exposed-section">
          <strong className="small">Exposed Files</strong>
          <div className="exposed-list">
            {result.exposedFiles.map((ef) => (
              <div key={ef.path} className="exposed-item">
                <code className="small">{ef.path}</code>
                <span className="badge sev-high">HTTP {ef.status}</span>
                <button
                  className="btn-copy"
                  onClick={() => copyToClipboard(ef.url)}
                  title="Copy URL"
                >
                  ⧉
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ResultsPanel({ results, isScanning, onExportJson, onExportCsv }) {
  const [severityFilter, setSeverityFilter] = useState(null);

  const totalTypes = results.reduce((n, r) => n + (r.findings?.length ?? 0), 0);
  const totalCritical = results.reduce(
    (n, r) => n + (r.findings?.filter((f) => f.severity === 'critical').length ?? 0),
    0
  );

  const filteredResults = severityFilter
    ? results.map((r) => ({
        ...r,
        findings: r.findings.filter((f) => f.severity === severityFilter),
      }))
    : results;

  if (results.length === 0 && !isScanning) {
    return (
      <div className="results-empty card">
        <div className="empty-icon">⊙</div>
        <p className="muted">
          Enter URLs above and click <strong>Start scan</strong> to begin.
        </p>
        <p className="muted small">
          Scans HTML, JS bundles, and 32+ exposed paths for 49+ secret patterns.
          Optionally checks security headers and actively tests endpoints for SQL injection and XSS.
        </p>
      </div>
    );
  }

  return (
    <div className="results-panel">
      {results.length > 0 && (
        <div className="results-toolbar card">
          <div className="toolbar-stats">
            <span className="stat-main">
              {totalTypes === 0
                ? 'No findings'
                : `${totalTypes} finding type${totalTypes !== 1 ? 's' : ''}`}
            </span>
            {totalCritical > 0 && (
              <span className="badge sev-critical">{totalCritical} critical</span>
            )}
            <span className="muted small">
              across {results.length} target{results.length !== 1 ? 's' : ''}
            </span>
          </div>

          <div className="toolbar-actions">
            <div className="filter-row">
              <button
                className={`btn-filter ${!severityFilter ? 'active' : ''}`}
                onClick={() => setSeverityFilter(null)}
              >
                All
              </button>
              {SEVERITY_ORDER.map((sev) => (
                <button
                  key={sev}
                  className={`btn-filter sev-filter-${sev} ${severityFilter === sev ? 'active' : ''}`}
                  onClick={() => setSeverityFilter(sev === severityFilter ? null : sev)}
                >
                  {SEVERITY_LABELS[sev]}
                </button>
              ))}
            </div>

            <div className="export-row">
              <button
                className="btn-secondary"
                onClick={onExportJson}
                disabled={results.length === 0}
              >
                Export JSON
              </button>
              <button
                className="btn-secondary"
                onClick={onExportCsv}
                disabled={results.length === 0}
              >
                Export CSV
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="results-list">
        {filteredResults.map((r) => (
          <ResultCard key={r.url} result={r} />
        ))}
      </div>
    </div>
  );
}
