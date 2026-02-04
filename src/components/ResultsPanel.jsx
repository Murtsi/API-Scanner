export default function ResultsPanel({ results }) {
  const guidance = {
    "AWS Access Key": {
      risk: "Can be used to access AWS services, read data, or spin up resources for abuse.",
      hide: "Leaking this enables unauthorized cloud access and potential billing fraud.",
    },
    "AWS Secret Key": {
      risk: "Pairs with access keys to fully authenticate against AWS APIs.",
      hide: "Grants full programmatic access; must be rotated immediately if exposed.",
    },
    "Google API Key": {
      risk: "Can be used to call Google APIs, potentially incurring costs or accessing data.",
      hide: "Exposed keys can be abused for quota theft or data access.",
    },
    "Stripe Live Key": {
      risk: "Allows live payment actions and access to billing data.",
      hide: "Could enable fraudulent charges or data exposure.",
    },
    "Stripe Test Key": {
      risk: "Allows test-mode access that may still reveal integration details.",
      hide: "Can expose implementation details and be used for abuse in test environments.",
    },
    "Slack Token": {
      risk: "Can be used to read or post messages, access workspace data.",
      hide: "May allow data exfiltration or impersonation.",
    },
    "GitHub Token": {
      risk: "Can access repositories, issues, and CI secrets depending on scope.",
      hide: "Leaked tokens enable unauthorized repo access and code tampering.",
    },
    "GitLab Token": {
      risk: "Can access projects, repos, and CI/CD resources.",
      hide: "Exposed tokens enable unauthorized access and pipeline abuse.",
    },
    "Twilio API Key": {
      risk: "Can send SMS/voice traffic and incur charges.",
      hide: "May be abused for spam or billing fraud.",
    },
    "SendGrid API Key": {
      risk: "Can send email campaigns or access delivery data.",
      hide: "Abuse can cause spam, reputation damage, and cost.",
    },
    "Mailgun API Key": {
      risk: "Can send email and access logs.",
      hide: "Leaked keys allow spam and data access.",
    },
    "Firebase Server Key": {
      risk: "Can send push notifications or access Firebase services.",
      hide: "Can be abused for spam or to access data depending on rules.",
    },
    "Heroku API Key": {
      risk: "Can manage apps, view config, and deploy code.",
      hide: "Leaked keys allow takeover of deployments and data exposure.",
    },
    "Private Key Block": {
      risk: "Can be used to authenticate as the owner or decrypt data.",
      hide: "Private keys must never be public; rotate and revoke immediately.",
    },
    "JWT Token": {
      risk: "May grant session access or API authorization.",
      hide: "Tokens can allow account takeover or data access.",
    },
    "JWT Refresh Token": {
      risk: "Can mint new access tokens, extending access.",
      hide: "Refresh tokens enable long-term unauthorized access.",
    },
    "Bearer Token": {
      risk: "Direct API authorization; often equivalent to a password.",
      hide: "Should be protected to prevent unauthorized API use.",
    },
    "Password Assignment": {
      risk: "Indicates hardcoded credentials that may unlock services.",
      hide: "Passwords in code can be discovered and abused.",
    },
    "Generic API Key": {
      risk: "Can provide direct API access depending on service.",
      hide: "Exposed keys can be abused for data access and cost.",
    },
    "Suspicious Key Assignment": {
      risk: "Likely a secret-like value that could authorize API actions.",
      hide: "Secrets should be stored in vaults or environment variables.",
    },
    "High-Entropy String": {
      risk: "Often indicates random secrets or tokens.",
      hide: "Random secrets should not be embedded in client-accessible content.",
    },
    "Azure Storage Key": {
      risk: "Can grant full access to storage accounts.",
      hide: "Leaked keys allow data exfiltration and overwrite.",
    },
  };

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
                  {guidance[item.rule] && (
                    <div className="muted small">
                      <div>
                        <strong>Potential misuse:</strong> {guidance[item.rule].risk}
                      </div>
                      <div>
                        <strong>Why hide:</strong> {guidance[item.rule].hide}
                      </div>
                    </div>
                  )}
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
