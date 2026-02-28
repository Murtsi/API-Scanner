import { useState } from 'react';
import { SEVERITY_ORDER, SEVERITY_LABELS } from '../config/constants.js';

/**
 * Structured explanations for non-technical users.
 * Each entry has:
 *   what   — plain-English description of the finding
 *   attack — real-world impact / what an attacker does with it
 *   fix    — numbered remediation steps
 */
const DETAIL_INFO = {
  // ── Cloud ──────────────────────────────────────────────────────────────────
  'AWS Access Key ID': {
    what: 'An AWS Access Key ID is one half of the credentials used to access Amazon cloud services (AWS). Think of it like a username for your cloud account. On its own it is not enough to cause harm, but paired with the Secret Access Key it provides full API access.',
    attack: 'Attackers scan public GitHub repos and websites for leaked AWS keys every minute using automated tools. With both key parts they can spin up expensive servers for crypto-mining (costing you thousands in hours), steal databases, access private files in S3 buckets, or use your account to send phishing emails — all billed to you.',
    fix: [
      'Go to AWS Console → IAM → Users → Security credentials and immediately deactivate / delete this key.',
      'Check your AWS CloudTrail logs for any suspicious API calls made with this key in the past 90 days.',
      'Create a new key with the minimum required permissions and store it securely (e.g. AWS Secrets Manager or environment variables — never in code).',
      'Enable AWS GuardDuty to automatically detect credential misuse in the future.',
    ],
  },
  'AWS Secret Access Key': {
    what: 'The AWS Secret Access Key is the second half of AWS credentials — like a password paired with the Access Key ID. Together they give full programmatic access to your AWS account.',
    attack: 'With both the Access Key ID and this Secret Key, an attacker can authenticate as your IAM user and do anything that user is permitted to do — read/delete S3 files, create EC2 instances, exfiltrate RDS databases, or escalate privileges to full account control if the IAM policy is permissive.',
    fix: [
      'Immediately revoke this key in AWS IAM Console → Security credentials.',
      'Audit CloudTrail for API calls made with this key over the past 90 days.',
      'Rotate all keys. Store new keys only in environment variables, AWS Secrets Manager, or a vault — never commit them to source code.',
      'Apply least-privilege IAM policies — keys should only be able to do what is strictly needed.',
    ],
  },
  'Azure Storage Key': {
    what: 'An Azure Storage Account key is a master credential that grants full read, write, and delete access to all data in an Azure Blob, Table, Queue, and File storage account — similar to a root password for your cloud storage.',
    attack: 'An attacker with this key can download or delete every file in your Azure storage, overwrite backups, read private customer data, or use your storage as a staging area for malware — all without any Azure login.',
    fix: [
      'Regenerate the storage account key immediately in Azure Portal → Storage Accounts → Access keys.',
      'Use Azure Shared Access Signatures (SAS tokens) instead of account keys — they expire and can be scoped to specific containers and operations.',
      'Enable Azure Defender for Storage to detect suspicious access patterns.',
      'Store keys in Azure Key Vault and access them via managed identities, never in code or config files.',
    ],
  },

  // ── Payment ────────────────────────────────────────────────────────────────
  'Stripe Live Secret Key': {
    what: 'A Stripe live secret key (starting with sk_live_) is a master credential for your real Stripe payment account. It provides API access to your live payment processing, customer billing data, and financial records.',
    attack: 'An attacker can immediately: (1) charge any existing customer\'s stored card without their knowledge, (2) issue refunds to themselves, (3) access all customer payment details and email addresses, (4) create false invoices, or (5) disable your ability to process payments. Financial and reputational damage can be severe and immediate.',
    fix: [
      'Immediately go to Stripe Dashboard → Developers → API keys and roll (rotate) the compromised key.',
      'Review the Stripe Dashboard → Logs for any suspicious API calls in the past 24–72 hours.',
      'Notify your security team — you may have a PCI DSS reporting obligation depending on your jurisdiction.',
      'Store the new key only in environment variables or a secrets manager (e.g., Vault, AWS Secrets Manager). Never put it in source code or config files that are committed to version control.',
    ],
  },

  // ── Source control ─────────────────────────────────────────────────────────
  'GitHub Personal Token': {
    what: 'A GitHub Personal Access Token (PAT) acts as a password substitute for GitHub API access. It allows whoever holds it to perform GitHub operations — reading/writing code, managing issues, and more — on behalf of the account that generated it.',
    attack: 'An attacker with this token can clone private repositories (including any secrets stored in code history), push malicious code to repositories, delete branches, harvest email addresses of contributors, and potentially pivot to other systems if the repos contain credentials or infrastructure code.',
    fix: [
      'Go to GitHub → Settings → Developer settings → Personal access tokens and immediately revoke this token.',
      'Search your git history (git log -p | grep -i token) for any other committed secrets and purge them using git-filter-repo or BFG Repo Cleaner.',
      'Generate a new token with only the specific scopes needed (follow least-privilege).',
      'Consider using GitHub Actions OIDC or deploy keys for CI/CD instead of personal tokens.',
    ],
  },
  'GitLab Personal Token': {
    what: 'A GitLab Personal Access Token is equivalent to a password for GitLab API access. It grants the same access as the user who created it.',
    attack: 'With this token an attacker can access all your private GitLab projects, read source code, download CI/CD pipeline logs (which often contain secrets), modify or delete code, and impersonate you in API calls. If the token has admin scope, it can compromise the entire GitLab instance.',
    fix: [
      'Revoke the token immediately in GitLab → User Settings → Access Tokens.',
      'Audit recent API activity in the GitLab audit log for unauthorised actions.',
      'Rotate any credentials found in the repositories that were accessible with this token.',
      'Use CI/CD job tokens scoped to specific projects rather than personal tokens for pipelines.',
    ],
  },

  // ── Cryptographic keys ─────────────────────────────────────────────────────
  'RSA Private Key': {
    what: 'An RSA private key is the secret half of a public/private key pair used for encryption and authentication (e.g., SSH access to servers, SSL/TLS certificates, code signing). Publishing it is equivalent to publishing a master password for everything it protects.',
    attack: 'An attacker who obtains this key can: silently authenticate to any server that trusts the corresponding public key (SSH login without a password), decrypt all data encrypted to this key\'s public key, sign malicious code or documents as you, or impersonate your HTTPS server if it\'s a TLS private key.',
    fix: [
      'Immediately revoke and replace this key everywhere it is used (update ~/.ssh/authorized_keys on all servers, revoke certificates via your CA).',
      'Rotate any TLS certificates signed with this key.',
      'Generate a new key pair: ssh-keygen -t ed25519 -C "your@email.com" — store private keys only in ~/.ssh/ with permissions 600, never in a repository.',
      'Use a hardware key (YubiKey) or an SSH agent to prevent the key from being read from disk.',
    ],
  },
  'EC Private Key': {
    what: 'An Elliptic Curve (EC) private key is used for asymmetric cryptography — authentication, digital signatures, and key agreement. It is the secret counterpart to a public key used to verify your identity or encrypt data.',
    attack: 'Exposure allows an attacker to impersonate you on any system that trusts the corresponding public key, forge digital signatures, or decrypt communications protected with this key.',
    fix: [
      'Revoke and replace this key everywhere it is trusted.',
      'Generate a new key pair and securely store only the private key (never in source code).',
      'Investigate what the key was used for and assess whether any communications were compromised.',
    ],
  },
  'PGP Private Key': {
    what: 'A PGP private key is used to decrypt PGP-encrypted messages and to sign documents or emails so recipients can verify they came from you.',
    attack: 'With this key an attacker can decrypt all PGP-encrypted messages ever sent to you (including old emails), forge signed messages or code commits that appear to come from you, and impersonate you in any PGP-authenticated system.',
    fix: [
      'Revoke the key by generating a revocation certificate and publishing it to key servers.',
      'Generate a new PGP key pair and distribute the new public key to your contacts.',
      'Notify anyone who may have sent you PGP-encrypted messages to assume those messages are compromised.',
    ],
  },

  // ── Database connections ───────────────────────────────────────────────────
  'PostgreSQL Connection String': {
    what: 'A database connection string contains the hostname, username, and password needed to connect directly to a PostgreSQL database. It is like having the address and keys to your database server.',
    attack: 'An attacker with this string can connect directly to your database from anywhere on the internet (if it\'s not firewalled), dump all data, modify or delete records, create admin accounts, or drop entire tables — causing permanent data loss or a full data breach.',
    fix: [
      'Change the database user\'s password immediately via ALTER USER in psql.',
      'Check if the database port (default 5432) is publicly accessible — it should only be accessible from your application servers via a firewall / security group.',
      'Audit recent database connections and queries for any suspicious activity.',
      'Store connection strings only in environment variables or a secrets manager — never in source code.',
    ],
  },
  'MySQL Connection String': {
    what: 'A MySQL connection string embeds the credentials (host, username, password, database name) needed to connect to your MySQL database. Anyone with this string has the keys to your data.',
    attack: 'Direct database access means an attacker can read all customer data, financial records, passwords (even hashed), dump the full database for offline cracking, plant backdoors, or destroy all data.',
    fix: [
      'Change the MySQL user\'s password immediately: ALTER USER \'user\'@\'host\' IDENTIFIED BY \'newpassword\';',
      'Restrict database access to application server IPs only in your firewall.',
      'Rotate all credentials in your application configuration.',
      'Use a secrets manager to store and rotate database credentials automatically.',
    ],
  },
  'MongoDB Connection String': {
    what: 'A MongoDB connection string includes the credentials and server address needed to connect to a MongoDB database. This gives read and write access to all collections in the specified database.',
    attack: 'With this string an attacker can read all documents (including user records, passwords, personal data), insert malicious data, delete collections, or use the database as a foothold for further attacks. MongoDB databases have historically been a target for ransomware attacks.',
    fix: [
      'Rotate the MongoDB user\'s credentials immediately via the Atlas dashboard or db.updateUser().',
      'Ensure MongoDB is not directly exposed to the internet — it should sit behind a VPC and only be accessible from your application tier.',
      'Enable MongoDB audit logging to detect suspicious queries.',
      'Store credentials in environment variables or a vault solution.',
    ],
  },

  // ── Auth tokens ────────────────────────────────────────────────────────────
  'JSON Web Token': {
    what: 'A JSON Web Token (JWT) is a compact, signed token that proves authentication — like a signed digital ticket. It contains user claims (user ID, roles, email) and is used by the server to verify identity without querying the database on every request.',
    attack: 'If the token is still valid (JWTs typically expire in minutes to hours but sometimes days), an attacker can replay it to authenticate as the victim user, access their data, and perform actions on their behalf. If the signing secret is also exposed, the attacker can forge arbitrary tokens as any user including admins.',
    fix: [
      'If this token belongs to a real user session, invalidate it immediately by rotating the JWT signing secret (which invalidates all tokens) or adding it to a token blocklist.',
      'Check the token\'s "exp" (expiry) claim — if it has already expired it may be lower risk, but rotate the signing secret anyway if that is also exposed.',
      'Never store JWTs in localStorage (vulnerable to XSS) — prefer HttpOnly cookies.',
      'Implement short expiry times (15–60 minutes) with refresh token rotation.',
    ],
  },
  'Hardcoded Password': {
    what: 'A plaintext password was found directly in the website\'s source code or a JavaScript file. Hardcoded passwords are a critical security mistake because anyone who can read the code can read the password.',
    attack: 'An attacker can use this password to log into whatever service it authenticates to — a database, admin panel, internal API, email account, etc. Hardcoded passwords are rarely rotated, so they often remain valid for years and frequently reused across multiple systems.',
    fix: [
      'Remove the hardcoded password from the codebase immediately and commit the change.',
      'Rotate the password on whatever system it authenticates to.',
      'If the code is in a public or shared repository, assume the password has been seen — rotate it regardless of who had access.',
      'Store passwords and secrets in environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).',
    ],
  },
  'High-Entropy String': {
    what: 'This string appears highly random — more random than normal text or identifiers. Genuine secrets like API keys, tokens, and cryptographic keys are designed to be random, so high randomness is a strong indicator that this may be a real credential that was not explicitly matched by a named rule.',
    attack: 'If this is a real secret (API key, session token, encryption key), an attacker who finds it can use it the same way a legitimate user would — accessing the associated service, data, or account.',
    fix: [
      'Carefully inspect the value — does it start with a known service prefix? Does it appear in an API key assignment?',
      'If you believe it is a real secret, treat it as compromised: rotate it and remove it from the codebase.',
      'If it is a legitimate non-secret (e.g., a content hash or font data), you can safely ignore this finding.',
    ],
  },

  // ── Active test results ────────────────────────────────────────────────────
  'SQL Injection — Error-Based': {
    what: 'SQL injection is one of the most dangerous web vulnerabilities. It occurs when user input (like a search query or login field) is inserted directly into a database query without proper sanitisation. The "error-based" variant means the database actually printed an error message when given a malformed input — confirming the injection point and revealing the database type.',
    attack: 'An attacker can: (1) dump the entire database contents including usernames, passwords, emails, and payment info, (2) bypass login pages by making the query always return "true", (3) read files from the server\'s filesystem, (4) in some configurations, execute operating system commands. SQL injection is the #1 cause of database breaches.',
    fix: [
      'Replace all dynamic SQL with parameterised queries / prepared statements in your server-side code.',
      'Use an ORM (Object-Relational Mapper) that handles parameterisation automatically.',
      'Implement input validation on the server side (never rely on client-side validation alone).',
      'Apply the principle of least privilege — the database user should only have SELECT/INSERT on the tables it needs, never DROP or FILE privileges.',
      'Deploy a Web Application Firewall (WAF) as a defence-in-depth layer, but do NOT rely on it as the primary defence.',
    ],
  },
  'SQL Injection — Time-Based Blind': {
    what: 'Time-based blind SQL injection is a variant where the attacker cannot see database errors in the response, but can infer that code is executing by measuring how long the server takes to respond. A SLEEP(3) or WAITFOR DELAY command was injected and the server responded 3 seconds later than baseline — confirming code execution.',
    attack: 'Even without visible errors, an attacker can: slowly extract data character by character by asking the server "is the first character of the admin password > \'m\'? If yes, sleep 3 seconds", enumerate the full database schema, dump password hashes for offline cracking. This technique bypasses many WAF rules because there are no obvious error strings in the response.',
    fix: [
      'Use parameterised queries / prepared statements — this is the only reliable fix.',
      'Time-based SQLi is particularly hard to detect with logging, so this finding likely means the vulnerability has existed unnoticed for some time. Review your server and database access logs.',
      'Consider a complete audit of all database-touching code paths.',
      'Monitor database query times — a sudden spike of 3-second queries is an indicator of active exploitation.',
    ],
  },
  'NoSQL Injection (MongoDB Operator)': {
    what: 'NoSQL injection occurs when query operators from MongoDB (like $ne "not equal", $gt "greater than") are injected through URL parameters or JSON body fields. When an application passes request parameters directly into a MongoDB query filter, these operators can alter the query\'s logic.',
    attack: 'An attacker can bypass authentication by replacing a password field with {"$ne": null} — meaning "find a user where the password is not null", which matches every user. This is how attackers log in as the first admin in the database without knowing any password. More advanced attacks can extract all data from collections.',
    fix: [
      'Never pass raw request parameters directly into MongoDB query objects.',
      'Validate and sanitise all inputs: confirm they are the expected type (string, number) before using them in queries.',
      'Use schema validation libraries (Joi, Zod, Yup) to enforce input shapes.',
      'In Express/Node.js, consider the express-mongo-sanitize middleware to strip $ and . from request data automatically.',
    ],
  },
  'Reflected XSS': {
    what: 'Cross-Site Scripting (XSS) occurs when a website echoes user input back in a page without escaping special characters. In the reflected variant, the malicious input travels in the URL — when a victim visits the crafted URL, the server reflects the script back, and the victim\'s browser executes it.',
    attack: 'An attacker crafts a malicious URL and tricks a victim into clicking it (via email, social media, or a redirect). The browser executes the injected script, which can: steal session cookies (hijacking the account), capture keystrokes and form data, redirect to a phishing page, or install browser-based malware. XSS attacks appear to come from a trusted site, making them especially effective.',
    fix: [
      'Escape all user-supplied data before inserting it into HTML — use textContent instead of innerHTML in JavaScript, or use your framework\'s built-in escaping (e.g., {{ }} in React, Angular, and Vue are safe by default).',
      'Implement a strict Content-Security-Policy (CSP) header to prevent inline script execution even if injection occurs.',
      'Use the HttpOnly flag on session cookies so they cannot be accessed by JavaScript.',
      'Apply input validation to reject inputs containing HTML/script characters at the boundary of your application.',
    ],
  },

  // ── Security headers ───────────────────────────────────────────────────────
  'Missing HSTS': {
    what: 'HTTP Strict Transport Security (HSTS) tells browsers to always use HTTPS when visiting your site — even if someone types "http://" or clicks an http:// link. Without it, browsers will first try HTTP before being redirected to HTTPS.',
    attack: 'An attacker on the same network (café Wi-Fi, corporate network) can intercept the initial HTTP request before the redirect happens — a "SSL stripping" attack. They silently downgrade your connection to HTTP and read or modify everything in transit, including login credentials and session cookies.',
    fix: [
      'Add this header to all HTTPS responses: Strict-Transport-Security: max-age=31536000; includeSubDomains',
      'Start with a short max-age (e.g., 300 seconds) to test, then increase to 31536000 (1 year).',
      'Once confident, submit your domain to the HSTS preload list at hstspreload.org so browsers never make an HTTP connection at all.',
    ],
  },
  'Missing Content-Security-Policy': {
    what: 'A Content Security Policy (CSP) is a browser security mechanism that tells the browser which sources of scripts, styles, images, and other resources are trusted. Without it, the browser will load and execute any script from any origin.',
    attack: 'Without a CSP, any XSS vulnerability on your site immediately becomes a full script execution attack — an attacker can inject a script tag that loads malware from anywhere on the internet. A properly configured CSP would block that external script from loading even if the injection happened.',
    fix: [
      'Start with a report-only mode to understand what breaks: Content-Security-Policy-Report-Only: default-src \'self\'',
      "Tighten it gradually to: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self'; img-src 'self' data:",
      'Use nonces (Content-Security-Policy: script-src \'nonce-{random}\') on all inline scripts rather than allowing \'unsafe-inline\'.',
      'Use a CSP validator tool (csp-evaluator.withgoogle.com) to check your policy strength.',
    ],
  },
  'Missing X-Frame-Options': {
    what: 'X-Frame-Options controls whether your site can be embedded in an iframe on another website. Without it, any website can load your pages invisibly in a hidden iframe.',
    attack: 'Clickjacking attacks load your site invisibly on top of a decoy page. When the victim thinks they are clicking a "Play" button, they are actually clicking "Transfer Funds" or "Change Email" on your site invisibly beneath. This bypasses any JavaScript-based confirmation dialogs.',
    fix: [
      'Add: X-Frame-Options: DENY (blocks all framing)',
      'Or: X-Frame-Options: SAMEORIGIN (allows framing only from your own domain)',
      'The modern alternative is to use Content-Security-Policy: frame-ancestors \'self\' which is more flexible and takes precedence in modern browsers.',
    ],
  },
  'CORS Wildcard Origin': {
    what: 'CORS (Cross-Origin Resource Sharing) controls which websites can read responses from your API. The "Access-Control-Allow-Origin: *" header tells browsers "any website can read my responses" — a very permissive setting.',
    attack: 'If your API returns sensitive data (user profiles, tokens, account info) with a wildcard CORS policy, any malicious website can make requests to your API using a logged-in user\'s credentials and read the response. This is a cross-site data theft attack.',
    fix: [
      'Replace the wildcard with your specific allowed origins: Access-Control-Allow-Origin: https://yoursite.com',
      'If you need to support multiple origins, maintain an allowlist on the server and dynamically echo back the requesting origin only if it is on the list.',
      'If the API is truly public and returns no sensitive data, the wildcard is acceptable — review carefully whether responses could ever be sensitive.',
    ],
  },
  'Server Technology Disclosure': {
    what: 'Your server is revealing what software and version it is running (e.g., "Apache/2.4.41 (Ubuntu)" or "X-Powered-By: PHP/7.4"). While not directly exploitable on its own, this gives attackers a roadmap.',
    attack: 'Attackers use the version information to look up known CVEs (published vulnerabilities) for that exact software version and then run targeted exploits. Instead of trying all possible attacks, they can go directly to "Apache 2.4.41 has CVE-XXXX-XXXXX — let me exploit that".',
    fix: [
      'Apache: Set ServerTokens Prod and ServerSignature Off in your Apache config.',
      'Nginx: Set server_tokens off; in the http block of nginx.conf.',
      'PHP: Set expose_php = Off in php.ini to hide the X-Powered-By header.',
      'Regardless of hiding version info, keep all server software up to date — that is the real defence.',
    ],
  },
};

// Risk guidance text keyed by rule name (short one-liner, shown before DETAIL_INFO)
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
  'Directory Listing Enabled':
    'Directory indexing is exposed and can reveal internal files and paths to attackers.',
  'Stack Trace Disclosure':
    'Verbose runtime errors reveal internals that help attackers target known weaknesses.',
  'Potential Source Map Exposure':
    'Public source maps can leak original source code and implementation details.',
  'Debug Header Disclosure':
    'Debug response headers can expose internal tooling and diagnostics data.',
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
  const [showDetail, setShowDetail] = useState(false);
  const guidance = GUIDANCE[finding.name];
  const detail = DETAIL_INFO[finding.name];
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

          {detail && (
            <div className="detail-toggle-row">
              <button
                className="btn-link detail-toggle-btn"
                onClick={() => setShowDetail((v) => !v)}
              >
                {showDetail ? '▲ Hide explanation' : '▼ Learn more (plain English)'}
              </button>
            </div>
          )}

          {detail && showDetail && (
            <div className="detail-box">
              <div className="detail-section">
                <span className="detail-label">What this means</span>
                <p className="detail-text">{detail.what}</p>
              </div>
              <div className="detail-section">
                <span className="detail-label">What an attacker can do</span>
                <p className="detail-text detail-attack">{detail.attack}</p>
              </div>
              <div className="detail-section">
                <span className="detail-label">How to fix it</span>
                <ol className="detail-steps">
                  {detail.fix.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </div>
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
