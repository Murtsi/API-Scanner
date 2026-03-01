import { useState } from 'react';
import { SEVERITY_ORDER, SEVERITY_LABELS } from '../config/constants.js';

/**
 * Structured explanations for each finding type.
 * what   — plain-English description
 * attack — real-world attacker actions
 * fix    — numbered remediation steps
 */
const DETAIL_INFO = {
  // ── Cloud ──────────────────────────────────────────────────────────────────
  'AWS Access Key ID': {
    what: 'An AWS Access Key ID is one half of the credentials used to access Amazon cloud services. On its own it is not enough to cause harm, but paired with the Secret Access Key it provides full API access.',
    attack: 'Attackers scan public sites for leaked AWS keys using automated tools every minute. With both key parts they can spin up servers for crypto-mining, steal S3 data, exfiltrate RDS databases, or use your account to send phishing email — all billed to you.',
    fix: ['Immediately deactivate / delete this key in AWS Console → IAM → Users → Security credentials.','Check CloudTrail logs for suspicious API calls in the past 90 days.','Create a new key with minimum required permissions stored in AWS Secrets Manager or environment variables — never in code.','Enable AWS GuardDuty to automatically detect future credential misuse.'],
  },
  'AWS Secret Access Key': {
    what: 'The AWS Secret Access Key is the second half of AWS credentials — like a password paired with the Access Key ID. Together they give full programmatic access to your AWS account.',
    attack: 'An attacker can authenticate as your IAM user and do anything permitted: read/delete S3 files, create EC2 instances, exfiltrate RDS databases, or escalate to full account control if the IAM policy is permissive.',
    fix: ['Immediately revoke this key in AWS IAM Console → Security credentials.','Audit CloudTrail for API calls made with this key over the past 90 days.','Rotate all keys. Store new keys only in environment variables, AWS Secrets Manager, or a vault.','Apply least-privilege IAM policies.'],
  },
  'Azure Storage Key': {
    what: 'An Azure Storage Account key is a master credential granting full read, write, and delete access to all Blob, Table, Queue, and File storage.',
    attack: 'An attacker can download or delete every file in your Azure storage, overwrite backups, read private customer data, or use your storage as a staging area for malware — all without any Azure login.',
    fix: ['Regenerate the storage account key immediately in Azure Portal → Storage Accounts → Access keys.','Use Azure Shared Access Signatures (SAS tokens) with expiry and scope instead of account keys.','Enable Azure Defender for Storage.','Store keys in Azure Key Vault accessed via managed identities.'],
  },
  'Stripe Live Secret Key': {
    what: 'A Stripe live secret key (sk_live_…) provides master API access to your live payment account — customer billing data, charges, and refunds.',
    attack: 'An attacker can immediately: charge existing customers\' stored cards, issue refunds to themselves, access all customer payment details, create false invoices, or disable payment processing. Damage is financial and immediate.',
    fix: ['Go to Stripe Dashboard → Developers → API keys and roll the compromised key immediately.','Review the Stripe Dashboard → Logs for suspicious API calls in the past 24–72 hours.','You may have a PCI DSS reporting obligation — notify your security team.','Store the new key only in environment variables or a secrets manager. Never in source code.'],
  },
  'GitHub Personal Token': {
    what: 'A GitHub Personal Access Token (PAT) acts as a password substitute for GitHub API access, allowing repository and org operations on behalf of the account that generated it.',
    attack: 'An attacker can clone private repositories (including any secrets in git history), push malicious code, delete branches, harvest contributor email addresses, and pivot to other systems via credentials found in repos.',
    fix: ['Revoke this token in GitHub → Settings → Developer settings → Personal access tokens.','Search git history for other committed secrets and purge them using git-filter-repo or BFG Repo Cleaner.','Generate a new token with only the specific scopes needed.','Use GitHub Actions OIDC or deploy keys for CI/CD instead of personal tokens.'],
  },
  'GitLab Personal Token': {
    what: 'A GitLab Personal Access Token is equivalent to a password for GitLab API access, granting the same access as the user who created it.',
    attack: 'Attacker can access all private projects, read source code, download CI/CD pipeline logs (which often contain secrets), modify or delete code, and impersonate you in API calls.',
    fix: ['Revoke immediately in GitLab → User Settings → Access Tokens.','Audit recent API activity in the GitLab audit log.','Rotate any credentials found in accessible repositories.','Use CI/CD job tokens scoped to specific projects for pipelines.'],
  },
  'RSA Private Key': {
    what: 'An RSA private key is the secret half of a public/private key pair used for SSH authentication, TLS certificates, and code signing. Publishing it is equivalent to publishing a master password.',
    attack: 'An attacker can: silently authenticate to any server trusting the public key (SSH without a password), decrypt data encrypted to this key\'s public key, sign malicious code as you, or impersonate your HTTPS server if it\'s a TLS key.',
    fix: ['Immediately revoke and replace this key everywhere it is used (update authorized_keys on all servers, revoke certificates via your CA).','Rotate any TLS certificates signed with this key.','Generate a new key pair: ssh-keygen -t ed25519. Store private keys only in ~/.ssh/ with permissions 600, never in a repository.','Consider a hardware key (YubiKey) or SSH agent.'],
  },
  'EC Private Key': {
    what: 'An Elliptic Curve private key is used for asymmetric cryptography — authentication, digital signatures, and key agreement. It is the secret counterpart to a public key used to verify your identity.',
    attack: 'Exposure allows an attacker to impersonate you on any system trusting the public key, forge digital signatures, or decrypt communications protected with this key.',
    fix: ['Revoke and replace this key everywhere it is trusted.','Generate a new key pair and securely store only the private key (never in source code).','Investigate what the key was used for and assess whether any communications were compromised.'],
  },
  'PGP Private Key': {
    what: 'A PGP private key is used to decrypt PGP-encrypted messages and to sign documents or emails so recipients can verify authenticity.',
    attack: 'An attacker can decrypt all PGP-encrypted messages ever sent to you, forge signed messages or code commits appearing to come from you, and impersonate you in PGP-authenticated systems.',
    fix: ['Generate a revocation certificate and publish it to key servers.','Generate a new PGP key pair and distribute the new public key to contacts.','Notify anyone who may have sent PGP-encrypted messages that those may be compromised.'],
  },
  'PostgreSQL Connection String': {
    what: 'A database connection string contains the hostname, username, and password needed to connect directly to a PostgreSQL database. It is like having the address and keys to your database server.',
    attack: 'An attacker can connect directly to your database, dump all data, modify or delete records, create admin accounts, or drop entire tables — causing permanent data loss or a full breach.',
    fix: ['Change the database user\'s password immediately via ALTER USER in psql.','Check if port 5432 is publicly accessible — it should only be reachable from application servers via a firewall.','Audit recent database connections and queries for suspicious activity.','Store connection strings only in environment variables or a secrets manager.'],
  },
  'MySQL Connection String': {
    what: 'A MySQL connection string embeds the credentials needed to connect to your MySQL database. Anyone with this string has the keys to your data.',
    attack: 'Direct database access means an attacker can read all customer data, financial records, password hashes, dump the full database for offline cracking, plant backdoors, or destroy all data.',
    fix: ['Change the MySQL user\'s password: ALTER USER \'user\'@\'host\' IDENTIFIED BY \'newpassword\';','Restrict database access to application server IPs only via firewall.','Rotate all credentials in your application configuration.','Use a secrets manager to store and rotate database credentials automatically.'],
  },
  'MongoDB Connection String': {
    what: 'A MongoDB connection string includes the credentials and server address needed to connect to a MongoDB database, giving read and write access to all collections.',
    attack: 'An attacker can read all documents (user records, passwords, personal data), insert malicious data, delete collections, or use the database as a foothold for further attacks. MongoDB databases have historically been targeted for ransomware.',
    fix: ['Rotate the MongoDB user\'s credentials immediately via Atlas dashboard or db.updateUser().','Ensure MongoDB is not directly exposed to the internet — sit it behind a VPC.','Enable MongoDB audit logging.','Store credentials in environment variables or a vault solution.'],
  },
  'JSON Web Token': {
    what: 'A JSON Web Token (JWT) is a compact signed token proving authentication — like a signed digital ticket. It contains user claims (user ID, roles) used by the server to verify identity.',
    attack: 'If still valid, an attacker can replay it to authenticate as the victim user, access their data, and perform actions on their behalf. If the signing secret is also exposed, the attacker can forge arbitrary tokens as any user including admins.',
    fix: ['If this token belongs to a real session, invalidate it by rotating the JWT signing secret (invalidates all tokens) or adding it to a token blocklist.','Check the "exp" (expiry) claim — if expired, lower risk but rotate the signing secret anyway.','Never store JWTs in localStorage — prefer HttpOnly cookies.','Implement short expiry times (15–60 minutes) with refresh token rotation.'],
  },
  'Hardcoded Password': {
    what: 'A plaintext password was found directly in the website\'s source code or a JavaScript file. Hardcoded passwords are a critical security mistake because anyone who can read the code can read the password.',
    attack: 'An attacker can use this password to log into whatever service it authenticates to. Hardcoded passwords are rarely rotated, remain valid for years, and are frequently reused across multiple systems.',
    fix: ['Remove the hardcoded password from the codebase immediately and commit the change.','Rotate the password on whatever system it authenticates to.','If in a public or shared repository, assume the password has been seen — rotate regardless of who had access.','Store passwords and secrets in environment variables or a secrets manager.'],
  },
  'High-Entropy String': {
    what: 'This string appears highly random — more random than normal text or identifiers. Genuine secrets like API keys and tokens are designed to be random, so high randomness is a strong indicator this may be a real credential.',
    attack: 'If this is a real secret, an attacker who finds it can use it the same way a legitimate user would — accessing the associated service, data, or account.',
    fix: ['Inspect the value carefully — does it start with a known service prefix? Does it appear in an API key assignment?','If you believe it is a real secret, treat it as compromised: rotate it and remove it from the codebase.','If it is a legitimate non-secret (a content hash, font data), you can safely ignore this finding.'],
  },

  // ── Active test results ────────────────────────────────────────────────────
  'SQL Injection — Error-Based': {
    what: 'SQL injection occurs when user input is inserted directly into a database query without proper sanitisation. The "error-based" variant means the database printed an error message when given malformed input — confirming the injection point and revealing the database type.',
    attack: 'An attacker can: dump the entire database including passwords, emails, and payment info; bypass login pages; read files from the server\'s filesystem; in some configurations, execute OS commands. SQL injection is the #1 cause of database breaches.',
    fix: ['Replace all dynamic SQL with parameterised queries / prepared statements.','Use an ORM that handles parameterisation automatically.','Implement server-side input validation.','Apply least privilege — the database user should only have SELECT/INSERT on needed tables, never DROP or FILE.','Deploy a WAF as defence-in-depth, but do NOT rely on it as the primary defence.'],
  },
  'SQL Injection — Time-Based Blind': {
    what: 'Time-based blind SQL injection is a variant where the attacker cannot see database errors but can infer code execution by measuring response time. A SLEEP(3) or WAITFOR DELAY command was injected and the server responded 3 seconds later than baseline — confirming code execution.',
    attack: 'Even without visible errors, an attacker can slowly extract data character by character, enumerate the database schema, and dump password hashes for offline cracking. This technique bypasses many WAF rules because there are no obvious error strings.',
    fix: ['Use parameterised queries / prepared statements — this is the only reliable fix.','Time-based SQLi is especially hard to detect; this finding likely means the vulnerability has existed unnoticed for some time. Audit all database-touching code paths.','Monitor database query times — a spike of 3-second queries is an indicator of active exploitation.'],
  },
  'NoSQL Injection (MongoDB Operator)': {
    what: 'NoSQL injection occurs when query operators ($ne, $gt, $regex) are injected through URL parameters or JSON body fields. When an application passes request parameters directly into a MongoDB query filter, these operators alter the query\'s logic.',
    attack: 'An attacker can bypass authentication by replacing a password field with {"$ne": null} — meaning "find a user where the password is not null", which matches every user. This is how attackers log in as the first admin without knowing any password.',
    fix: ['Never pass raw request parameters directly into MongoDB query objects.','Validate and sanitise all inputs: confirm they are the expected type (string, number) before using in queries.','Use schema validation libraries (Joi, Zod, Yup) to enforce input shapes.','In Express/Node.js, consider express-mongo-sanitize middleware to strip $ and . from request data automatically.'],
  },
  'Reflected XSS': {
    what: 'Cross-Site Scripting occurs when a website echoes user input back in a page without escaping special characters. In the reflected variant, the malicious input travels in the URL — when a victim visits the crafted URL, the server reflects the script back and the browser executes it.',
    attack: 'An attacker crafts a malicious URL and tricks a victim into clicking it. The browser executes the injected script, which can: steal session cookies (hijacking the account), capture keystrokes, redirect to a phishing page, or install browser-based malware. XSS attacks appear to come from a trusted site.',
    fix: ['Escape all user-supplied data before inserting into HTML — use textContent instead of innerHTML.','Implement a strict Content-Security-Policy (CSP) header to prevent inline script execution even if injection occurs.','Use the HttpOnly flag on session cookies.','Apply input validation to reject inputs containing HTML/script characters.'],
  },
  'Path Traversal / Local File Inclusion': {
    what: 'Path traversal allows an attacker to read files outside the intended directory by injecting sequences like ../../../etc/passwd into file-handling parameters. Local File Inclusion (LFI) is a related vulnerability where the server executes or renders a file based on user-supplied path input.',
    attack: 'An attacker can read: /etc/passwd (user accounts), /etc/shadow (password hashes), application configuration files with database credentials, private keys, .env files, and internal source code. In some configurations this escalates to Remote Code Execution via log poisoning or PHP wrappers.',
    fix: ['Validate all file paths against a strict allowlist of permitted filenames.','Use realpath() (PHP/Python) or Path.resolve() (Node.js) to resolve paths, then assert they begin with the intended base directory.','Never allow user input to directly control which file is opened or included.','Run your application with the minimum filesystem permissions required.'],
  },
  'Command Injection (OS)': {
    what: 'Command injection occurs when user-supplied input is passed to a system shell command without proper sanitisation. Shell metacharacters (;, |, &&, $(), backticks) allow attackers to append additional commands to the intended one.',
    attack: 'An attacker achieves arbitrary OS command execution on the server: reading /etc/passwd and /etc/shadow, listing directory contents, establishing a reverse shell for persistent access, creating new user accounts, downloading and executing malware, and pivoting to internal network services.',
    fix: ['Never pass user input to shell commands. Use parameterised subprocess calls with explicit argument arrays (e.g., subprocess.run([\'cmd\', arg], shell=False) in Python).','Apply allowlist-only input validation — reject anything not matching the expected character set.','Drop unnecessary OS-level privileges from your application process.','Consider running the application in a container or sandbox with restricted syscalls (seccomp, AppArmor).'],
  },
  'Server-Side Template Injection (SSTI)': {
    what: 'SSTI occurs when user input is embedded directly into a server-side template as template code rather than as data. Template engines like Jinja2, Twig, Freemarker, and ERB evaluate expressions in their template syntax — if user input contains those expressions, they are evaluated.',
    attack: 'SSTI typically leads to Remote Code Execution. An attacker can use template syntax to access language built-ins, import OS modules, and execute arbitrary commands on the server. From the initial SSTI, an attacker can achieve full server compromise via a single parameter injection.',
    fix: ['Never render user-controlled input as a template. Pass user data as context variables only — never as template source code.','Validate and sanitise any input that will be used in template contexts.','If sandboxed template rendering is genuinely required, use a purpose-built sandboxed environment (Jinja2 SandboxedEnvironment).','Apply strict input validation to reject template syntax characters ({{ }}, ${ }, <% %>) in user input.'],
  },
  'Open Redirect': {
    what: 'Open redirect vulnerabilities occur when a web application redirects users to a URL specified via a parameter without validating that the destination is a trusted location. The URL appears to be from the legitimate site, making it highly effective for phishing.',
    attack: 'An attacker crafts a URL like yoursite.com/login?redirect=https://evil.com and sends it to victims via email or social media. Victims see the legitimate domain and trust the link; after clicking they are redirected to a phishing page harvesting credentials or delivering malware.',
    fix: ['Validate redirect targets against a strict allowlist of known-good paths or domains.','Use relative paths only for post-authentication redirects — avoid absolute URLs from user input.','If absolute URLs are needed, maintain a server-side list of allowed redirect destinations and reject anything not on it.','Consider using opaque redirect tokens that map to pre-configured URLs server-side.'],
  },
  'Server-Side Request Forgery (SSRF)': {
    what: 'SSRF vulnerabilities allow attackers to make the server perform HTTP requests to arbitrary URLs, including internal services and cloud metadata endpoints that are normally not accessible from the internet.',
    attack: 'An attacker can: access cloud instance metadata (169.254.169.254) to steal IAM credentials and take over cloud infrastructure, probe internal services (Redis, Elasticsearch, internal APIs, databases), bypass firewalls by routing requests through the server, and access services that only trust the server\'s IP address.',
    fix: ['Validate all outbound request URLs against a strict allowlist of permitted destinations.','Block RFC 1918 private IP ranges (10.x, 172.16-31.x, 192.168.x) and link-local addresses (169.254.x.x) at the network/firewall layer.','Require IMDSv2 (PUT-request token flow) for AWS EC2 instances to prevent metadata service SSRF.','Use a dedicated egress proxy that enforces allowlist-only outbound HTTP.'],
  },
  'Host Header Injection': {
    what: 'Host header injection occurs when an application uses the HTTP Host header to generate URLs (e.g., for password reset links, email confirmations, or API base URLs) without validating that it matches the legitimate configured domain.',
    attack: 'An attacker makes a password reset request with a forged Host header pointing to their server (e.g., X-Forwarded-Host: attacker.com). The application generates a reset link to attacker.com, sends it to the victim\'s email, and when the victim clicks it, the attacker captures the reset token and takes over the account. Also enables web cache poisoning.',
    fix: ['Whitelist the allowed hostnames explicitly in server configuration — reject requests with unrecognized Host headers.','Never use the Host header to construct absolute URLs — use a configured BASE_URL environment variable instead.','Configure your reverse proxy (Nginx, Apache) to validate and normalise the Host header before passing it to the application.','Implement cache-control headers correctly to prevent poisoned responses from being cached.'],
  },
  'CORS Origin Reflection / Misconfiguration': {
    what: 'Cross-Origin Resource Sharing (CORS) controls which websites can read your API\'s responses. A misconfigured CORS policy that reflects arbitrary Origin headers — especially combined with Access-Control-Allow-Credentials: true — allows any website to read your API responses on behalf of logged-in users.',
    attack: 'An attacker\'s website makes JavaScript API requests to your API. If CORS reflects the attacker\'s origin and credentials are allowed, the attacker\'s script can read the full API response including session data, user profiles, tokens, and any other sensitive data the logged-in victim can access. All of this happens invisibly to the victim.',
    fix: ['Maintain an explicit allowlist of trusted origins on the server. Never reflect arbitrary Origin headers.','Never combine a wildcard (Access-Control-Allow-Origin: *) with Access-Control-Allow-Credentials: true — this combination is prohibited by spec but some servers do it anyway.','Only enable CORS for endpoints that genuinely need cross-origin access.','Validate the Origin header against your allowlist before including it in the ACAO response header.'],
  },
  'HTTP TRACE Method Enabled': {
    what: 'The HTTP TRACE method is a diagnostic method that reflects the full request back to the client, including all HTTP headers. This enables Cross-Site Tracing (XST) attacks when combined with XSS.',
    attack: 'An attacker uses XSS to trigger an XMLHttpRequest with the TRACE method to the same server. The server reflects the request back including HttpOnly cookies, Authorization headers, and other sensitive headers that JavaScript cannot normally access — stealing credentials that were supposed to be protected from JavaScript.',
    fix: ['Disable the TRACE and TRACK methods in your web server configuration: Apache: TraceEnable Off, Nginx: if ($request_method = TRACE) { return 405; }.','Verify using: curl -X TRACE https://yoursite.com — should return 405 Method Not Allowed.'],
  },
  'HTTP Verb Tampering — DELETE Unexpectedly Accepted': {
    what: 'HTTP verb tampering occurs when an application accepts HTTP methods (PUT, DELETE, PATCH) that are not part of its intended API contract. This can enable unauthorized data modification or deletion.',
    attack: 'An attacker sends DELETE or PUT requests to endpoints that should only respond to GET, bypassing business logic that only checks for GET requests. This can delete resources, overwrite data, or trigger unintended state changes in the application.',
    fix: ['Explicitly allowlist HTTP methods per route — any method not in the allowlist should return 405 Method Not Allowed.','Implement method allowlisting at the web server or API gateway level in addition to application-level checks.','Ensure your authorization checks apply to all HTTP methods, not just GET and POST.'],
  },
  'HTTP Verb Tampering — PUT Unexpectedly Accepted': {
    what: 'HTTP verb tampering occurs when an application accepts HTTP methods that are not part of its intended API contract. Accepting PUT on read-only endpoints may allow unauthorized data modification.',
    attack: 'An attacker sends PUT requests to endpoints that should only respond to GET, potentially overwriting resources, creating new ones, or bypassing business logic checks that only validate GET requests.',
    fix: ['Explicitly allowlist HTTP methods per route — any method not in the allowlist should return 405 Method Not Allowed.','Implement method allowlisting at the web server or API gateway level.','Ensure authorization checks apply to all HTTP methods, not just GET and POST.'],
  },
  'CRLF / HTTP Response Splitting': {
    what: 'CRLF injection occurs when carriage-return (\\r) and line-feed (\\n) characters embedded in user input are placed into HTTP response headers without sanitisation. This allows an attacker to inject arbitrary HTTP headers and split the response.',
    attack: 'An attacker can inject: Set-Cookie headers to fix a victim\'s session token (session fixation), Location headers to redirect after a 200 response, arbitrary headers to poison web caches, and in some cases inject a new HTTP body (response splitting) enabling XSS even when no XSS exists in the application itself.',
    fix: ['Strip or reject CR (\\r = %0d) and LF (\\n = %0a) characters from any user input that is placed into HTTP response headers.','Use your web framework\'s built-in header-setting APIs — they typically handle CRLF encoding automatically.','Apply a Web Application Firewall rule to detect and block CRLF sequences in query parameters.'],
  },
  'GraphQL Introspection Enabled': {
    what: 'GraphQL introspection is a feature that allows any client to query the complete schema — all available queries, mutations, subscriptions, types, and fields. In production, this provides attackers with a complete map of your API surface.',
    attack: 'An attacker runs an introspection query to extract the full schema, identifies sensitive mutations (deleteUser, transferFunds, grantAdmin), finds hidden or undocumented fields, and methodically tests each operation for authorization bypasses, injection vulnerabilities, and business logic flaws. Tools like graphql-voyager visualise the schema as an interactive graph.',
    fix: ['Disable introspection in production GraphQL deployments.','If introspection is needed for internal tooling, restrict it to authenticated admin users with a separate middleware check.','Implement query depth and complexity limits to prevent abuse even for authenticated users.','Consider GraphQL query allowlisting (persisted queries) for production traffic.','If batch query execution is enabled, rate-limit it to prevent query complexity abuse.'],
  },
  'XML External Entity Injection (XXE)': {
    what: 'XXE injection occurs when an XML parser is configured to resolve external entities — references defined in a DOCTYPE that point to external resources like local files (file://) or internal URLs (http://). If an application processes user-supplied XML, an attacker can define malicious entities.',
    attack: 'An attacker can: read arbitrary files from the server\'s filesystem (/etc/passwd, /etc/shadow, application config files), probe internal network services by forcing HTTP requests, trigger Denial of Service via "Billion Laughs" entity expansion attacks, and in some configurations achieve Remote Code Execution through expect:// or jar:// URI handlers.',
    fix: ['Disable external entity processing in your XML parser configuration: defusedxml for Python, FEATURE_DISALLOW_DOCTYPE_DECL in Java, libxml_disable_entity_loader() in PHP (deprecated), or use a well-configured modern parser.','Where possible, use JSON instead of XML for API communication.','Apply input validation to reject DOCTYPE declarations in user-supplied XML.','Run the XML parser in a sandboxed process with no filesystem or network access.'],
  },
  'Potential IDOR — Insecure Direct Object Reference': {
    what: 'Insecure Direct Object Reference (IDOR) occurs when an application uses user-controlled values (like sequential numeric IDs) to directly access objects without verifying that the requesting user has permission for that specific object.',
    attack: 'An attacker changes the ID in an API request from their own user ID to another user\'s ID and receives that user\'s data — profile information, orders, medical records, financial data, messages, or any other per-user resource. Because the IDs are sequential integers, an attacker can enumerate all records systematically.',
    fix: ['Implement object-level authorization on every resource request — verify the requesting user owns or has permission for the specific resource ID, not just that they are authenticated.','Use opaque, non-sequential, globally unique identifiers (UUID v4) instead of sequential integers for resource IDs.','Perform authorization checks server-side, never rely on the client not sending certain IDs.','Log and alert on rapid sequential access patterns that may indicate enumeration.'],
  },
  'HTTP Parameter Pollution (HPP)': {
    what: 'HTTP Parameter Pollution occurs when duplicate parameters are sent in a request. Different servers and frameworks parse duplicate parameters differently — PHP takes the last value, Express.js returns an array, ASP.NET returns a comma-separated string — creating inconsistencies that can be exploited.',
    attack: 'An attacker sends duplicate parameters to: bypass WAF rules (WAF checks the first occurrence, application uses the last), override access controls (role=user in first occurrence, role=admin in second), trigger unexpected application behaviour from parameter array handling, or inject SQL/XSS payloads into the second occurrence that the WAF doesn\'t check.',
    fix: ['Define and enforce consistent parameter parsing — always take the first or last occurrence of a parameter, never both.','Reject requests with duplicate parameters if your API does not expect them (return 400 Bad Request).','Ensure WAF rules apply to all parameter occurrences, not just the first.','Use strongly-typed request schemas (OpenAPI/JSON Schema validation) to reject unexpected parameter structures.'],
  },
  'CORS Wildcard Origin': {
    what: 'CORS (Cross-Origin Resource Sharing) controls which websites can read your API\'s responses. The "Access-Control-Allow-Origin: *" header tells browsers any website can read your responses.',
    attack: 'If your API returns sensitive data with a wildcard CORS policy, any malicious website can make requests to your API using a logged-in user\'s credentials and read the response — a cross-site data theft attack.',
    fix: ['Replace the wildcard with specific allowed origins: Access-Control-Allow-Origin: https://yoursite.com','If you need multiple origins, maintain an allowlist and dynamically echo back the requesting origin only if it is on the list.','If the API is truly public and returns no sensitive data, the wildcard may be acceptable — review carefully.'],
  },
  'Path Traversal / LFI': {
    what: 'Path traversal happens when user-controlled input is used to build filesystem paths. Attackers can include traversal sequences like ../ to escape intended directories and read arbitrary files from the server.',
    attack: 'An attacker can read sensitive local files such as environment configs, credentials, or OS account data. Those leaked secrets can then be used for lateral movement and full service compromise.',
    fix: [
      'Do not concatenate raw user input into file paths.',
      'Canonicalize resolved paths and enforce they stay inside a strict allowlisted base directory.',
      'Use IDs or allowlisted filenames instead of accepting direct path input in requests.',
      'Block traversal tokens and encoded variants (../, ..\\, %2f, %5c) at validation boundaries.',
    ],
  },
  'Command Injection': {
    what: 'Command injection occurs when user input is passed into shell or system commands without strict separation and validation.',
    attack: 'If exploitable, attackers can execute arbitrary OS commands, read sensitive files, alter server state, and potentially gain remote control of the host process context.',
    fix: [
      'Avoid shell execution for user-influenced functionality whenever possible.',
      'When process execution is required, use safe APIs that pass arguments as arrays and avoid shell interpolation.',
      'Apply strict allowlists for accepted commands and argument values.',
      'Run services with least-privilege OS users and isolate risky operations in constrained environments.',
    ],
  },

  // ── Passive findings ───────────────────────────────────────────────────────
  'Missing HSTS': {
    what: 'HTTP Strict Transport Security (HSTS) tells browsers to always use HTTPS when visiting your site. Without it, browsers will first try HTTP before being redirected to HTTPS.',
    attack: 'An attacker on the same network (café Wi-Fi, corporate network) can intercept the initial HTTP request before the redirect happens — a "SSL stripping" attack. They silently downgrade your connection to HTTP and read or modify everything in transit.',
    fix: ['Add: Strict-Transport-Security: max-age=31536000; includeSubDomains','Start with a short max-age (300 seconds) to test, then increase to 31536000 (1 year).','Submit your domain to the HSTS preload list at hstspreload.org so browsers never make an HTTP connection at all.'],
  },
  'Missing Content-Security-Policy': {
    what: 'A Content Security Policy (CSP) tells the browser which sources of scripts, styles, images, and other resources are trusted. Without it, the browser will load and execute any script from any origin.',
    attack: 'Without a CSP, any XSS vulnerability immediately becomes a full script execution attack — an attacker can inject a script tag loading malware from anywhere on the internet. A properly configured CSP would block that external script.',
    fix: ["Start with report-only mode: Content-Security-Policy-Report-Only: default-src 'self'","Tighten it: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'","Use nonces on all inline scripts rather than allowing 'unsafe-inline'.","Use a CSP validator (csp-evaluator.withgoogle.com) to check policy strength."],
  },
  'Missing X-Frame-Options': {
    what: 'X-Frame-Options controls whether your site can be embedded in an iframe on another website. Without it, any website can load your pages invisibly in a hidden iframe.',
    attack: 'Clickjacking attacks load your site invisibly on top of a decoy page. When the victim thinks they are clicking "Play", they are actually clicking "Transfer Funds" or "Change Email" on your site beneath. This bypasses JavaScript-based confirmation dialogs.',
    fix: ['Add: X-Frame-Options: DENY (blocks all framing)','Or: X-Frame-Options: SAMEORIGIN (allows framing only from your own domain)','The modern alternative is CSP: frame-ancestors \'self\' which takes precedence in modern browsers.'],
  },
  'Server Technology Disclosure': {
    what: 'Your server is revealing what software and version it is running (e.g., "Apache/2.4.41 (Ubuntu)" or "X-Powered-By: PHP/7.4"). While not directly exploitable, this gives attackers a roadmap.',
    attack: 'Attackers use the version information to look up known CVEs for that exact software version and run targeted exploits. Instead of trying all possible attacks, they can go directly to known vulnerabilities for the identified version.',
    fix: ['Apache: Set ServerTokens Prod and ServerSignature Off.','Nginx: Set server_tokens off; in the http block of nginx.conf.','PHP: Set expose_php = Off in php.ini.','Keep all server software up to date — that is the real defence.'],
  },
};

// ── Short guidance text keyed by rule name ─────────────────────────────────────

const GUIDANCE = {
  'AWS Access Key ID': 'Pair with the Secret Access Key to fully authenticate as the IAM user — grants broad cloud access.',
  'AWS Secret Access Key': 'Combined with an Access Key ID this enables full programmatic AWS access including billing.',
  'AWS Session Token': 'Temporary credential — still grants AWS access until it expires.',
  'Stripe Live Secret Key': 'Enables real payment charges and read access to live customer billing data.',
  'Stripe Test Key': 'Test-mode only, but reveals integration details and can disrupt test pipelines.',
  'Stripe Webhook Secret': 'Allows forging webhook events to your backend, bypassing signature validation.',
  'Google API Key': 'Can call paid Google APIs (Maps, Vision, Translate) incurring charges on the owner\'s account.',
  'Google OAuth Token': 'Short-lived but grants live Google API access as the authorizing user.',
  'Google Service Account': 'Full service-account credentials — can escalate to any role bound to the account.',
  'GitHub Personal Token': 'Grants repository and org access matching the token\'s scopes. Rotate immediately.',
  'GitHub OAuth Token': 'OAuth token granting access scoped to the app\'s permissions.',
  'GitHub App Token': 'App installation token — access scoped to repo/org permissions.',
  'GitHub Classic Token': 'Classic 40-char PAT — may have broad repo/org access.',
  'GitLab Personal Token': 'Full API access to GitLab projects, issues, and CI/CD pipelines.',
  'GitLab Runner Token': 'Can register new runners and intercept CI jobs.',
  'Slack Bot Token': 'Can read/post messages, access DMs, and manage workspace resources.',
  'Slack User Token': 'Acts on behalf of the authorizing user — read DMs, post messages.',
  'Slack Incoming Webhook': 'Can post arbitrary messages to the configured channel.',
  'Twilio Account SID': 'Identifier needed alongside Auth Token for full Twilio access.',
  'Twilio Auth Token': 'Full Twilio access — can send SMS/voice and incur charges.',
  'SendGrid API Key': 'Can send email on behalf of the domain — spam, phishing, and reputation risk.',
  'Mailgun API Key': 'Can send email and access message logs.',
  'Firebase Server Key': 'Can push notifications to all app users; may also access Firebase data depending on rules.',
  'Azure Storage Key': 'Full read/write/delete access to Azure Blob, Table, and Queue storage.',
  'Azure Client Secret': 'Authenticates an Azure AD application — scope depends on assigned roles.',
  'Heroku API Key': 'Manage apps, view config vars, and deploy code on Heroku.',
  'Shopify Access Token': 'Grants store API access — orders, customers, products depending on scopes.',
  'Discord Bot Token': 'Full bot control — can read/send messages and manage servers.',
  'Discord Webhook URL': 'Can post messages to the configured Discord channel.',
  'NPM Access Token': 'Can publish packages or read private packages depending on access level.',
  'Terraform Cloud Token': 'Can read state files and trigger runs — state may contain secrets.',
  'Datadog API Key': 'Can submit metrics, read monitors, and access logs.',
  'HashiCorp Vault Token': 'Grants access to Vault secrets — scope depends on policy.',
  'JSON Web Token': 'Decode to check claims and expiry — may grant session or API access.',
  'JWT Refresh Token': 'Can mint new access tokens, extending unauthorized access.',
  'Bearer Token': 'Direct API authorization — equivalent to a password for the API.',
  'RSA Private Key': 'Can authenticate as the key owner or decrypt data encrypted to the public key.',
  'EC Private Key': 'Elliptic curve private key used for signing or ECDH key exchange.',
  'Generic Private Key': 'Private key material must never be public — rotate and revoke immediately.',
  'PGP Private Key': 'Can sign or decrypt PGP messages as the key owner.',
  'PostgreSQL Connection String': 'Contains database credentials — direct read/write access to the database.',
  'MySQL Connection String': 'Contains database credentials — direct read/write access to the database.',
  'MongoDB Connection String': 'Contains database credentials — direct read/write access to the cluster.',
  'Redis Connection String': 'Contains Redis password — can read/write all cache data.',
  'Hardcoded Password': 'Literal password in code — likely shared or reused across systems.',
  'High-Entropy String': 'Appears randomly generated — may be an undeclared API key or secret.',
  'Directory Listing Enabled': 'Directory indexing is exposed and can reveal internal files and paths to attackers.',
  'Stack Trace Disclosure': 'Verbose runtime errors reveal internals that help attackers target known weaknesses.',
  'Potential Source Map Exposure': 'Public source maps can leak original source code and implementation details.',
  'Debug Header Disclosure': 'Debug response headers can expose internal tooling and diagnostics data.',
  'Path Traversal / LFI': 'File path input may be escaping intended directories and exposing local sensitive files.',
  'Command Injection': 'User input appears to affect backend shell/system command execution paths.',
  // Active findings
  'SQL Injection — Error-Based': 'Error-based SQLi confirmed — database error messages leaked in response.',
  'SQL Injection — Time-Based Blind': 'Timing side-channel confirmed — SLEEP/WAITFOR delay executed by the database.',
  'NoSQL Injection (MongoDB Operator)': 'MongoDB operator injection bypassed authentication or query logic.',
  'Reflected XSS': 'Injected HTML/script tag reflected unescaped — executes in victim browser.',
  'Path Traversal / Local File Inclusion': 'Server reads filesystem paths based on user input — system files accessible.',
  'Command Injection (OS)': 'OS command output detected in response — server executes user-supplied shell commands.',
  'Server-Side Template Injection (SSTI)': 'Template expression evaluated server-side — leads to arbitrary code execution.',
  'Open Redirect': 'Redirect parameter accepts external URLs — enables phishing link abuse.',
  'Server-Side Request Forgery (SSRF)': 'Server fetches attacker-controlled internal URLs — cloud metadata or internal services accessible.',
  'Host Header Injection': 'Host header reflected in response — enables password reset link poisoning and cache poisoning.',
  'CORS Origin Reflection / Misconfiguration': 'Arbitrary Origin reflected in ACAO — attacker site can read API responses cross-origin.',
  'HTTP TRACE Method Enabled': 'TRACE reflects full request including HttpOnly cookies — enables Cross-Site Tracing (XST).',
  'CRLF / HTTP Response Splitting': 'CR/LF characters injected into response headers — enables session fixation and cache poisoning.',
  'GraphQL Introspection Enabled': 'Full GraphQL schema exposed — complete API map available to attackers.',
  'XML External Entity Injection (XXE)': 'XML parser resolved external entity — server files readable by attacker.',
  'Potential IDOR — Insecure Direct Object Reference': 'Sequential ID parameter returns different resources — authorization not enforced per object.',
  'HTTP Parameter Pollution (HPP)': 'Duplicate parameters change server behaviour — may bypass WAF rules or access controls.',
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
  header:  { label: 'Header',  cls: 'type-header' },
  vuln:    { label: 'Active',  cls: 'type-vuln' },
  passive: { label: 'Passive', cls: 'type-passive' },
};

function FindingCard({ finding }) {
  const [open, setOpen] = useState(true);
  const [showDetail, setShowDetail] = useState(false);
  const guidance = GUIDANCE[finding.name];

  // Try exact match first, then prefix match for dynamic names (e.g. "DOM XSS Sink: …")
  let detail = DETAIL_INFO[finding.name];
  if (!detail) {
    const prefix = Object.keys(DETAIL_INFO).find((k) => finding.name.startsWith(k.split(':')[0]));
    if (prefix) detail = DETAIL_INFO[prefix];
  }

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

          {/* Technique / targeting info — shown for active & passive findings */}
          {finding.targeting && (
            <div className="technique-box">
              <span className="technique-label">Method</span>
              <span className="technique-text">{finding.targeting}</span>
            </div>
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

const PASSIVE_SKIP_LABELS = {
  disabled: 'disabled',
  'experimental-disabled': 'experimental off',
  'threshold-filtered': 'filtered by threshold',
  error: 'module error',
};

function PassiveModuleSummary({ modules }) {
  if (!Array.isArray(modules) || modules.length === 0) return null;

  const skipped = modules.filter((module) => module.skippedReason);
  if (skipped.length === 0) return null;

  return (
    <div className="passive-summary">
      <strong className="small">Passive modules skipped</strong>
      <div className="passive-summary-list">
        {skipped.map((module) => (
          <span key={module.id} className="passive-skip-tag">
            {module.label}: {PASSIVE_SKIP_LABELS[module.skippedReason] || module.skippedReason}
            {module.skippedReason === 'threshold-filtered' && module.filteredOutCount > 0
              ? ` (${module.filteredOutCount})`
              : ''}
          </span>
        ))}
      </div>
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

  // Count by type
  const activeCount  = result.findings.filter((f) => f.type === 'vuln').length;
  const passiveCount = result.findings.filter((f) => f.type === 'passive').length;
  const headerCount  = result.findings.filter((f) => f.type === 'header').length;
  const secretCount  = result.findings.filter((f) => !f.type).length;

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
              {result.exposedFiles.length} exposed file{result.exposedFiles.length !== 1 ? 's' : ''}
            </span>
          )}
          {activeCount > 0 && (
            <span className="meta-tag meta-active">{activeCount} active finding{activeCount !== 1 ? 's' : ''}</span>
          )}
          {passiveCount > 0 && (
            <span className="meta-tag meta-passive-tag">{passiveCount} passive finding{passiveCount !== 1 ? 's' : ''}</span>
          )}
          {headerCount > 0 && (
            <span className="meta-tag">{headerCount} header issue{headerCount !== 1 ? 's' : ''}</span>
          )}
          {secretCount > 0 && (
            <span className="meta-tag meta-secret">{secretCount} secret{secretCount !== 1 ? 's' : ''}</span>
          )}
          {!hasFindings && <span className="badge sev-none">Clean</span>}
        </div>
      </div>

      {hasFindings && <SeveritySummary findings={result.findings} />}
      <PassiveModuleSummary modules={result.passiveModuleSummary} />

      <div className="findings-list">
        {result.findings.map((f) => (
          <FindingCard key={f.id} finding={f} />
        ))}
      </div>

      {result.exposedFiles?.length > 0 && (
        <div className="exposed-section">
          <strong className="small">Exposed Files / Paths</strong>
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
  const [skipReasonFilter, setSkipReasonFilter] = useState(null);
  const [typeFilter, setTypeFilter] = useState(null);

  const totalTypes = results.reduce((n, r) => n + (r.findings?.length ?? 0), 0);
  const totalCritical = results.reduce(
    (n, r) => n + (r.findings?.filter((f) => f.severity === 'critical').length ?? 0),
    0
  );
  const totalPassiveSkipped = results.reduce(
    (n, r) => n + (r.passiveModuleSummary?.filter((m) => m.skippedReason).length ?? 0),
    0
  );

  const skipReasonCounts = Object.fromEntries(
    Object.keys(PASSIVE_SKIP_LABELS).map((reason) => [
      reason,
      results.reduce(
        (n, r) => n + (r.passiveModuleSummary?.filter((m) => m.skippedReason === reason).length ?? 0),
        0
      ),
    ])
  );

  const filteredResults = results
    .map((r) => ({
      ...r,
      findings: r.findings.filter((f) => {
        if (severityFilter && f.severity !== severityFilter) return false;
        if (typeFilter === 'active'  && f.type !== 'vuln')    return false;
        if (typeFilter === 'passive' && f.type !== 'passive') return false;
        if (typeFilter === 'header'  && f.type !== 'header')  return false;
        if (typeFilter === 'secrets' && f.type)               return false;
        return true;
      }),
    }))
    .filter((r) => {
      if (!skipReasonFilter) return true;
      return (r.passiveModuleSummary || []).some((m) => m.skippedReason === skipReasonFilter);
    });

  if (results.length === 0 && !isScanning) {
    return (
      <div className="results-empty card">
        <div className="empty-icon">⊙</div>
        <p className="muted">
          Enter URLs above and click <strong>Start scan</strong> to begin.
        </p>
        <p className="muted small">
          Professional-grade security assessment covering secrets, headers, active exploits, and passive code analysis.
        </p>
        <div className="empty-capabilities">
          <span className="empty-cap">49+ Secret Patterns</span>
          <span className="empty-cap">130+ Exposed Paths</span>
          <span className="empty-cap">18 Attack Methods</span>
          <span className="empty-cap">DOM XSS Sinks</span>
          <span className="empty-cap">Vulnerable Libraries</span>
          <span className="empty-cap">Security Headers</span>
          <span className="empty-cap">SSRF / XXE / SSTI</span>
          <span className="empty-cap">GraphQL Introspection</span>
          <span className="empty-cap">Tech Fingerprinting</span>
        </div>
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
            {totalPassiveSkipped > 0 && (
              <span className="meta-tag">{totalPassiveSkipped} passive skipped</span>
            )}
            <span className="muted small">
              across {results.length} target{results.length !== 1 ? 's' : ''}
            </span>
          </div>

          <div className="toolbar-actions">
            <div className="filter-row">
              {/* Severity filters */}
              <button
                className={`btn-filter ${!severityFilter && !typeFilter ? 'active' : ''}`}
                onClick={() => { setSeverityFilter(null); setTypeFilter(null); }}
              >
                All
              </button>
              {SEVERITY_ORDER.map((sev) => (
                <button
                  key={sev}
                  className={`btn-filter sev-filter-${sev} ${severityFilter === sev ? 'active' : ''}`}
                  onClick={() => { setSeverityFilter(sev === severityFilter ? null : sev); setTypeFilter(null); }}
                >
                  {SEVERITY_LABELS[sev]}
                </button>
              ))}
              {/* Type filters */}
              {[
                { key: 'active',  label: 'Active' },
                { key: 'passive', label: 'Passive' },
                { key: 'header',  label: 'Headers' },
                { key: 'secrets', label: 'Secrets' },
              ].map(({ key, label }) => (
                <button
                  key={key}
                  className={`btn-filter type-filter-${key} ${typeFilter === key ? 'active' : ''}`}
                  onClick={() => { setTypeFilter(typeFilter === key ? null : key); setSeverityFilter(null); }}
                >
                  {label}
                </button>
              ))}
            </div>

            {totalPassiveSkipped > 0 && (
              <div className="filter-row skip-filter-row">
                <span className="filter-label">Passive skips</span>
                <button
                  className={`btn-filter ${!skipReasonFilter ? 'active' : ''}`}
                  onClick={() => setSkipReasonFilter(null)}
                >
                  All
                </button>
                {Object.entries(PASSIVE_SKIP_LABELS).map(([reason, label]) => {
                  const count = skipReasonCounts[reason] || 0;
                  if (count === 0) return null;
                  return (
                    <button
                      key={reason}
                      className={`btn-filter ${skipReasonFilter === reason ? 'active' : ''}`}
                      onClick={() => setSkipReasonFilter(reason === skipReasonFilter ? null : reason)}
                    >
                      {label} ({count})
                    </button>
                  );
                })}
              </div>
            )}

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
