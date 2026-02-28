/**
 * Built-in detection rules — 49 patterns across 12 categories.
 * Each rule has: id, name, category, severity, regex (with /g flag), description.
 */
export const BASE_RULES = [
  // ─── AWS ──────────────────────────────────────────────────────────────────
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    category: 'Cloud',
    severity: 'critical',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    description: 'AWS Access Key ID (AKIA prefix) — identifies an IAM user or role.',
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key',
    category: 'Cloud',
    severity: 'critical',
    regex: /(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["'`]?([A-Za-z0-9+/]{40})["'`]?/gi,
    description: 'AWS Secret Access Key (40 characters) paired with an access key ID.',
  },
  {
    id: 'aws-session-token',
    name: 'AWS Session Token',
    category: 'Cloud',
    severity: 'critical',
    regex: /(?:aws[_\-.]?session[_\-.]?token|AWS_SESSION_TOKEN)\s*[:=]\s*["'`]?([A-Za-z0-9+/=]{100,})["'`]?/gi,
    description: 'Temporary STS session token — grants AWS access until expiry.',
  },

  // ─── Stripe ───────────────────────────────────────────────────────────────
  {
    id: 'stripe-live',
    name: 'Stripe Live Secret Key',
    category: 'Payment',
    severity: 'critical',
    regex: /sk_live_[0-9A-Za-z]{24,}/g,
    description: 'Live Stripe secret key — enables real payment charges and billing access.',
  },
  {
    id: 'stripe-test',
    name: 'Stripe Test Key',
    category: 'Payment',
    severity: 'high',
    regex: /sk_test_[0-9A-Za-z]{24,}/g,
    description: 'Stripe test secret key — reveals integration details.',
  },
  {
    id: 'stripe-webhook',
    name: 'Stripe Webhook Secret',
    category: 'Payment',
    severity: 'high',
    regex: /whsec_[0-9A-Za-z]{32,}/g,
    description: 'Stripe webhook endpoint signing secret.',
  },
  {
    id: 'stripe-restricted',
    name: 'Stripe Restricted Key',
    category: 'Payment',
    severity: 'high',
    regex: /rk_live_[0-9A-Za-z]{24,}/g,
    description: 'Stripe restricted API key (live mode).',
  },

  // ─── Google ───────────────────────────────────────────────────────────────
  {
    id: 'google-api-key',
    name: 'Google API Key',
    category: 'Google',
    severity: 'high',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    description: 'Google API key (AIza prefix) — can call paid Google APIs.',
  },
  {
    id: 'google-oauth',
    name: 'Google OAuth Token',
    category: 'Google',
    severity: 'high',
    regex: /ya29\.[0-9A-Za-z\-_]+/g,
    description: 'Google OAuth 2.0 short-lived access token.',
  },
  {
    id: 'google-service-account',
    name: 'Google Service Account',
    category: 'Google',
    severity: 'critical',
    regex: /"type"\s*:\s*"service_account"/g,
    description: 'Google service account credentials JSON — may have broad project permissions.',
  },

  // ─── GitHub ───────────────────────────────────────────────────────────────
  {
    id: 'github-pat',
    name: 'GitHub Personal Token',
    category: 'SCM',
    severity: 'critical',
    regex: /ghp_[A-Za-z0-9]{36}/g,
    description: 'GitHub Personal Access Token (ghp_ prefix, new format).',
  },
  {
    id: 'github-oauth',
    name: 'GitHub OAuth Token',
    category: 'SCM',
    severity: 'critical',
    regex: /gho_[A-Za-z0-9]{36}/g,
    description: 'GitHub OAuth Access Token.',
  },
  {
    id: 'github-app',
    name: 'GitHub App Token',
    category: 'SCM',
    severity: 'high',
    regex: /ghs_[A-Za-z0-9]{36}/g,
    description: 'GitHub App installation access token.',
  },
  {
    id: 'github-classic',
    name: 'GitHub Classic Token',
    category: 'SCM',
    severity: 'high',
    regex: /(?:github[_\-\s](?:api[_\-\s])?(?:key|token|pat)|GITHUB_TOKEN)\s*[:=]\s*["'`]?([a-f0-9]{40})["'`]?/gi,
    description: 'GitHub classic personal access token (40-char hex).',
  },

  // ─── GitLab ───────────────────────────────────────────────────────────────
  {
    id: 'gitlab-pat',
    name: 'GitLab Personal Token',
    category: 'SCM',
    severity: 'critical',
    regex: /glpat-[A-Za-z0-9\-_]{20}/g,
    description: 'GitLab personal access token.',
  },
  {
    id: 'gitlab-runner',
    name: 'GitLab Runner Token',
    category: 'SCM',
    severity: 'high',
    regex: /glrt-[A-Za-z0-9\-_]{20}/g,
    description: 'GitLab CI runner registration token.',
  },

  // ─── Slack ────────────────────────────────────────────────────────────────
  {
    id: 'slack-bot',
    name: 'Slack Bot Token',
    category: 'Communication',
    severity: 'high',
    regex: /xoxb-[0-9A-Za-z\-]{50,}/g,
    description: 'Slack bot OAuth token — can read/post messages.',
  },
  {
    id: 'slack-user',
    name: 'Slack User Token',
    category: 'Communication',
    severity: 'high',
    regex: /xoxp-[0-9A-Za-z\-]{70,}/g,
    description: 'Slack user OAuth token — acts on behalf of a user.',
  },
  {
    id: 'slack-app',
    name: 'Slack App-Level Token',
    category: 'Communication',
    severity: 'medium',
    regex: /xapp-[0-9A-Za-z\-]{80,}/g,
    description: 'Slack app-level token.',
  },
  {
    id: 'slack-webhook',
    name: 'Slack Incoming Webhook',
    category: 'Communication',
    severity: 'medium',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[A-Za-z0-9]+/g,
    description: 'Slack incoming webhook URL — can post messages to a channel.',
  },

  // ─── Twilio ───────────────────────────────────────────────────────────────
  {
    id: 'twilio-sid',
    name: 'Twilio Account SID',
    category: 'Communication',
    severity: 'medium',
    regex: /\bAC[a-f0-9]{32}\b/g,
    description: 'Twilio account identifier (AC prefix).',
  },
  {
    id: 'twilio-token',
    name: 'Twilio Auth Token',
    category: 'Communication',
    severity: 'high',
    regex: /twilio[_\-\s]*(?:auth[_\-\s]*)?token\s*[:=]\s*["'`]?([a-f0-9]{32})["'`]?/gi,
    description: 'Twilio authentication token — enables SMS/voice charges.',
  },

  // ─── Email ────────────────────────────────────────────────────────────────
  {
    id: 'sendgrid',
    name: 'SendGrid API Key',
    category: 'Email',
    severity: 'high',
    regex: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
    description: 'SendGrid API key — can send email and access delivery data.',
  },
  {
    id: 'mailgun',
    name: 'Mailgun API Key',
    category: 'Email',
    severity: 'high',
    regex: /key-[0-9a-f]{32}/g,
    description: 'Mailgun API key — can send email and access logs.',
  },

  // ─── Firebase ─────────────────────────────────────────────────────────────
  {
    id: 'firebase-server',
    name: 'Firebase Server Key',
    category: 'Google',
    severity: 'critical',
    regex: /AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}/g,
    description: 'Firebase Cloud Messaging server key — can push to all app users.',
  },

  // ─── Azure ────────────────────────────────────────────────────────────────
  {
    id: 'azure-storage',
    name: 'Azure Storage Key',
    category: 'Cloud',
    severity: 'critical',
    regex: /AccountKey=[A-Za-z0-9+/=]{88}/g,
    description: 'Azure Storage Account access key — full read/write to blobs, tables, queues.',
  },
  {
    id: 'azure-client-secret',
    name: 'Azure Client Secret',
    category: 'Cloud',
    severity: 'critical',
    regex: /(?:AZURE_CLIENT_SECRET|azure[_\-\s]*client[_\-\s]*secret)\s*[:=]\s*["'`]?([A-Za-z0-9~._\-]{34,40})["'`]?/gi,
    description: 'Azure AD application client secret.',
  },

  // ─── Heroku ───────────────────────────────────────────────────────────────
  {
    id: 'heroku',
    name: 'Heroku API Key',
    category: 'Cloud',
    severity: 'high',
    regex: /(?:heroku[_\-\s]*(?:api[_\-\s]*)?(?:key|token))\s*[:=]\s*["'`]?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["'`]?/gi,
    description: 'Heroku API key (UUID format) — manage apps and deployments.',
  },

  // ─── Shopify ──────────────────────────────────────────────────────────────
  {
    id: 'shopify-token',
    name: 'Shopify Access Token',
    category: 'E-Commerce',
    severity: 'high',
    regex: /shpat_[A-Za-z0-9]{32}/g,
    description: 'Shopify private app access token.',
  },
  {
    id: 'shopify-secret',
    name: 'Shopify Shared Secret',
    category: 'E-Commerce',
    severity: 'high',
    regex: /shpss_[A-Za-z0-9]{32}/g,
    description: 'Shopify shared secret for app validation.',
  },

  // ─── Discord ──────────────────────────────────────────────────────────────
  {
    id: 'discord-token',
    name: 'Discord Bot Token',
    category: 'Communication',
    severity: 'high',
    regex: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g,
    description: 'Discord bot or application token.',
  },
  {
    id: 'discord-webhook',
    name: 'Discord Webhook URL',
    category: 'Communication',
    severity: 'medium',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9\-_]+/g,
    description: 'Discord webhook URL — can post messages to a channel.',
  },

  // ─── Dev Tools ────────────────────────────────────────────────────────────
  {
    id: 'npm-token',
    name: 'NPM Access Token',
    category: 'Dev',
    severity: 'high',
    regex: /npm_[A-Za-z0-9]{36}/g,
    description: 'NPM publish or read-only access token.',
  },
  {
    id: 'terraform-token',
    name: 'Terraform Cloud Token',
    category: 'Dev',
    severity: 'high',
    regex: /[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,}/g,
    description: 'Terraform Cloud API token.',
  },

  // ─── Observability ────────────────────────────────────────────────────────
  {
    id: 'datadog',
    name: 'Datadog API Key',
    category: 'Observability',
    severity: 'high',
    regex: /(?:datadog|dd)[_\-\s]*(?:api[_\-\s]*)?key\s*[:=]\s*["'`]?([a-f0-9]{32})["'`]?/gi,
    description: 'Datadog API or application key.',
  },

  // ─── Secrets Management ───────────────────────────────────────────────────
  {
    id: 'vault-token',
    name: 'HashiCorp Vault Token',
    category: 'Secrets',
    severity: 'critical',
    regex: /\bhvs\.[A-Za-z0-9]{24}/g,
    description: 'HashiCorp Vault service token.',
  },

  // ─── Auth / JWT ───────────────────────────────────────────────────────────
  {
    id: 'jwt',
    name: 'JSON Web Token',
    category: 'Auth',
    severity: 'medium',
    regex: /eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]+/g,
    description: 'JSON Web Token — may grant session or API access.',
  },
  {
    id: 'jwt-refresh',
    name: 'JWT Refresh Token',
    category: 'Auth',
    severity: 'medium',
    regex: /refresh_token\s*[:=]\s*["'`]?([A-Za-z0-9_\-]{20,})["'`]?/gi,
    description: 'OAuth refresh token — can mint new access tokens.',
  },
  {
    id: 'bearer',
    name: 'Bearer Token',
    category: 'Auth',
    severity: 'medium',
    regex: /[Bb]earer\s+([A-Za-z0-9\-_.~+/]{20,}=*)/g,
    description: 'HTTP Authorization Bearer token — direct API credential.',
  },

  // ─── Private Keys / Certificates ──────────────────────────────────────────
  {
    id: 'rsa-private',
    name: 'RSA Private Key',
    category: 'Crypto',
    severity: 'critical',
    regex: /-----BEGIN RSA PRIVATE KEY-----/g,
    description: 'PEM-encoded RSA private key.',
  },
  {
    id: 'ec-private',
    name: 'EC Private Key',
    category: 'Crypto',
    severity: 'critical',
    regex: /-----BEGIN EC PRIVATE KEY-----/g,
    description: 'PEM-encoded elliptic curve private key.',
  },
  {
    id: 'generic-private',
    name: 'Generic Private Key',
    category: 'Crypto',
    severity: 'critical',
    regex: /-----BEGIN (?:OPENSSH |DSA )?PRIVATE KEY-----/g,
    description: 'PEM-encoded private key block.',
  },
  {
    id: 'pgp-private',
    name: 'PGP Private Key',
    category: 'Crypto',
    severity: 'critical',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    description: 'PGP/GPG private key block.',
  },

  // ─── Database DSNs ────────────────────────────────────────────────────────
  {
    id: 'postgres-dsn',
    name: 'PostgreSQL Connection String',
    category: 'Database',
    severity: 'critical',
    regex: /postgres(?:ql)?:\/\/[^:]+:[^@\s]+@[^/\s]+\/\S+/gi,
    description: 'PostgreSQL DSN with embedded credentials.',
  },
  {
    id: 'mysql-dsn',
    name: 'MySQL Connection String',
    category: 'Database',
    severity: 'critical',
    regex: /mysql:\/\/[^:]+:[^@\s]+@[^/\s]+\/\S+/gi,
    description: 'MySQL DSN with embedded credentials.',
  },
  {
    id: 'mongodb-dsn',
    name: 'MongoDB Connection String',
    category: 'Database',
    severity: 'critical',
    regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@\s]+@[^/\s]+\/\S*/gi,
    description: 'MongoDB DSN with embedded credentials.',
  },
  {
    id: 'redis-dsn',
    name: 'Redis Connection String',
    category: 'Database',
    severity: 'high',
    regex: /rediss?:\/\/[^:]*:[^@\s]+@[^/\s]+/gi,
    description: 'Redis DSN with embedded password.',
  },

  // ─── Generic Patterns ─────────────────────────────────────────────────────
  {
    id: 'generic-api-key',
    name: 'Generic API Key',
    category: 'Generic',
    severity: 'low',
    regex: /(?:api[_\-]?key|apikey)\s*[:=]\s*["'`]?([A-Za-z0-9\-_]{16,64})["'`]?/gi,
    description: 'Generic API key assignment.',
  },
  {
    id: 'generic-secret',
    name: 'Generic Client Secret',
    category: 'Generic',
    severity: 'low',
    regex: /(?:client[_\-]?secret|app[_\-]?secret)\s*[:=]\s*["'`]([A-Za-z0-9\-_/+]{16,})["'`]/gi,
    description: 'Generic application secret assignment.',
  },
  {
    id: 'password-hardcoded',
    name: 'Hardcoded Password',
    category: 'Generic',
    severity: 'medium',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*["'`]([^\s"'`]{8,})["'`]/gi,
    description: 'Potential hardcoded password literal in code.',
  },
  {
    id: 'suspicious-token',
    name: 'Suspicious Token Assignment',
    category: 'Generic',
    severity: 'low',
    regex: /(?:access[_\-]?token|auth[_\-]?token|private[_\-]?key)\s*[:=]\s*["'`]([A-Za-z0-9\-_/+=]{24,})["'`]/gi,
    description: 'Suspicious token or key assignment in code.',
  },
];
