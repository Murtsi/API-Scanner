export const SCAN_CONFIG = {
  MAX_ASSETS: 15,
  MAX_MATCHES_PER_RULE: 8,
  MAX_ENTROPY_MATCHES: 10,
  ENTROPY_THRESHOLD: 3.5,
  FETCH_TIMEOUT_MS: 12000,
  ASSET_CONCURRENCY: 4,
};

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

export const SEVERITY_LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export const EXPOSED_PATHS = [
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
  '.env.backup',
  '.git/config',
  '.git/HEAD',
  'config.json',
  'config.yml',
  'config.yaml',
  'secrets.json',
  'credentials.json',
  'docker-compose.yml',
  'docker-compose.yaml',
  'swagger.json',
  'swagger.yaml',
  'openapi.json',
  'api-docs/swagger.json',
  'robots.txt',
  'backup.zip',
  'backup.tar.gz',
  'dump.sql',
  'database.sql',
  'wp-config.php',
  'phpinfo.php',
  'server-status',
  'actuator/env',
  'actuator/info',
  'actuator/health',
  'actuator/beans',
  '.well-known/security.txt',
  'package.json',
];
