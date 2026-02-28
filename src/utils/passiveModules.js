import { analyzeSecurityHeaders } from './headerAnalyzer.js';
import { analyzeWebRisks } from './webRiskAnalyzer.js';

export const PASSIVE_SEVERITY_LEVELS = ['low', 'medium', 'high', 'critical'];

function normalizeThresholds(nextThresholds = {}, defaultThresholds = {}) {
  const normalized = { ...defaultThresholds };

  for (const module of PASSIVE_MODULES) {
    const candidate = nextThresholds[module.id];
    normalized[module.id] = PASSIVE_SEVERITY_LEVELS.includes(candidate)
      ? candidate
      : (defaultThresholds[module.id] || 'low');
  }

  return normalized;
}

export const PASSIVE_MODULES = [
  {
    id: 'security-headers',
    optionKey: 'checkHeaders',
    label: 'Security headers',
    defaultEnabled: true,
    experimental: false,
    run: ({ headers, url }) => analyzeSecurityHeaders(headers, url),
  },
  {
    id: 'web-risks',
    optionKey: 'checkWebRisks',
    label: 'Web risks',
    defaultEnabled: true,
    experimental: false,
    run: ({ content, headers, url }) => analyzeWebRisks({ content, headers, url }),
  },
];

export function passiveModuleDefaults() {
  const defaults = {
    enableExperimentalModules: false,
    passiveSeverityThresholds: {},
  };

  for (const module of PASSIVE_MODULES) {
    defaults[module.optionKey] = module.defaultEnabled;
    defaults.passiveSeverityThresholds[module.id] = 'low';
  }

  return defaults;
}

export function normalizePassiveOptions(options = {}) {
  const defaults = passiveModuleDefaults();
  const merged = {
    ...defaults,
    ...options,
  };

  merged.enableExperimentalModules = Boolean(merged.enableExperimentalModules);

  for (const module of PASSIVE_MODULES) {
    if (typeof merged[module.optionKey] !== 'boolean') {
      merged[module.optionKey] = defaults[module.optionKey];
    }
  }

  merged.passiveSeverityThresholds = normalizeThresholds(
    options.passiveSeverityThresholds,
    defaults.passiveSeverityThresholds
  );

  return merged;
}
