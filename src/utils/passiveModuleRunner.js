const SEVERITY_RANK = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function passesThreshold(finding, threshold) {
  const thresholdRank = SEVERITY_RANK[threshold] ?? 0;
  const findingRank = SEVERITY_RANK[finding?.severity] ?? 0;
  return findingRank >= thresholdRank;
}

export function runPassiveModules(modules, options, context) {
  return modules.map((module) => {
    const enabled = options[module.optionKey] !== false;
    if (!enabled) {
      return { module, findings: [], skippedReason: 'disabled', threshold: null, filteredOutCount: 0 };
    }

    if (module.experimental && !options.enableExperimentalModules) {
      return { module, findings: [], skippedReason: 'experimental-disabled', threshold: null, filteredOutCount: 0 };
    }

    const threshold = options.passiveSeverityThresholds?.[module.id] || 'low';

    try {
      const rawFindings = module.run(context) || [];
      const findings = rawFindings.filter((finding) => passesThreshold(finding, threshold));
      const filteredOutCount = Math.max(0, rawFindings.length - findings.length);
      return {
        module,
        findings,
        threshold,
        filteredOutCount,
        skippedReason: findings.length === 0 && filteredOutCount > 0 ? 'threshold-filtered' : null,
      };
    } catch (error) {
      return {
        module,
        findings: [],
        threshold,
        filteredOutCount: 0,
        skippedReason: 'error',
        error,
      };
    }
  });
}
