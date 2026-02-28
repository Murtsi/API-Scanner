function download(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Export results to a pretty-printed JSON file.
 * @param {Array} results
 */
export function exportJson(results) {
  const payload = {
    exported: new Date().toISOString(),
    tool: 'API-Scanner',
    version: '2.0.0',
    totalTargets: results.length,
    totalFindingTypes: results.reduce((n, r) => n + (r.findings?.length ?? 0), 0),
    results,
  };
  download(JSON.stringify(payload, null, 2), 'api-scan-results.json', 'application/json');
}

/**
 * Export results to a CSV file.
 * @param {Array} results
 */
export function exportCsv(results) {
  const rows = [['URL', 'Rule', 'Category', 'Severity', 'Match', 'Source']];
  for (const r of results) {
    for (const f of r.findings ?? []) {
      for (const match of f.matches ?? []) {
        const source = f.sources?.[0] ?? r.url;
        rows.push([r.url, f.name, f.category ?? '', f.severity ?? '', match, source]);
      }
    }
    for (const ef of r.exposedFiles ?? []) {
      rows.push([r.url, 'Exposed File', 'Exposure', 'high', ef.path, ef.url]);
    }
  }
  const csv = rows
    .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
    .join('\n');
  download(csv, 'api-scan-results.csv', 'text/csv');
}
