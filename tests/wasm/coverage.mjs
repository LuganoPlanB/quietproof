// Coverage accounting only; cryptographic verification remains in the worker.
export const REQUIRED_ENGINES = Object.freeze(['chromium', 'webkit']);
export const REQUIRED_KEYS = Object.freeze(['one-key']);
export const DIAGNOSTIC_ENGINES = Object.freeze(['firefox']);

export function parseSelection(value, defaults, allowed, label) {
  const names = value === undefined ? [...defaults] : value.split(',');
  if (!names.length || names.some(name => !allowed.includes(name)))
    throw new Error(`Unsupported or empty ${label} selection.`);
  if (new Set(names).size !== names.length) throw new Error(`Duplicate ${label} selection.`);
  return names;
}

export function assessCoverage(report) {
  const failures = [];
  if (report.completeness !== 'complete') failures.push('Report capture is incomplete.');
  const engines = Array.isArray(report.engines) ? report.engines : [];
  const names = engines.map(engine => engine.name);
  if (new Set(names).size !== names.length) failures.push('Duplicate engine result.');
  if (names.some(name => ![...REQUIRED_ENGINES, ...DIAGNOSTIC_ENGINES].includes(name)))
    failures.push('Unknown engine result.');
  for (const name of REQUIRED_ENGINES) {
    const matches = engines.filter(engine => engine.name === name);
    if (matches.length !== 1) { failures.push(`Required ${name} result is missing or duplicated.`); continue; }
    const engine = matches[0];
    if (engine.status !== 'passed') failures.push(`Required ${name} did not pass.`);
    const checks = Array.isArray(engine.checks) ? engine.checks : [];
    const keys = checks.map(check => check.key);
    if (checks.length !== REQUIRED_KEYS.length || new Set(keys).size !== keys.length ||
        REQUIRED_KEYS.some(key => !keys.includes(key)) || checks.some(check => check.status !== 'passed'))
      failures.push(`Required ${name} single-key coverage is incomplete, duplicated or failed.`);
  }
  return { passed: failures.length === 0, requiredEngines: [...REQUIRED_ENGINES],
    requiredKeys: [...REQUIRED_KEYS], unsupportedBrowsers: ['firefox'], failures };
}
