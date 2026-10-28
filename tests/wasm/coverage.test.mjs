import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { REQUIRED_ENGINES, REQUIRED_KEYS, parseSelection, assessCoverage } from './coverage.mjs';

// Synthetic reports exercise accounting, not proof verification or callbacks.
const engine = name => ({ name, status: 'passed', checks: REQUIRED_KEYS.map(key => ({ key, status: 'passed' })) });
const complete = () => ({ completeness: 'complete', engines: REQUIRED_ENGINES.map(engine) });

test('default selection is exactly Chromium and WebKit', () => {
  assert.deepEqual(parseSelection(undefined, REQUIRED_ENGINES, [...REQUIRED_ENGINES, 'firefox'], 'engine'), ['chromium', 'webkit']);
  assert.equal(assessCoverage(complete()).passed, true);
});
for (const selection of ['', 'chromium,', 'chromium,chromium', 'firefox,firefox', 'unknown', 'chromium,webkit,webkit']) {
  test(`reject malformed/duplicate engine selection ${JSON.stringify(selection)}`, () => {
    assert.throws(() => parseSelection(selection, REQUIRED_ENGINES, [...REQUIRED_ENGINES, 'firefox'], 'engine'));
  });
}
for (const selection of ['', 'one-key,one-key', 'two-key,two-key', 'unknown']) {
  test(`reject malformed/duplicate key selection ${JSON.stringify(selection)}`, () => {
    assert.throws(() => parseSelection(selection, REQUIRED_KEYS, REQUIRED_KEYS, 'key'));
  });
}
for (const missing of ['chromium', 'webkit']) {
  test(`missing required ${missing} cannot be replaced by Firefox`, () => {
    const report = complete(); report.engines = report.engines.filter(e => e.name !== missing); report.engines.push(engine('firefox'));
    assert.equal(assessCoverage(report).passed, false);
  });
}
for (const status of ['failed', 'unavailable', 'running']) {
  test(`required ${status} engine fails coverage`, () => {
    const report = complete(); report.engines[0].status = status;
    assert.equal(assessCoverage(report).passed, false);
  });
}
test('duplicate engines cannot satisfy missing coverage', () => {
  const report = complete(); report.engines = [engine('chromium'), engine('chromium')];
  assert.equal(assessCoverage(report).passed, false);
});
test('key subsets and duplicate keys fail required coverage', () => {
  for (const keys of [['two-key'], ['one-key', 'one-key'], []]) {
    const report = complete(); report.engines[1].checks = keys.map(key => ({ key, status: 'passed' }));
    assert.equal(assessCoverage(report).passed, false);
  }
});
test('failed key family and incomplete capture fail coverage', () => {
  const report = complete(); report.engines[0].checks[0].status = 'failed';
  assert.equal(assessCoverage(report).passed, false);
  assert.equal(assessCoverage({ ...complete(), completeness: 'running' }).passed, false);
});
test('optional Firefox remains unsupported and cannot alter required-engine success', () => {
  for (const status of ['passed', 'failed', 'unavailable']) {
    const report = complete(); report.engines.push({ ...engine('firefox'), status });
    const result = assessCoverage(report);
    assert.equal(result.passed, true); assert.deepEqual(result.unsupportedBrowsers, ['firefox']);
  }
  assert.equal(assessCoverage({ completeness: 'complete', engines: [engine('firefox')] }).passed, false);
});
test('CLI rejects duplicate selectors before reading artifacts', () => {
  const result = spawnSync(process.execPath, ['tests/wasm/feasibility.mjs'], {
    cwd: new URL('../../', import.meta.url), encoding: 'utf8',
    env: { ...process.env, QUIETPROOF_FEASIBILITY_REPORT: '/tmp/not-created-coverage.json', QUIETPROOF_ENGINES: 'chromium,chromium' },
  });
  assert.notEqual(result.status, 0); assert.match(result.stderr, /Duplicate engine selection/);
});
