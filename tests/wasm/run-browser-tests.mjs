// Run the same shipping reactor contracts in both required engines, serially.
import { spawnSync } from 'node:child_process';
for (const engine of ['chromium', 'webkit']) {
  const result = spawnSync(process.execPath, ['--test', '--test-concurrency=1',
    '--test-timeout=60000', 'tests/wasm/browser.test.mjs'], {
    stdio: 'inherit', env: { ...process.env, QUIETPROOF_WASM_ENGINE: engine },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
