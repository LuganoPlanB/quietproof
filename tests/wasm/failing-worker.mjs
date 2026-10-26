// Test-only browser host failures; production worker messages cannot select these.
const failure = new URL(self.location).searchParams.get('failure');
// Top-level dynamic import can yield before the production handler is installed.
const queued = [];
self.onmessage = event => queued.push(event);
if (failure === 'missing-entropy') {
  Object.defineProperty(globalThis, 'crypto', { value: undefined });
} else if (failure === 'entropy') {
  Object.defineProperty(globalThis, 'crypto', {
    value: { getRandomValues() { throw new Error('Entropy fixture failure'); } },
  });
} else if (failure === 'clock') {
  Date.now = () => { throw new Error('Clock fixture failure'); };
}
await import('../../web/wasm/worker.mjs');
for (const event of queued) self.onmessage(event);
