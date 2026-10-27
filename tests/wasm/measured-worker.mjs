// Test-only entry notification immediately before the production handler enters
// synchronous verification. No cryptography, clocks, or entropy are replaced.
const queued = [];
self.onmessage = event => queued.push(event);
await import('../../web/wasm/worker.mjs');
const production = self.onmessage;
self.onmessage = event => {
  if (event.data?.type === 'verify') self.postMessage({ id: event.data.id, type: 'enteredVerification' });
  return production(event);
};
for (const event of queued) self.onmessage(event);
