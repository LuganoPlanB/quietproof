import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, webkit } from 'playwright';

const root = fileURLToPath(new URL('../../../', import.meta.url));
let server, origin;
before(async () => {
  assert(process.env.QUIETPROOF_WASM && process.env.QUIETPROOF_WASM_FIXTURES,
    'Provide the real reactor and current public native fixtures.');
  server = createServer(async (request, response) => {
    try {
      const path = new URL(request.url, 'http://localhost').pathname;
      if (path === '/') { response.setHeader('Content-Type', 'text/html'); response.end('<!doctype html><title>Provider verification</title>'); return; }
      if (path === '/quietproof.wasm') {
        response.setHeader('Content-Type', 'application/wasm');
        response.end(await readFile(resolve(process.env.QUIETPROOF_WASM))); return;
      }
      if (/^\/one-key\.(qpf|qpr)$/.test(path)) {
        response.end(await readFile(resolve(process.env.QUIETPROOF_WASM_FIXTURES, path.slice(1)))); return;
      }
      const local = resolve(root, '.' + path);
      if (!local.startsWith(root) || !local.endsWith('.mjs')) { response.writeHead(404).end(); return; }
      response.setHeader('Content-Type', 'text/javascript'); response.end(await readFile(local));
    } catch { response.writeHead(404).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { if (server) await new Promise(resolve => server.close(resolve)); });

for (const [engine, type] of [['chromium', chromium], ['webkit', webkit]]) {
  test(`${engine}: real provider flow verifies and assesses exact fresh observations`, { timeout: 300000 }, async () => {
    const browser = await type.launch({ headless: true,
      ...(engine === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
    console.log(`${engine}: ${browser.version()}`);
    try {
      const page = await browser.newPage(); await page.goto(origin);
      const result = await page.evaluate(async () => {
        const { setupProvider } = await import('/web/features/provider/discovery.mjs');
        const { decodeInspection } = await import('/web/wasm/codec.mjs');
        const request = await (await fetch('/one-key.qpr')).arrayBuffer();
        const inspection = new Uint8Array(61 + request.byteLength);
        inspection.set(new TextEncoder().encode('QWI1')); inspection.set(new Uint8Array(request), 61);
        const manifest = decodeInspection(inspection.buffer), claim = manifest.claims[0];
        const funding = '34'.repeat(32), tip = '56'.repeat(32), requests = [];
        const status = { confirmed: true, block_height: 100, block_hash: funding, block_time: 1600000000 };
        const vout = Array.from({ length: claim.vout + 1 }, () => ({ value: 1, scriptpubkey: '51' }));
        vout[claim.vout] = { value: Number(claim.amountSats), scriptpubkey: '0014' + claim.program };
        const adapter = setupProvider({ network: 'mainnet', fetch: async (url, options) => {
          requests.push({ url, body: options.body ?? null, method: options.method });
          if (url.endsWith('/block-height/0')) return new Response('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
          if (url.endsWith('/blocks/tip/hash')) return new Response(tip);
          if (url.endsWith('/block-height/100')) return new Response(funding);
          let value;
          if (url.endsWith(`/tx/${claim.txid}`)) value = { txid: claim.txid, vout, status };
          else if (url.endsWith(`/tx/${claim.txid}/status`)) value = status;
          else if (url.includes('/outspend/')) value = { spent: false };
          else if (url.endsWith('/status')) value = { in_best_chain: true };
          else value = { id: tip, height: 110 };
          return new Response(JSON.stringify(value));
        } });
        const policy = { expectedRequest: request, provider: adapter.provider.endpoint,
          maxLifetimeSeconds: 3600, minConfirmations: 1, minimumTotalSats: claim.amountSats, maxObservationAgeSeconds: 60 };
        try {
          const result = await adapter.verify({ proof: await (await fetch('/one-key.qpf')).arrayBuffer(),
            wasmBytes: await (await fetch('/quietproof.wasm')).arrayBuffer(), policy });
          const validRequests = requests.length;
          const corrupted = await (await fetch('/one-key.qpf')).arrayBuffer();
          new Uint8Array(corrupted)[corrupted.byteLength - 1] ^= 1;
          const invalid = await adapter.verify({ proof: corrupted,
            wasmBytes: await (await fetch('/quietproof.wasm')).arrayBuffer(), policy, validated: true });
          return { cryptography: result.cryptography, policy: result.policy, explorer: result.explorer,
            authorizes: result.authorizes, totalSats: result.totalSats, atomic: result.provenance.atomic,
            fundingIsTip: result.provenance.attempts[0].tipBefore.block === funding,
            invalid: invalid.cryptography, invalidExplorer: invalid.explorer, validRequests,
            extraRequests: requests.length - validRequests, onlyGetWithoutBody: requests.every(r => r.method === 'GET' && r.body === null) };
        } finally { adapter.dispose(); }
      });
      assert.deepEqual(result, { cryptography: 'valid', policy: 'matched', explorer: 'reported_unspent',
        authorizes: false, totalSats: '50000', atomic: false, fundingIsTip: false,
        invalid: 'invalid', invalidExplorer: 'unavailable', validRequests: 10, extraRequests: 0, onlyGetWithoutBody: true });
    } finally { await browser.close(); }
  });
}
