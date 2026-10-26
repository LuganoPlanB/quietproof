import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const root = fileURLToPath(new URL('../../', import.meta.url));
const artifact = process.env.QUIETPROOF_WASM;
let server, browser, page, origin;
before(async () => {
  assert(artifact, 'Set QUIETPROOF_WASM to the built reactor path.');
  const wasm = await readFile(resolve(artifact));
  server = createServer(async (request, response) => {
    try {
      const path = new URL(request.url, 'http://localhost').pathname;
      if (path === '/') {
        response.setHeader('Content-Type', 'text/html');
        response.end('<!doctype html><title>Quietproof worker qualification</title>');
        return;
      }
      if (path === '/quietproof.wasm') {
        response.setHeader('Content-Type', 'application/wasm');
        response.end(wasm);
        return;
      }
      const local = resolve(root, '.' + path);
      if (!local.startsWith(root) || !['.mjs'].includes(extname(local))) {
        response.writeHead(404).end(); return;
      }
      response.setHeader('Content-Type', 'text/javascript');
      response.end(await readFile(local));
    } catch { response.writeHead(404).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true });
  console.log(`Browser: ${browser.version()}; Playwright 1.61.1`);
  page = await browser.newPage();
  await page.goto(origin);
});
after(async () => {
  await browser?.close();
  if (server) await new Promise(resolve => server.close(resolve));
});

async function inBrowser(fn, argument) {
  const result = await page.evaluate(fn, argument);
  assert.equal(result, true);
}

test('real worker executes SDK hash with transferred entropy/time result', async () => {
  await inBrowser(async () => {
    const worker = new Worker('/web/wasm/worker.mjs', { type: 'module' });
    let id = 0;
    const call = (type, bytes) => new Promise((resolve, reject) => {
      worker.onmessage = event => resolve(event.data);
      worker.onerror = event => reject(new Error(event.message));
      worker.postMessage({ id: ++id, type, bytes }, bytes ? [bytes] : []);
    });
    try {
      const bytes = await (await fetch('/quietproof.wasm')).arrayBuffer();
      const initialized = call('initialize', bytes);
      if (bytes.byteLength !== 0) throw new Error('Input was not transferred');
      if ((await initialized).type !== 'ready') throw new Error('Not ready');
      const first = await call('smoke');
      const second = await call('smoke');
      for (const response of [first, second]) {
        if (response.type !== 'result' || response.bytes.byteLength !== 72)
          throw new Error('Invalid result');
        const data = new Uint8Array(response.bytes);
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data.slice(0, 40)));
        if (!digest.every((b, i) => b === data[40 + i])) throw new Error('SDK hash mismatch');
        const time = Number(new DataView(response.bytes).getBigUint64(32, true) / 1000000n);
        if (Math.abs(time - Date.now()) > 10000) throw new Error('Clock mismatch');
      }
      if (new Uint8Array(first.bytes).slice(0, 32).every((b, i) =>
        b === new Uint8Array(second.bytes)[i])) throw new Error('Entropy repeated');
      const duplicate = await call('initialize', await (await fetch('/quietproof.wasm')).arrayBuffer());
      if (duplicate.type !== 'error' || !duplicate.message.includes('already initialized'))
        throw new Error('Duplicate initialization accepted');
      return true;
    } finally { worker.terminate(); }
  });
});

for (const [failure, expected] of [['missing-entropy', 'randomness'],
  ['entropy', 'status 2'], ['clock', 'status 3']]) {
  test(`worker fails closed on ${failure}`, async () => {
    await inBrowser(async ({ failure, expected }) => {
      const worker = new Worker(`/tests/wasm/failing-worker.mjs?failure=${failure}`, { type: 'module' });
      const call = (type, bytes) => new Promise((resolve, reject) => {
        worker.onmessage = event => resolve(event.data);
        worker.onerror = event => reject(new Error(event.message));
        worker.postMessage({ id: 1, type, bytes }, bytes ? [bytes] : []);
      });
      try {
        let response = await call('initialize', await (await fetch('/quietproof.wasm')).arrayBuffer());
        if (response.type === 'ready') response = await call('smoke');
        if (response.type !== 'error' || !response.message.includes(expected))
          throw new Error(JSON.stringify(response));
        return true;
      } finally { worker.terminate(); }
    }, { failure, expected });
  });
}

test('missing imports, unexpected imports and unsupported SIMD are rejected', async () => {
  await inBrowser(async () => {
    const { instantiateReactor, requireCapabilities } = await import('/web/wasm/runtime.mjs');
    const bytes = await (await fetch('/quietproof.wasm')).arrayBuffer();
    const module = await WebAssembly.compile(bytes);
    let rejected = false;
    try { await WebAssembly.instantiate(module, { wasi_snapshot_preview1: { clock_time_get() {} } }); }
    catch (error) { rejected = error instanceof WebAssembly.LinkError; }
    if (!rejected) throw new Error('Missing import accepted');
    const mutated = new Uint8Array(bytes.slice(0));
    const needle = new TextEncoder().encode('random_get');
    const index = mutated.findIndex((_, i) => needle.every((byte, j) => mutated[i + j] === byte));
    if (index < 0) throw new Error('Missing fixture import');
    mutated[index] = 'x'.charCodeAt(0);
    rejected = false;
    try { await instantiateReactor(mutated); }
    catch (error) { rejected = error.name === 'CapabilityError' && error.message.includes('imports'); }
    if (!rejected) throw new Error('Unexpected import accepted');
    rejected = false;
    try { await instantiateReactor(new Uint8Array([0, 1, 2, 3])); }
    catch (error) { rejected = error.name === 'CapabilityError' && error.message.includes('invalid'); }
    if (!rejected) throw new Error('Invalid artifact accepted');
    rejected = false;
    try { requireCapabilities({ WebAssembly: { validate: () => false }, crypto }); }
    catch (error) { rejected = error.name === 'CapabilityError' && error.message.includes('SIMD'); }
    if (!rejected) throw new Error('Unsupported SIMD accepted');
    return true;
  });
});

test('adapter bounds, quota chunking and partial entropy failure clearing', async () => {
  await inBrowser(async () => {
    const { createWasiImports } = await import('/web/wasm/runtime.mjs');
    const memory = new WebAssembly.Memory({ initial: 2, maximum: 3 });
    let calls = 0;
    const host = { crypto: { getRandomValues(bytes) {
      if (bytes.length > 65536) throw new Error('quota exceeded');
      calls++; bytes.fill(1); if (calls === 2) throw new Error('partial failure');
    } }, Date: { now: () => Number.NaN } };
    const imports = createWasiImports(() => memory, host);
    if (imports.random_get(0, 100000) !== 29 || calls !== 2)
      throw new Error('Entropy failure not propagated');
    if (new Uint8Array(memory.buffer, 0, 100000).some(Boolean))
      throw new Error('Partial entropy retained');
    if (imports.random_get(-1, 8) !== 21 || imports.clock_time_get(0, 0n, -1) !== 21)
      throw new Error('Bounds ignored');
    if (imports.clock_time_get(1, 0n, 0) !== 28 || imports.clock_time_get(0, 0n, 0) !== 29)
      throw new Error('Clock failure ignored');
    memory.grow(1);
    host.crypto = crypto;
    if (imports.random_get(131072, 8) !== 0) throw new Error('Stale memory view');
    return true;
  });
});

test('reactor clears caller output on failed entropy or clock imports', async () => {
  await inBrowser(async () => {
    const bytes = await (await fetch('/quietproof.wasm')).arrayBuffer();
    const module = await WebAssembly.compile(bytes);
    for (const status of [2, 3]) {
      let memory;
      const instance = await WebAssembly.instantiate(module, {
        wasi_snapshot_preview1: {
          random_get(pointer, size) {
            new Uint8Array(memory.buffer, pointer, size).fill(7);
            return status === 2 ? 29 : 0;
          },
          clock_time_get() { return 29; },
        },
      });
      memory = instance.exports.memory;
      instance.exports._initialize();
      const pointer = instance.exports.quietproof_wasm_alloc(72);
      try {
        new Uint8Array(memory.buffer, pointer, 72).fill(255);
        if (instance.exports.quietproof_wasm_smoke(pointer, 72) !== status ||
            new Uint8Array(memory.buffer, pointer, 72).some(Boolean))
          throw new Error('Host failure exposed stale output');
      } finally { instance.exports.quietproof_wasm_free(pointer); }
    }
    return true;
  });
});

test('repeated instances, allocation/free, copied results and memory growth', async () => {
  await inBrowser(async () => {
    const { instantiateReactor } = await import('/web/wasm/runtime.mjs');
    const bytes = await (await fetch('/quietproof.wasm')).arrayBuffer();
    for (let instance = 0; instance < 2; instance++) {
      const reactor = await instantiateReactor(bytes);
      const api = reactor.exports;
      if (api.quietproof_wasm_alloc(0) || api.quietproof_wasm_alloc(16777217))
        throw new Error('Allocation bound ignored');
      const pointer = api.quietproof_wasm_alloc(72);
      if (!pointer || api.quietproof_wasm_smoke(pointer, 71) !== 1)
        throw new Error('Invalid smoke length accepted');
      api.quietproof_wasm_free(pointer);
      const first = reactor.smoke();
      const snapshot = new Uint8Array(first).slice();
      const initialMemory = api.memory.buffer.byteLength;
      for (let i = 0; i < 100; i++) reactor.smoke();
      if (api.memory.buffer.byteLength !== initialMemory)
        throw new Error('Memory grows across repeated allocated results');
      const old = api.memory.buffer;
      api.memory.grow(1);
      if (old.byteLength !== 0 || reactor.smoke().byteLength !== 72)
        throw new Error('Memory growth handling failed');
      if (!snapshot.every((b, i) => b === new Uint8Array(first)[i]))
        throw new Error('Result aliases freed memory');
    }
    return true;
  });
});

test('termination prevents delivery and a fresh worker initializes independently', async () => {
  await inBrowser(async () => {
    const worker = new Worker('/web/wasm/worker.mjs', { type: 'module' });
    let delivered = false;
    worker.onmessage = () => { delivered = true; };
    const bytes = await (await fetch('/quietproof.wasm')).arrayBuffer();
    worker.postMessage({ id: 1, type: 'initialize', bytes }, [bytes]);
    worker.terminate();
    await new Promise(resolve => setTimeout(resolve, 100));
    if (delivered) throw new Error('Terminated worker delivered a result');
    const fresh = new Worker('/web/wasm/worker.mjs', { type: 'module' });
    try {
      const response = new Promise((resolve, reject) => {
        fresh.onmessage = event => resolve(event.data);
        fresh.onerror = event => reject(new Error(event.message));
      });
      const newBytes = await (await fetch('/quietproof.wasm')).arrayBuffer();
      fresh.postMessage({ id: 2, type: 'initialize', bytes: newBytes }, [newBytes]);
      if ((await response).type !== 'ready') throw new Error('Recreated worker failed');
      return true;
    } finally { fresh.terminate(); }
  });
});
