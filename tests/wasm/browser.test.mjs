import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const root = fileURLToPath(new URL('../../', import.meta.url));
const artifact = process.env.QUIETPROOF_WASM;
const realFixtures = process.env.QUIETPROOF_WASM_FIXTURES;
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
      if (realFixtures && /^\/real\/one-key\.(qpf|qpr|evidence)$/.test(path)) {
        response.end(await readFile(resolve(realFixtures, path.split('/').pop()))); return;
      }
      if (path === '/quietproof.wasm') {
        response.setHeader('Content-Type', 'application/wasm');
        response.end(wasm);
        return;
      }
      if (/^\/tests\/wasm\/fixtures\/[0-2]\.(options|qpr|qpf)$/.test(path)) {
        response.end(await readFile(resolve(root, '.' + path))); return;
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
  page.on('console', message => {
    const value = message.text();
    if (value.startsWith('qp-stage:')) console.log(value);
  });
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

test('an otherwise compatible reactor advertising a stale ABI version is rejected', async () => {
  await inBrowser(async () => {
    const { instantiateReactor } = await import('/web/wasm/runtime.mjs');
    const bytes = new Uint8Array(await (await fetch('/quietproof.wasm')).arrayBuffer());
    let cursor = 8, target = -1, imported = 0, patched = false;
    function uleb() { let n = 0, shift = 0, b; do { b = bytes[cursor++]; n += (b & 127) * 2 ** shift; shift += 7; } while (b & 128); return n; }
    while (cursor < bytes.length) {
      const section = bytes[cursor++], size = uleb(), end = cursor + size;
      if (section === 2) imported = uleb();
      if (section === 7) {
        const count = uleb();
        for (let i = 0; i < count; i++) {
          const length = uleb(), name = new TextDecoder().decode(bytes.subarray(cursor, cursor + length)); cursor += length;
          const kind = bytes[cursor++], index = uleb();
          if (name === 'quietproof_wasm_abi_version' && kind === 0) target = index;
        }
      }
      if (section === 10) {
        const count = uleb();
        for (let i = 0; i < count; i++) {
          const length = uleb(), bodyEnd = cursor + length;
          if (i === target - imported) {
            if (length !== 4 || bytes[cursor] !== 0 || bytes[cursor + 1] !== 65 || bytes[cursor + 2] !== 2 || bytes[cursor + 3] !== 11)
              throw new Error('Unexpected ABI fixture body');
            bytes[cursor + 2] = 1; patched = true;
          }
          cursor = bodyEnd;
        }
      }
      cursor = end;
    }
    if (!patched || !WebAssembly.validate(bytes)) throw new Error('Invalid stale ABI fixture');
    try { await instantiateReactor(bytes); }
    catch (error) { if (error.name === 'CapabilityError' && error.message.includes('ABI version')) return true; throw error; }
    throw new Error('Stale ABI was accepted');
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
    if (imports.clock_time_get(2, 0n, 0) !== 28 || imports.clock_time_get(0, 0n, 0) !== 29)
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
    const { createWasiImports } = await import('/web/wasm/runtime.mjs');
    for (const status of [2, 3]) {
      let memory;
      const instance = await WebAssembly.instantiate(module, {
        wasi_snapshot_preview1: {
          ...createWasiImports(() => memory),
          random_get(pointer, size) {
            new Uint8Array(memory.buffer, pointer, size).fill(7);
            return status === 2 ? 29 : 0;
          },
          clock_time_get(clock, precision, pointer) {
            return clock === 0 ? 29 : createWasiImports(() => memory).clock_time_get(clock, precision, pointer);
          },
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
      if (api.quietproof_wasm_alloc(0) || api.quietproof_wasm_alloc(134221898))
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

test('canonical v1/v2/mixed request bytes match native golden codecs exactly', async () => {
  await inBrowser(async () => {
    const { createWasiImports } = await import('/web/wasm/runtime.mjs');
    const { decodeInspection } = await import('/web/wasm/codec.mjs');
    const module = await WebAssembly.compile(await (await fetch('/quietproof.wasm')).arrayBuffer());
    let memory;
    let failure;
    const host = { performance, console, Date: { now: () => failure === 'clock' ? NaN : 1700000000000 },
      crypto: { getRandomValues(bytes) { if (failure === 'random') throw new Error('failed'); bytes.fill(7); } } };
    const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: createWasiImports(() => memory, host) });
    const api = instance.exports; memory = api.memory; api._initialize();
    const call = (name, buffer, ...args) => {
      const pointer = api.quietproof_wasm_alloc(buffer.byteLength);
      try {
        new Uint8Array(memory.buffer, pointer, buffer.byteLength).set(new Uint8Array(buffer));
        const status = api[name](pointer, buffer.byteLength, ...args);
        const start = api.quietproof_wasm_result_data();
        return { status, bytes: memory.buffer.slice(start, start + api.quietproof_wasm_result_size()) };
      } finally { api.quietproof_wasm_free(pointer); }
    };
    for (let mode = 0; mode < 3; mode++) {
      const load = async ext => (await fetch(`/tests/wasm/fixtures/${mode}.${ext}`)).arrayBuffer();
      const options = await load('options'), golden = new Uint8Array(await load('qpr'));
      const result = call('quietproof_wasm_create_request', options);
      if (result.status || !golden.every((b, i) => new Uint8Array(result.bytes)[i] === b) || result.bytes.byteLength !== golden.length)
        throw new Error(`Native golden mismatch ${mode}`);
      const inspection = call('quietproof_wasm_inspect', result.bytes, 0);
      const metadata = decodeInspection(inspection.bytes);
      if (inspection.status || metadata.statementVersion !== (mode ? 2 : 1) || metadata.claims.length !== 2 || metadata.claims[0].vout !== 4294967295)
        throw new Error('Incorrect canonical inspection');
      const proof = await load('qpf');
      const proofMetadata = decodeInspection(call('quietproof_wasm_inspect', proof, 1).bytes);
      if (proofMetadata.verified !== false || proofMetadata.proofBytes !== 3 || proofMetadata.proofCreatedAt !== '1700000001')
        throw new Error('Metadata inspection claims verification');
      const malformed = new Uint8Array(proof.byteLength + 1); malformed.set(new Uint8Array(proof));
      if (!call('quietproof_wasm_inspect', malformed.buffer, 1).status || api.quietproof_wasm_result_size())
        throw new Error('Trailing proof or stale result accepted');
      for (failure of ['random', 'clock']) {
        if (call('quietproof_wasm_create_request', options).status !== (failure === 'random' ? 2 : 3) || api.quietproof_wasm_result_size())
          throw new Error('Request entropy/clock failure did not clear result');
      }
      failure = undefined;
      for (const offset of [0, 15, options.byteLength - 21]) {
        const invalid = new Uint8Array(options.slice(0)); invalid[offset] = 255;
        if (!call('quietproof_wasm_create_request', invalid.buffer).status) throw new Error('Malformed options accepted');
      }
      const snapshot = new Uint8Array(result.bytes).slice();
      call('quietproof_wasm_create_request', options);
      if (!snapshot.every((b, i) => b === new Uint8Array(result.bytes)[i])) throw new Error('Copied result lifetime failed');
    }
    const pointer = api.quietproof_wasm_alloc(16);
    api.quietproof_wasm_free(pointer); api.quietproof_wasm_free(pointer);
    if (!api.quietproof_wasm_create_request(pointer, 16) || !api.quietproof_wasm_inspect(-1, 4096, 0) ||
        !api.quietproof_wasm_inspect(0, 0, 0)) throw new Error('Foreign/freed input accepted');
    return true;
  });
});

test('worker creates and inspects fresh canonical requests using real browser entropy', async () => {
  await inBrowser(async () => {
    const worker = new Worker('/web/wasm/worker.mjs', { type: 'module' });
    let id = 0;
    const call = (type, fields = {}) => new Promise((resolve, reject) => {
      worker.onmessage = ({ data }) => data.type === 'error' ? reject(new Error(data.message)) : resolve(data);
      worker.onerror = event => reject(new Error(event.message));
      worker.postMessage({ id: ++id, type, ...fields }, fields.bytes ? [fields.bytes] : []);
    });
    try {
      await call('initialize', { bytes: await (await fetch('/quietproof.wasm')).arrayBuffer() });
      const options = { network: 'mainnet', verifier: 'browser.example', purpose: 'proof-of-control',
        message: 'public message', lifetimeSeconds: '300', claims: [{ txid: 'ab'.repeat(32), vout: 0,
          amountSats: '2100000000000000', program: 'cd'.repeat(20), scriptKind: 'p2wpkh' }] };
      const first = (await call('createRequest', { options })).bytes;
      const inspected = (await call('inspectRequest', { bytes: first })).metadata;
      const second = (await call('createRequest', { options })).bytes;
      const next = (await call('inspectRequest', { bytes: second })).metadata;
      if (inspected.verified || inspected.network !== 'mainnet' || inspected.nonce === next.nonce ||
          BigInt(inspected.expiresAt) - BigInt(inspected.notBefore) !== 300n ||
          inspected.claims[0].amountSats !== '2100000000000000') throw new Error('Request contract mismatch');
      const tagHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('BIP0322-signed-message')));
      const message = new TextEncoder().encode(options.message);
      const input = new Uint8Array(64 + message.length); input.set(tagHash); input.set(tagHash, 32); input.set(message, 64);
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
      if (Array.from(digest, b => b.toString(16).padStart(2, '0')).join('') !== inspected.messageHash)
        throw new Error('Message hash mismatch');
      return true;
    } finally { worker.terminate(); }
  });
});

test('JS rejects inexact integers, invalid UTF-8, unsupported scripts and oversized inputs', async () => {
  await inBrowser(async () => {
    const { encodeRequestOptions } = await import('/web/wasm/codec.mjs');
    const { instantiateReactor } = await import('/web/wasm/runtime.mjs');
    const options = { network: 'signet', verifier: 'browser.example', purpose: 'proof-of-funds', message: '',
      lifetimeSeconds: 300, claims: [{ txid: '01'.repeat(32), vout: 1, amountSats: '10', program: '02'.repeat(20), scriptKind: 'p2pkh' }] };
    for (const mutate of [o => o.verifier = '\ud800', o => o.verifier = 'a'.repeat(257),
      o => o.message = 'a'.repeat(4097), o => o.network = 'regtest', o => o.lifetimeSeconds = '18446744073709551616',
      o => o.claims[0].amountSats = 9007199254740992, o => o.claims[0].amountSats = '-1',
      o => o.claims[0].vout = 4294967296, o => o.claims[0].scriptKind = 'taproot', o => o.claims = []]) {
      const invalid = structuredClone(options); mutate(invalid);
      let rejected = false; try { encodeRequestOptions(invalid); } catch { rejected = true; }
      if (!rejected) throw new Error('Invalid options accepted');
    }
    const reactor = await instantiateReactor(await (await fetch('/quietproof.wasm')).arrayBuffer());
    for (const bytes of [new ArrayBuffer(0), new ArrayBuffer(4097)]) {
      let rejected = false; try { reactor.inspect(bytes); } catch { rejected = true; }
      if (!rejected) throw new Error('Oversized/truncated inspection accepted');
    }
    for (const mutate of [o => o.lifetimeSeconds = 0, o => o.lifetimeSeconds = 86401,
      o => o.claims.push(structuredClone(o.claims[0])), o => o.claims[0].amountSats = '18446744073709551615']) {
      const invalid = structuredClone(options); mutate(invalid);
      let rejected = false; try { reactor.createRequest(invalid); } catch { rejected = true; }
      if (!rejected) throw new Error('Core invalid claims accepted');
    }
    return true;
  });
});


test('bounded diagnostic stderr and checked monotonic clock imports', async () => {
  await inBrowser(async () => {
    const { createWasiImports, requireCapabilities } = await import('/web/wasm/runtime.mjs');
    let missingClock = false;
    try { requireCapabilities({ WebAssembly, crypto, Date }); }
    catch (error) { missingClock = error.name === 'CapabilityError' && error.message.includes('clocks'); }
    if (!missingClock) throw new Error('Missing monotonic clock was accepted');
    const memory = new WebAssembly.Memory({ initial: 2 });
    const messages = [];
    const host = { performance: { now: () => 123.125 }, console: { warn: s => messages.push(s) } };
    const api = createWasiImports(() => memory, host), view = new DataView(memory.buffer);
    const data = new TextEncoder().encode('verifier diagnostic');
    new Uint8Array(memory.buffer, 100, data.length).set(data);
    view.setUint32(0, 100, true); view.setUint32(4, data.length, true);
    if (api.fd_write(2, 0, 1, 8) || messages[0] !== 'verifier diagnostic' || view.getUint32(8, true) !== data.length)
      throw new Error('Diagnostics were not written accurately');
    if (api.fd_write(1, 0, 1, 8) !== 8 || api.fd_seek(2) !== 70 || api.fd_close(2) !== 8 ||
        api.fd_write(2, -1, 1, 8) !== 21 || api.fd_write(2, 0, 65, 8) !== 28)
      throw new Error('Unexpected descriptor or bounds accepted');
    view.setUint32(4, 65536, true);
    if (api.fd_write(2, 0, 1, 8) !== 51) throw new Error('Diagnostic budget ignored');
    if (api.clock_time_get(1, 0n, 16) || view.getBigUint64(16, true) !== 123125000n)
      throw new Error('Monotonic time conversion incorrect');
    host.performance.now = () => NaN;
    if (api.clock_time_get(1, 0n, 16) !== 29) throw new Error('Invalid monotonic time accepted');
    return true;
  });
});

test('real proof stages bind independent request/policy and consume explorer phase', { timeout: 600000 }, async () => {
  assert(realFixtures, 'Set QUIETPROOF_WASM_FIXTURES to native verifier-test output.');
  await inBrowser(async () => {
    const worker = new Worker('/web/wasm/worker.mjs', { type: 'module' });
    let id = 0;
    const call = (type, fields = {}) => new Promise((resolve, reject) => {
      const start = performance.now();
      worker.onmessage = ({ data }) => {
        console.info(`qp-stage: ${type} ${Math.round(performance.now()-start)}ms ${data.type}/${data.cryptography ?? data.name ?? ''}`);
        resolve(data);
      };
      worker.onerror = event => reject(new Error(event.message));
      worker.postMessage({ id: ++id, type, ...fields }, fields.bytes ? [fields.bytes] : []);
    });
    const ok = response => { if (response.type === 'error') throw new Error(response.message); return response; };
    const rejected = response => { if (response.type !== 'error') throw new Error('Expected rejection'); };
    try {
      ok(await call('initialize', { bytes: await (await fetch('/quietproof.wasm')).arrayBuffer() }));
      const proof = await (await fetch('/real/one-key.qpf')).arrayBuffer();
      const request = await (await fetch('/real/one-key.qpr')).arrayBuffer();
      const policy = { expectedRequest: request, provider: 'fixture-explorer', maxLifetimeSeconds: 3600,
        minConfirmations: 1, minimumTotalSats: 50000, maxObservationAgeSeconds: 60 };
      const explicit = { ...policy, expectedRequest: undefined, network: 'mainnet',
        verifier: 'browser-fixture.example', purpose: 'proof-of-funds', message: 'public browser fixture' };
      for (const changes of [{ network: 'signet' }, { verifier: 'wrong.example' },
        { purpose: 'proof-of-control' }, { message: 'wrong message' }, { maxLifetimeSeconds: 1 }]) {
        rejected(await call('prepare', { bytes: proof.slice(0), policy: { ...explicit, ...changes } }));
      }
      const wrongRequest = request.slice(0); new Uint8Array(wrongRequest)[wrongRequest.byteLength - 1] ^= 1;
      rejected(await call('prepare', { bytes: proof.slice(0), policy: { ...policy, expectedRequest: wrongRequest } }));
      rejected(await call('prepare', { bytes: proof.slice(0) }));
      ok(await call('prepare', { bytes: proof.slice(0), policy: explicit }));
      // Construct canonical but unsupported statement modes around the real
      // envelope; preparation must reject before cryptography or claim fetching.
      const r = new Uint8Array(request), rv = new DataView(request);
      let purposeStart = 6; purposeStart += 2 + rv.getUint16(purposeStart);
      const purposeEnd = purposeStart + 2 + rv.getUint16(purposeStart);
      const flags = purposeEnd + 80;
      const snapshot = new Uint8Array(r.length + 36);
      snapshot.set(r.subarray(0, flags)); snapshot[flags] = 1;
      snapshot.fill(1, flags + 1, flags + 33);
      new DataView(snapshot.buffer).setUint32(flags + 33, 100);
      snapshot.set(r.subarray(flags + 1), flags + 37);
      const bridgePurpose = new TextEncoder().encode('bridge-authorization');
      const bridgeBinding = new Uint8Array(1 + 32 + 2 + 3 + 32);
      bridgeBinding.fill(1, 1, 33); new DataView(bridgeBinding.buffer).setUint16(33, 3);
      bridgeBinding.set(new TextEncoder().encode('USD'), 35); bridgeBinding.fill(2, 38);
      const bridge = new Uint8Array(purposeStart + 2 + bridgePurpose.length + 80 + 2 + bridgeBinding.length + r.length - flags - 2);
      let b = 0; bridge.set(r.subarray(0, purposeStart)); b += purposeStart;
      new DataView(bridge.buffer).setUint16(b, bridgePurpose.length); b += 2;
      bridge.set(bridgePurpose, b); b += bridgePurpose.length;
      bridge.set(r.subarray(purposeEnd, flags), b); b += 80;
      bridge[b++] = 0; bridge[b++] = 1; bridge.set(bridgeBinding, b); b += bridgeBinding.length;
      bridge.set(r.subarray(flags + 2), b);
      for (const statement of [snapshot, bridge]) {
        const unsupportedProof = new Uint8Array(proof.byteLength - r.length + statement.length);
        unsupportedProof.set(new Uint8Array(proof, 0, 9));
        new DataView(unsupportedProof.buffer).setUint32(5, statement.length);
        unsupportedProof.set(statement, 9);
        unsupportedProof.set(new Uint8Array(proof, 9 + r.length), 9 + statement.length);
        const response = await call('prepare', { bytes: unsupportedProof.buffer, policy });
        if (response.type !== 'error' || response.name !== 'UnsupportedError') throw new Error('Unsupported mode was not rejected');
      }
      const first = ok(await call('prepare', { bytes: proof.slice(0), policy }));
      if (first.cryptography !== 'not_checked' || first.manifest) throw new Error('Unverified manifest leaked');
      const second = ok(await call('prepare', { bytes: proof.slice(0), policy }));
      rejected(await call('verify', { operationId: first.operationId, phaseToken: first.phaseToken }));
      const verified = ok(await call('verify', { operationId: second.operationId, phaseToken: second.phaseToken }));
      if (verified.cryptography !== 'valid' || verified.policy !== 'matched' || verified.explorer !== 'unavailable' ||
          verified.authorizes !== false || !verified.manifest || verified.manifest.proofBytes < 40000000)
        throw new Error('Real proof was not verified or trust was overstated');
      rejected(await call('verify', { operationId: second.operationId, phaseToken: second.phaseToken }));
      rejected(await call('evaluate', { operationId: first.operationId, phaseToken: verified.phaseToken, evidence: {} }));
      const manifest = verified.manifest;
      const evidence = { provider: 'fixture-explorer', network: 'mainnet', observedAt: Math.floor(Date.now() / 1000),
        tipBefore: { block: '07'.repeat(32), height: 100 }, tipAfter: { block: '07'.repeat(32), height: 100 },
        claims: manifest.claims.map(claim => ({ ...claim, status: 'unspent',
          scriptPubKey: '0014' + claim.program, confirmations: 10, inBestChain: true })) };
      const evaluated = ok(await call('evaluate', { operationId: verified.operationId, phaseToken: verified.phaseToken, evidence }));
      if (evaluated.explorer !== 'reported_unspent' || evaluated.cryptography !== 'valid' ||
          evaluated.authorizes !== false || evaluated.totalSats !== '50000') throw new Error('Explorer assessment incorrect');
      rejected(await call('evaluate', { operationId: verified.operationId, phaseToken: verified.phaseToken, evidence }));
      const corrupted = proof.slice(0); new Uint8Array(corrupted)[corrupted.byteLength - 1] ^= 1;
      const bad = ok(await call('prepare', { bytes: corrupted, policy }));
      const invalid = ok(await call('verify', { operationId: bad.operationId, phaseToken: bad.phaseToken }));
      if (invalid.cryptography !== 'invalid' || invalid.manifest || invalid.explorer !== 'unavailable')
        throw new Error('Mutated real proof accepted or claims exposed');
      rejected(await call('evaluate', { operationId: bad.operationId, phaseToken: invalid.phaseToken, evidence }));
      const wrongCircuit = proof.slice(0), circuitView = new DataView(wrongCircuit);
      const digestOffset = 9 + circuitView.getUint32(5) + (new Uint8Array(wrongCircuit)[4] === 2 ? 8 : 0);
      new Uint8Array(wrongCircuit)[digestOffset] ^= 1;
      const unsupported = ok(await call('prepare', { bytes: wrongCircuit, policy }));
      rejected(await call('verify', { operationId: unsupported.operationId, phaseToken: unsupported.phaseToken }));
      const wrongParameters = proof.slice(0);
      new DataView(wrongParameters).setUint32(digestOffset + 32 + 4, 3);
      rejected(await call('prepare', { bytes: wrongParameters, policy }));
      return true;
    } finally { worker.terminate(); }
  });
});

test('browser time and phase failures prevent crypto and evidence reuse', async () => {
  assert(realFixtures, 'Set QUIETPROOF_WASM_FIXTURES to native verifier-test output.');
  await inBrowser(async () => {
    const { instantiateReactor } = await import('/web/wasm/runtime.mjs');
    const reactor = await instantiateReactor(await (await fetch('/quietproof.wasm')).arrayBuffer());
    const proof = await (await fetch('/real/one-key.qpf')).arrayBuffer();
    const request = await (await fetch('/real/one-key.qpr')).arrayBuffer();
    const metadata = reactor.inspect(request);
    const policy = { expectedRequest: request, provider: '', maxLifetimeSeconds: 3600,
      minConfirmations: 1, minimumTotalSats: 0, maxObservationAgeSeconds: 60 };
    let rejected = false;
    const prepared = reactor.prepare(proof, policy), original = Date.now;
    try {
      Date.now = () => Number(metadata.expiresAt) * 1000;
      try { reactor.verify(prepared.contextId); } catch (error) { rejected = error.name === 'PolicyError'; }
      if (!rejected) throw new Error('Expiry was ignored');
    } finally { Date.now = original; }
    const again = reactor.prepare(proof, policy);
    try {
      Date.now = () => NaN; rejected = false;
      try { reactor.verify(again.contextId); } catch { rejected = true; }
      if (!rejected) throw new Error('Clock failure was ignored');
    } finally { Date.now = original; }
    rejected = false;
    try { reactor.verify(again.contextId); } catch { rejected = true; }
    if (!rejected) throw new Error('Clock failure retained context');
    return true;
  });
});

test('a trapped instance stays unusable until its worker is recreated', async () => {
  await inBrowser(async () => {
    const bytes = new Uint8Array(await (await fetch('/quietproof.wasm')).arrayBuffer());
    // Test-only corruption: replace alloc's body with unreachable/nop/end while
    // retaining the complete artifact import/export/type surface.
    let cursor = 8, imported = 0, target;
    const uleb = () => { let value = 0, shift = 0, byte; do { byte = bytes[cursor++]; value += (byte & 127) * 2 ** shift; shift += 7; } while (byte & 128); return value; };
    const name = () => { const size = uleb(), start = cursor; cursor += size; return new TextDecoder().decode(bytes.subarray(start, cursor)); };
    while (cursor < bytes.length) {
      const section = bytes[cursor++], length = uleb(), end = cursor + length;
      if (section === 2) { imported = uleb(); }
      if (section === 7) {
        const count = uleb();
        for (let i = 0; i < count; i++) { const label = name(), kind = bytes[cursor++], index = uleb(); if (label === 'quietproof_wasm_alloc' && kind === 0) target = index; }
      }
      if (section === 10) {
        const count = uleb();
        for (let i = 0; i < count; i++) {
          const size = uleb(), functionEnd = cursor + size;
          if (i === target - imported) {
            const locals = uleb();
            for (let j = 0; j < locals; j++) { uleb(); cursor++; }
            bytes.fill(1, cursor, functionEnd - 1); bytes[cursor] = 0; bytes[functionEnd - 1] = 11;
          }
          cursor = functionEnd;
        }
      }
      cursor = end;
    }
    const worker = new Worker('/web/wasm/worker.mjs', { type: 'module' });
    let id = 0;
    const call = (type, buffer) => new Promise((resolve, reject) => {
      worker.onmessage = ({ data }) => resolve(data); worker.onerror = event => reject(new Error(event.message));
      worker.postMessage({ id: ++id, type, bytes: buffer }, buffer ? [buffer] : []);
    });
    try {
      if ((await call('initialize', bytes.buffer)).type !== 'ready') throw new Error('Trap fixture failed to initialize');
      const failed = await call('smoke');
      if (failed.name !== 'WorkerResetError') throw new Error('Trap did not require worker recreation');
      const reused = await call('reset');
      if (reused.type !== 'error' || !reused.message.includes('unusable')) throw new Error('Trapped worker was reused');
      return true;
    } finally { worker.terminate(); }
  });
});
