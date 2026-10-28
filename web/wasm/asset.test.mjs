import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assetUrl, loadWasmAsset } from './asset.mjs';
import { secureHtml } from '../../docs/.vitepress/security.mjs';
import { createHash } from 'node:crypto';

test('WASM URLs reject unsafe origins, schemes, credentials and ambiguous paths before fetch', async () => {
  for (const value of ['https://evil.example/x.wasm', '//evil.example/x.wasm', 'javascript:x.wasm',
    'data:application/wasm,x.wasm', 'file:///x.wasm', '/x.wasm?q=1', '/x.wasm#x', '/x\\x.wasm',
    '/x\nx.wasm', 'https://user:pass@quietproof.invalid/x.wasm', '', undefined]) {
    let calls = 0;
    await assert.rejects(loadWasmAsset(value, { fetch() { calls++; }, check() {}, label: 'proof' }));
    assert.equal(calls, 0, String(value));
  }
  assert.equal(assetUrl('/quietproof/wasm/quietproof.wasm', 'https://host.example/quietproof/verify').href,
    'https://host.example/quietproof/wasm/quietproof.wasm');
});

test('WASM download is credential-free, bounded and never follows redirects', async () => {
  const bytes = new Uint8Array([0, 97, 115, 109]);
  const result = await loadWasmAsset('/x.wasm', { check() {}, label: 'proof', fetch: async (url, init) => {
    assert.equal(url, '/x.wasm');
    assert.equal(init.mode, 'same-origin'); assert.equal(init.redirect, 'error');
    assert.equal(init.credentials, 'omit'); assert.equal(init.referrerPolicy, 'no-referrer');
    assert.equal(init.body, undefined); assert.equal(init.method, undefined);
    return new Response(bytes);
  } });
  assert.deepEqual(new Uint8Array(result), bytes);
  for (const response of [new Response('', { status: 404 }), new Response(''),
    new Response(bytes, { headers: { 'content-length': 'NaN' } }),
    new Response(bytes, { headers: { 'content-length': '8388609' } }),
    new Response(new Uint8Array(8388609)),
    { ok: true, redirected: true, headers: new Headers(), body: null },
    { ok: true, url: 'https://evil.example/x.wasm', headers: new Headers(), body: null }]) {
    await assert.rejects(loadWasmAsset('/x.wasm', { fetch: async () => response, check() {}, label: 'proof' }));
  }
});

test('static CSP precedes resources and authorizes exact inline build scripts', () => {
  const script = 'window.test = "<tag>";';
  const html = secureHtml(`<html><head><script>${script}</script><script src="/assets/app.js"></script></head></html>`);
  assert(html.indexOf('Content-Security-Policy') < html.indexOf('<script'));
  assert(html.includes(`'sha256-${createHash('sha256').update(script).digest('base64')}'`));
  assert(html.includes("worker-src 'self'")); assert(html.includes("object-src 'none'"));
  assert(!html.includes("script-src 'unsafe-inline'")); assert(!html.includes("'unsafe-eval'"));
  assert(!html.includes('frame-ancestors')); // Header-only directive, never claim meta support.
});

test('hashed reactor bytes reject stale CDN/cache substitutions independently of MIME', async () => {
  const bytes = new Uint8Array([0, 97, 115, 109]);
  const digest = createHash('sha256').update(bytes).digest('hex');
  const url = `/assets/quietproof.${digest}.wasm`;
  const load = body => loadWasmAsset(url, { check() {}, label: 'proof',
    fetch: async () => new Response(body, { headers: { 'content-type': 'text/plain' } }) });
  assert.deepEqual(new Uint8Array(await load(bytes)), bytes, 'bounded fetch works with a generic MIME host');
  await assert.rejects(load(new Uint8Array([0, 97, 115, 110])), /version mismatch/);
});
