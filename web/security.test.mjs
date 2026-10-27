import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeEvidence } from './wasm/codec.mjs';
import { createWasiImports } from './wasm/runtime.mjs';

test('attacker evidence rejects malformed text, hashes, scripts, counts and inexact integers', () => {
  const valid = { network: 'mainnet', provider: 'https://blockstream.info/api', observedAt: '1',
    tipBefore: { block: '11'.repeat(32), height: '1' }, tipAfter: { block: '11'.repeat(32), height: '1' },
    claims: [{ txid: '22'.repeat(32), vout: 0, status: 'unspent', amountSats: '1', scriptPubKey: '0014' + '33'.repeat(20),
      confirmations: '1', inBestChain: true }] };
  assert(encodeEvidence(valid).byteLength < 4096);
  for (const mutate of [
    e => e.network = 'regtest', e => e.provider = '<img>\u0000', e => e.observedAt = '18446744073709551616',
    e => e.tipBefore.block = '<img src=x onerror=alert(1)>', e => e.tipAfter.height = 1.5,
    e => e.claims = [], e => e.claims = Array(17).fill(e.claims[0]),
    e => e.claims[0].txid = '../x', e => e.claims[0].vout = 4294967296,
    e => e.claims[0].status = 'valid_current', e => e.claims[0].amountSats = 9007199254740992,
    e => e.claims[0].scriptPubKey = '<script>', e => e.claims[0].scriptPubKey = '00'.repeat(26),
    e => e.claims[0].confirmations = '-1', e => e.claims[0].inBestChain = 'true',
  ]) {
    const value = structuredClone(valid); mutate(value); assert.throws(() => encodeEvidence(value));
  }
});

test('WASI imports never expose descriptors or wrap heap-boundary ranges', () => {
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
  let entropy = 0;
  const imports = createWasiImports(() => memory, { crypto: { getRandomValues(bytes) { entropy++; bytes.fill(1); } } });
  assert.deepEqual(Object.keys(imports).sort(), ['clock_time_get', 'fd_close', 'fd_seek', 'fd_write', 'random_get']);
  for (const [pointer, size] of [[-1, 8], [65535, 2], [65536, 1], [0, -1]]) {
    assert.equal(imports.random_get(pointer, size), 21);
  }
  assert.equal(entropy, 0);
  assert.equal(imports.clock_time_get(0, 0n, 65529), 21);
  assert.equal(imports.fd_write(2, 65535, 1, 0), 21);
  assert.equal(imports.fd_write(2, 0, 65, 0), 28);
  for (const fd of [0, 1, 3, 999]) {
    assert.equal(imports.fd_write(fd, 0, 0, 0), 8);
    assert.equal(imports.fd_close(fd), 8); assert.equal(imports.fd_seek(fd), 8);
  }
  assert.equal(imports.random_get(65528, 8), 0);
  assert.equal(imports.fd_close(2), 8); assert.equal(imports.fd_seek(2), 70);
});
