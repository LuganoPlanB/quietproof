import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodePolicy, encodeRequestOptions, decodeInspection } from './codec.mjs';
import { readFileSync } from 'node:fs';

const base = { provider: '', maxLifetimeSeconds: 86400, minConfirmations: 1,
  minimumTotalSats: 0, maxObservationAgeSeconds: 60 };
test('public statement decoder rejects invalid enum, flags, claim count and kind', () => {
  const request=readFileSync(new URL('../../tests/wasm/fixtures/signature-p2wpkh.qpr',import.meta.url));
  const inspect=bytes=>{const encoded=new Uint8Array(61+bytes.length);encoded.set(new TextEncoder().encode('QWI1'));encoded.set(bytes,61);return decodeInspection(encoded.buffer);};
  assert.equal(inspect(request).proofMode,'signature-possession');
  let flags=10;for(let i=0;i<2;i++)flags+=2+request.readUInt16BE(flags);flags+=80;
  assert.equal(request[flags],0);assert.equal(request[flags+1],0);
  for(const [offset,value,message] of [[5,255,/network/],[flags,2,/snapshot/],[flags+1,2,/bridge/],
    [flags+3,0,/claim count/],[flags+3,17,/claim count/],[flags+4+44,2,/script kind/]]){
    const changed=Buffer.from(request);changed[offset]=value;assert.throws(()=>inspect(changed),message);
  }
});
test('signature policy requires explicit mode and independently retained binary request', () => {
  const request = new Uint8Array([1, 2, 3]).buffer;
  assert.equal(new TextDecoder().decode(new Uint8Array(encodePolicy({ ...base, expectedRequest: request })).slice(0,4)), 'QWP1');
  const signature = new Uint8Array(encodePolicy({ ...base, proofMode: 'signature-possession', expectedRequest: request }));
  assert.equal(new TextDecoder().decode(signature.slice(0,4)), 'QWP2');
  assert.deepEqual([...signature.slice(4,6)], [1,0]);
  assert.throws(() => encodePolicy({ ...base, proofMode: 'signature-possession' }), /retained/);
  assert.throws(() => encodePolicy({ ...base, proofMode: 'unknown', expectedRequest: request }), /mode/);
});
test('signature options select the mode and signing kind while old options stay QWC1', () => {
  const options = { network: 'mainnet', verifier: 'auditor.example', purpose: 'proof-of-funds', message: '', lifetimeSeconds: 300,
    claims: [{ txid: '01'.repeat(32), vout: 0, amountSats: '1', scriptKind: 'p2wpkh', program: '02'.repeat(20) }] };
  assert.equal(new TextDecoder().decode(new Uint8Array(encodeRequestOptions(options)).slice(0,4)), 'QWC1');
  const bytes = new Uint8Array(encodeRequestOptions({ ...options, proofMode: 'signature-possession', signingKind: 'p2wpkh' }));
  assert.equal(new TextDecoder().decode(bytes.slice(0,4)), 'QWC2');
  assert.deepEqual([...bytes.slice(4,6)], [1,0]);
  assert.throws(() => encodeRequestOptions({ ...options, proofMode: 'signature-possession' }), /signing kind/);
});
