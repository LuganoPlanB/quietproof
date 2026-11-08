import { test } from 'node:test';
import assert from 'node:assert/strict';
import { selectionSummary, validateForm } from './form.mjs';
import { decodeProfileCapabilities } from '../../wasm/codec.mjs';
import { readFileSync } from 'node:fs';
const raw=readFileSync(new URL('../../../tests/wasm/fixtures/signature.profiles',import.meta.url));
const signatureProfiles=decodeProfileCapabilities(raw.buffer.slice(raw.byteOffset,raw.byteOffset+raw.byteLength));
const claim = (i, amountSats = '1', program = '11'.repeat(20)) => ({ txid: i.toString(16).padStart(64, '0'), vout: 0, amountSats, program, scriptKind: 'p2wpkh' });
test('selection enforces exact amounts, unique outputs, 16 claims and one fingerprint', () => {
  assert.equal(selectionSummary([claim(1, '2099999999999999'), claim(2)]).totalSats, '2100000000000000');
  for (const claims of [[claim(1), claim(1)], [claim(1, '1.1')], [claim(1, '2100000000000001')],
    Array.from({ length: 17 }, (_, i) => claim(i)), [claim(1), claim(2, '1', '22'.repeat(20))]])
    assert.throws(() => selectionSummary(claims));
});
test('context validates protocol lifetime, UTF-8 byte limits and supported purpose', () => {
  const options = { network: 'signet', claims: [claim(1)], verifier: 'Auditor', purpose: 'proof-of-funds', message: '', lifetimeSeconds: '300' };
  assert.equal(validateForm(options).count, 1);
  for (const change of [{ lifetimeSeconds: '86401' }, { lifetimeSeconds: '0' }, { lifetimeSeconds: '1.5' },
    { verifier: 'é'.repeat(129) }, { message: 'é'.repeat(2049) }, { message: '\n' }, { purpose: 'bridge-authorization' }, { claims: [] }])
    assert.throws(() => validateForm({ ...options, ...change }));
});
test('signature selection requires supported build and a signing kind among selected outputs', () => {
  const options = { network: 'mainnet', claims: [claim(1)], verifier: 'Auditor', purpose: 'proof-of-control', message: '',
    lifetimeSeconds: '300', proofMode: 'signature-possession', signingKind: 'p2wpkh', signatureProfile:1, signatureProfileVersion:1 };
  assert.equal(validateForm(options, { signaturePossession: true, signatureProfiles }).count, 1);
  assert.throws(() => validateForm(options, { signaturePossession: false }), /unavailable/);
  assert.throws(() => validateForm({ ...options, signingKind: 'p2pkh' }, { signaturePossession: true }), /present/);
  for(const change of [{signatureProfile:2},{signatureProfile:255},{signatureProfileVersion:2}])
    assert.throws(()=>validateForm({...options,...change},{signaturePossession:true,signatureProfiles}),/procedure/);
  for(const signatureProfile of [1,2]) assert.equal(validateForm({...options,claims:[{...claim(1),scriptKind:'p2pkh'}],signingKind:'p2pkh',signatureProfile},
    {signaturePossession:true,signatureProfiles}).count,1);
});
