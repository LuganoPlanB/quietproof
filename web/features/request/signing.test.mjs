import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decodeInspection } from '../../wasm/codec.mjs';
import { signingMaterial } from './signing.mjs';

async function fixture(name) {
  const bytes = await readFile(new URL(`../../../tests/wasm/fixtures/${name}.qpr`, import.meta.url));
  const inspection = new Uint8Array(61 + bytes.length);
  inspection.set(new TextEncoder().encode('QWI1')); inspection.set(bytes, 61);
  const metadata = decodeInspection(inspection.buffer);
  metadata.signatureProfileName = metadata.signatureProfile === 2 ? 'bitcoin-message-ecdsa-v1' : 'bip322-ecdsa-v1';
  const claims = metadata.claims.map(c => ({ ...c, address: c.scriptKind === 'p2pkh'
    ? 'mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r' : 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx' }));
  return { bytes: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), metadata, claims };
}

for (const name of ['signature-p2wpkh', 'signature-p2pkh', 'signature-p2pkh-bip322']) {
  test(`${name}: signing message matches the independent native digest fixture`, async () => {
    const { bytes, metadata, claims } = await fixture(name);
    const material = await signingMaterial(bytes, metadata, claims);
    const digest = await readFile(new URL(`../../../tests/wasm/fixtures/${name}.digest`, import.meta.url));
    assert.equal(material.message, 'quietproof:signature:v4:' + digest.toString('hex'));
    assert.equal(material.message.length, 88);
    assert.equal(material.message.endsWith('\n'), false);
    assert.equal(material.port, 38332);
    if (name === 'signature-p2pkh-bip322') {
      assert.equal(material.command, null, 'never suggest signmessage for P2PKH BIP322 Full');
      assert.equal(material.format, 'bip322-full');
    } else {
      assert.equal(material.command, `bitcoin-cli -signet -rpcconnect=127.0.0.1 signmessage '${material.address}' '${material.message}'`);
      assert.equal(material.format, name === 'signature-p2pkh' ? 'bitcoin-message' : 'bip322-simple');
    }
    const regenerated = bytes.slice(0); new Uint8Array(regenerated)[40] ^= 1;
    assert.notEqual((await signingMaterial(regenerated, metadata, claims)).message, material.message);
  });
}

test('mainnet uses its default local RPC port and does not request credentials', async () => {
  const { bytes, metadata, claims } = await fixture('signature-p2wpkh');
  const result = await signingMaterial(bytes, { ...metadata, network: 'mainnet' }, claims);
  assert.equal(result.port, 8332);
  assert.match(result.command, /^bitcoin-cli -rpcconnect=127\.0\.0\.1 signmessage /);
  assert.doesNotMatch(result.command, /rpcuser|rpcpassword|curl/);
});

test('unknown profiles, missing signing addresses and shell text fail closed', async () => {
  const { bytes, metadata, claims } = await fixture('signature-p2wpkh');
  await assert.rejects(signingMaterial(bytes, { ...metadata, signatureProfileName: 'unknown' }, claims), /Unsupported/);
  await assert.rejects(signingMaterial(bytes, metadata, []), /address is missing/);
  await assert.rejects(signingMaterial(bytes, metadata, [{ ...claims[0], address: "address'; touch x; '" }]), /address is missing/);
  assert.equal(await signingMaterial(bytes, { proofMode: 'key-knowledge' }, claims), null);
});
