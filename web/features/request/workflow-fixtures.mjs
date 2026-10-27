// Node-only fixtures. Public disposable scalars 1 and 2 are used by native test
// proving only. Browser inputs contain public addresses, outputs and scripts.
import { createECDH, createHash } from 'node:crypto';
import { fixtures } from '../provider/fixtures.mjs';
const hash = (algorithm, bytes) => createHash(algorithm).update(bytes).digest();
const base58 = bytes => {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt('0x' + bytes.toString('hex')), result = '';
  while (n) { result = alphabet[Number(n % 58n)] + result; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; result = '1' + result; }
  return result;
};
export const workflows = ['mainnet', 'signet'].flatMap(network =>
  [['p2wpkh'], ['p2pkh'], ['p2wpkh', 'p2pkh']].map(kinds => {
    const claims = kinds.map((scriptKind, i) => {
      const scalar = Buffer.alloc(32); scalar[31] = i + 1;
      const key = createECDH('secp256k1'); key.setPrivateKey(scalar);
      const program = hash('ripemd160', hash('sha256', key.getPublicKey(null, 'compressed')));
      const payload = Buffer.concat([Buffer.from([network === 'mainnet' ? 0 : 111]), program]);
      const p2pkh = base58(Buffer.concat([payload, hash('sha256', hash('sha256', payload)).subarray(0, 4)]));
      const txid = (i === 0 ? 'ab' : 'cd').repeat(32), amountSats = String(50000 + i);
      return { txid, vout: 0, amountSats, program: program.toString('hex'), scriptKind,
        address: scriptKind === 'p2wpkh' ? fixtures[network].p2wpkh : p2pkh,
        scriptPubKey: scriptKind === 'p2wpkh' ? `0014${program.toString('hex')}` : `76a914${program.toString('hex')}88ac` };
    });
    return { id: `${network}-${kinds.length === 2 ? 'mixed-two-key' : kinds[0]}`, network, claims,
      version: kinds.includes('p2pkh') ? 2 : 1, publicDisposableScalars: claims.map((_, i) => i + 1) };
  }));

export function providerResponse(workflow, url) {
  if (url.endsWith('/block-height/0')) return { body: fixtures[workflow.network].genesis };
  const status = { confirmed: true, block_height: 100, block_hash: fixtures.block, block_time: 1600000000 };
  const claim = workflow.claims.find(c => url.endsWith(`/address/${c.address}/utxo`) || url.endsWith(`/tx/${c.txid}`));
  if (!claim) throw new Error(`Unexpected fixture request: ${url}`);
  return { json: url.endsWith('/utxo') ? [{ txid: claim.txid, vout: claim.vout, value: Number(claim.amountSats), status }]
    : { txid: claim.txid, vout: [{ value: Number(claim.amountSats), scriptpubkey: claim.scriptPubKey }], status } };
}
