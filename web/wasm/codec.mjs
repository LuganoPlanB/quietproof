// Binary transport only: proof/request artifacts never pass through JSON/base64.
export const MAX_ENVELOPE_BYTES = 128 * 1024 * 1024 + 4161;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const U64_MAX = (1n << 64n) - 1n;
function integer(value, maximum = U64_MAX) {
  if (typeof value === 'number' && !Number.isSafeInteger(value))
    throw new Error('Integer must be exact.');
  if (!['bigint', 'number', 'string'].includes(typeof value) ||
      (typeof value === 'string' && !/^(0|[1-9][0-9]*)$/.test(value)))
    throw new Error('Invalid unsigned integer.');
  const n = BigInt(value);
  if (n < 0n || n > maximum) throw new Error('Unsigned integer out of range.');
  return n;
}
function hex(value, size) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-fA-F]{${size * 2}}$`).test(value))
    throw new Error('Invalid fixed-length hexadecimal field.');
  return Uint8Array.from(value.match(/../g), item => parseInt(item, 16));
}
function hexify(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
function text(value, maximum) {
  if (typeof value !== 'string' || value.isWellFormed?.() === false)
    throw new Error('Invalid UTF-8 text.');
  const bytes = encoder.encode(value);
  // Round trip also rejects lone surrogates in engines without isWellFormed.
  if (decoder.decode(bytes) !== value || bytes.length > maximum || /[\x00-\x1f\x7f]/.test(value))
    throw new Error('Invalid or oversized UTF-8 text.');
  return bytes;
}
export function encodeRequestOptions(options) {
  if (!options || !['mainnet', 'signet'].includes(options.network))
    throw new Error('Select mainnet or signet.');
  if (!Array.isArray(options.claims) || !options.claims.length || options.claims.length > 16)
    throw new Error('Select between one and sixteen claims.');
  const bytes = [];
  const put = data => bytes.push(...data);
  const uint = (value, width) => {
    let n = integer(value, (1n << BigInt(width * 8)) - 1n);
    const out = Array(width);
    for (let i = width - 1; i >= 0; i--) { out[i] = Number(n & 255n); n >>= 8n; }
    put(out);
  };
  const string = (value, maximum) => { const data = text(value, maximum); uint(data.length, 2); put(data); };
  put(encoder.encode('QWC1'));
  uint(options.network === 'mainnet' ? 0 : 2, 1);
  uint(options.lifetimeSeconds, 8);
  string(options.verifier, 256);
  string(options.purpose, 64);
  string(options.message, 4096);
  uint(options.claims.length, 2);
  for (const claim of options.claims) {
    put(hex(claim.txid, 32)); uint(claim.vout, 4); uint(claim.amountSats, 8);
    if (!['p2wpkh', 'p2pkh'].includes(claim.scriptKind)) throw new Error('Unsupported script kind.');
    uint(claim.scriptKind === 'p2wpkh' ? 0 : 1, 1); put(hex(claim.program, 20));
  }
  return Uint8Array.from(bytes).buffer;
}

export function decodeInspection(buffer) {
  const bytes = new Uint8Array(buffer);
  let offset = 0;
  const take = n => {
    if (n > bytes.length - offset) throw new Error('Truncated inspection.');
    const out = bytes.subarray(offset, offset + n); offset += n; return out;
  };
  const uint = n => { let out = 0n; for (const b of take(n)) out = (out << 8n) | BigInt(b); return out; };
  const number = n => Number(uint(n));
  const string = () => decoder.decode(take(number(2)));
  if (decoder.decode(take(4)) !== 'QWI1') throw new Error('Invalid inspection format.');
  const envelopeVersion = number(1);
  const proofCreatedAt = uint(8).toString();
  const circuitDigest = hexify(take(32));
  const circuitVersion = number(4), rate = number(4), queries = number(4), proofBytes = number(4);
  const statementStart = offset;
  if (decoder.decode(take(4)) !== 'QPS1') throw new Error('Invalid statement format.');
  const statementVersion = number(1), networkId = number(1);
  const verifier = string(), purpose = string();
  const nonce = hexify(take(32)), messageHash = hexify(take(32));
  const notBefore = uint(8).toString(), expiresAt = uint(8).toString();
  const hasSnapshot = number(1) === 1;
  const snapshot = hasSnapshot ? { block: hexify(take(32)), height: number(4) } : null;
  const hasBridge = number(1) === 1;
  const bridge = hasBridge ? { networkId: number(1), commitment: hexify(take(32)), assetId: string(), lockId: hexify(take(32)) } : null;
  const count = number(2), claims = [];
  for (let i = 0; i < count; i++) {
    const txid = hexify(take(32)), vout = number(4), amountSats = uint(8).toString();
    const kind = statementVersion === 2 ? number(1) : 0;
    claims.push({ txid, vout, amountSats, scriptKind: kind === 0 ? 'p2wpkh' : 'p2pkh', program: hexify(take(20)) });
  }
  if (offset !== bytes.length) throw new Error('Trailing inspection bytes.');
  return { verified: false, envelopeVersion, proofCreatedAt: envelopeVersion === 2 ? proofCreatedAt : null,
    circuitDigest, circuitVersion, rate, queries, proofBytes, statementVersion,
    network: ['mainnet', 'testnet3', 'signet', 'regtest', 'testnet4'][networkId], verifier, purpose,
    nonce, messageHash, notBefore, expiresAt, snapshot, bridge, claims,
    requestBytes: bytes.slice(statementStart).buffer };
}

class Writer {
  bytes = [];
  put(data) { this.bytes.push(...data); }
  uint(value, width) {
    let n = integer(value, (1n << BigInt(width * 8)) - 1n);
    const out = Array(width);
    for (let i = width - 1; i >= 0; i--) { out[i] = Number(n & 255n); n >>= 8n; }
    this.put(out);
  }
  text(value, maximum) { const bytes = text(value, maximum); this.uint(bytes.length, 2); this.put(bytes); }
  finish() { return Uint8Array.from(this.bytes).buffer; }
}
export function encodePolicy(policy) {
  if (!policy || typeof policy !== 'object') throw new Error('Independent expected policy is required.');
  const w = new Writer(); w.put(encoder.encode('QWP1'));
  const exact = policy.expectedRequest instanceof ArrayBuffer;
  if (policy.expectedRequest !== undefined && !exact) throw new Error('Expected request must be binary.');
  w.uint(exact ? 0 : 1, 1);
  w.uint(policy.maxLifetimeSeconds, 8); w.uint(policy.minConfirmations, 8);
  w.uint(policy.minimumTotalSats, 8); w.uint(policy.maxObservationAgeSeconds, 8);
  w.text(policy.provider, 256);
  if (exact) {
    if (!policy.expectedRequest.byteLength || policy.expectedRequest.byteLength > 4096)
      throw new Error('Invalid expected request.');
    w.uint(policy.expectedRequest.byteLength, 4); w.put(new Uint8Array(policy.expectedRequest));
  } else {
    if (!['mainnet', 'signet'].includes(policy.network)) throw new Error('Independent expected network is required.');
    w.uint(policy.network === 'mainnet' ? 0 : 2, 1);
    w.text(policy.verifier, 256); w.text(policy.purpose, 64); w.text(policy.message, 4096);
  }
  return w.finish();
}
export function encodeEvidence(evidence) {
  if (!evidence || !['mainnet', 'signet'].includes(evidence.network) ||
      !Array.isArray(evidence.claims) || !evidence.claims.length || evidence.claims.length > 16)
    throw new Error('Invalid explorer evidence.');
  const w = new Writer(); w.put(encoder.encode('QWE1'));
  w.text(evidence.provider, 256); w.uint(evidence.observedAt, 8);
  w.uint(evidence.network === 'mainnet' ? 0 : 2, 1);
  for (const tip of [evidence.tipBefore, evidence.tipAfter]) {
    w.put(hex(tip.block, 32)); w.uint(tip.height, 8);
  }
  w.uint(evidence.claims.length, 2);
  for (const claim of evidence.claims) {
    w.put(hex(claim.txid, 32)); w.uint(claim.vout, 4);
    const status = ['unspent', 'spent', 'missing', 'unavailable', 'inconclusive'].indexOf(claim.status);
    if (status < 0 || typeof claim.inBestChain !== 'boolean' ||
        typeof claim.scriptPubKey !== 'string' || !/^(?:[0-9a-fA-F]{2}){0,25}$/.test(claim.scriptPubKey))
      throw new Error('Malformed claim observation.');
    w.uint(status, 1); w.uint(claim.amountSats, 8);
    const script = Uint8Array.from(claim.scriptPubKey.match(/../g) ?? [], item => parseInt(item, 16));
    w.uint(script.length, 2); w.put(script);
    w.uint(claim.confirmations, 8); w.uint(claim.inBestChain ? 1 : 0, 1);
  }
  return w.finish();
}
export function decodeVerification(buffer) {
  if (buffer.byteLength < 20) throw new Error('Truncated verification result.');
  const bytes = new Uint8Array(buffer), view = new DataView(buffer);
  if (decoder.decode(bytes.subarray(0, 4)) !== 'QWR1') throw new Error('Invalid verification result.');
  const contextId = view.getUint32(4), phase = ['empty', 'prepared', 'verified', 'finished'][bytes[8]];
  const cryptography = ['not_checked', 'valid', 'invalid'][bytes[9]];
  const policy = [undefined, 'matched', 'rejected', 'expired'][bytes[10]];
  const explorer = ['unavailable', 'reported_unspent', 'reported_spent', 'inconclusive'][bytes[11]];
  if (!phase || !cryptography || !policy || !explorer) throw new Error('Invalid verification outcome.');
  return { contextId, phase, cryptography, policy, explorer, authorizes: false,
    totalSats: view.getBigUint64(12).toString(),
    manifest: buffer.byteLength > 20 ? decodeInspection(buffer.slice(20)) : null };
}
