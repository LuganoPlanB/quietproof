// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Feature entry point. Construction/inspection performs no network access.
import { NETWORKS, LIMITS, hex, fail, integer, hash, status, createOperation } from './esplora.mjs';
import { createVerification } from './verification.mjs';
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
async function addressScript(input, config, crypto) {
  if (typeof input !== 'string' || input.length < 14 || input.length > 90 || /\s/.test(input)) fail('invalid_address');
  let address = input, program, scriptKind;
  if (/^(bc|tb|bcrt)1/i.test(input)) {
    if (input !== input.toLowerCase() && input !== input.toUpperCase()) fail('invalid_address');
    address = input.toLowerCase();
    const separator = address.lastIndexOf('1'), hrp = address.slice(0, separator);
    if (hrp !== config.hrp) fail('wrong_network');
    const data = [...address.slice(separator + 1)].map(c => BECH32.indexOf(c));
    if (data.length < 7 || data.some(n => n < 0)) fail('invalid_address');
    const expanded = [...hrp].map(c => c.charCodeAt(0) >> 5)
      .concat(0, [...hrp].map(c => c.charCodeAt(0) & 31), data);
    const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let checksum = 1;
    for (const n of expanded) {
      const top = checksum >>> 25;
      checksum = ((checksum & 0x1ffffff) << 5) ^ n;
      for (let i = 0; i < 5; i++) if ((top >>> i) & 1) checksum ^= generators[i];
    }
    if (data[0] !== 0) fail('unsupported_script');
    if ((checksum >>> 0) !== 1) fail('invalid_address');
    let accumulator = 0, bits = 0; const bytes = [];
    for (const n of data.slice(1, -6)) {
      accumulator = ((accumulator << 5) | n) & 0xffff;
      bits += 5;
      if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
    }
    if (bits >= 5 || ((accumulator << (8 - bits)) & 255)) fail('invalid_address');
    if (bytes.length !== 20) fail('unsupported_script');
    program = hex(bytes); scriptKind = 'p2wpkh';
  } else {
    if (input.length > 35) fail('invalid_address');
    let n = 0n;
    for (const c of input) { const digit = BASE58.indexOf(c); if (digit < 0) fail('invalid_address'); n = n * 58n + BigInt(digit); }
    const bytes = [];
    while (n) { bytes.unshift(Number(n & 255n)); n >>= 8n; }
    for (const c of input) { if (c !== '1') break; bytes.unshift(0); }
    if (bytes.length !== 25) fail('invalid_address');
    const payload = Uint8Array.from(bytes.slice(0, 21));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', await crypto.subtle.digest('SHA-256', payload)));
    if (bytes.slice(21).some((b, i) => b !== digest[i])) fail('invalid_address');
    if ([5, 196].includes(bytes[0])) fail('unsupported_script');
    if (bytes[0] !== config.version) fail('wrong_network');
    program = hex(payload.slice(1)); scriptKind = 'p2pkh';
  }
  return Object.freeze({ address, scriptKind, program,
    scriptPubKey: scriptKind === 'p2wpkh' ? `0014${program}` : `76a914${program}88ac` });
}

export function setupProvider({ network, fetch: fetcher = globalThis.fetch,
  crypto = globalThis.crypto, timeoutMs = LIMITS.timeoutMs, workerFactory } = {}) {
  if (!Object.hasOwn(NETWORKS, network)) fail('unsupported_network');
  if (typeof fetcher !== 'function' || !crypto?.subtle) fail('missing_capability');
  integer(timeoutMs, LIMITS.timeoutMs, 1);
  const config = NETWORKS[network];
  const provider = Object.freeze({ name: 'Blockstream Esplora', network, endpoint: config.endpoint,
    privacy: 'Lookup sends the selected addresses and funding transaction IDs to this public provider. Testnet addresses also encode signet; the endpoint selects the network.',
    trust: 'Explorer observations are trusted, non-atomic reports; they do not establish strict native chain validity.', limits: LIMITS });
  let disposed = false, discoveryController;

  async function discover({ addresses, signal } = {}) {
    if (disposed) fail('disposed_provider');
    discoveryController?.abort('superseded');
    // Snapshot inputs synchronously: callers cannot change an in-flight operation.
    if (!Array.isArray(addresses) || !addresses.length || addresses.length > LIMITS.addresses) fail('address_limit');
    const inputs = [...addresses];
    const controller = new AbortController(); discoveryController = controller;
    const cancel = () => controller.abort('aborted');
    if (signal?.aborted) cancel();
    signal?.addEventListener('abort', cancel, { once: true });
    const operation = createOperation(config, fetcher, timeoutMs, controller.signal);
    const { get, check } = operation;
    try {
      check();
      const decoded = [];
      for (const input of inputs) { decoded.push(await addressScript(input, config, crypto)); check(); }
      if (new Set(decoded.map(a => a.address)).size !== decoded.length) fail('duplicate_address');
      // Identity is mandatory for this pinned provider; never fall back on errors.
      if ((await get('/block-height/0', false, 128)).trim() !== config.genesis) fail('wrong_genesis');
      const pending = [], seen = new Set();
      for (const address of decoded) {
        const outputs = await get(`/address/${address.address}/utxo`);
        if (!Array.isArray(outputs)) fail('malformed_utxos');
        if (pending.length + outputs.length > LIMITS.outputs) fail('output_limit');
        for (const output of outputs) {
          if (!output || typeof output !== 'object') fail('malformed_utxos');
          const txid = hash(output.txid), vout = integer(output.vout, 0xffffffff);
          const amount = integer(output.value, 2100000000000000, 1), funding = status(output.status);
          const id = `${txid}:${vout}`;
          if (seen.has(id)) fail('duplicate_outpoint');
          seen.add(id); pending.push({ address, txid, vout, amount, funding });
        }
      }
      const transactions = new Map(), claims = [];
      for (const output of pending) {
        if (!transactions.has(output.txid)) {
          const tx = await get(`/tx/${output.txid}`);
          if (!tx || tx.txid !== output.txid || !Array.isArray(tx.vout) || !tx.vout.length || tx.vout.length > LIMITS.transactionOutputs)
            fail('invalid_transaction');
          transactions.set(output.txid, { tx, funding: status(tx.status) });
        }
        const { tx, funding } = transactions.get(output.txid), vout = tx.vout[output.vout];
        if (!vout || integer(vout.value, 2100000000000000, 1) !== output.amount ||
            vout.scriptpubkey !== output.address.scriptPubKey) fail('output_mismatch');
        if (JSON.stringify(funding) !== JSON.stringify(output.funding)) fail('conflicting_status');
        claims.push(Object.freeze({ txid: output.txid, vout: output.vout, amountSats: String(output.amount),
          scriptKind: output.address.scriptKind, program: output.address.program,
          scriptPubKey: output.address.scriptPubKey, address: output.address.address, funding }));
      }
      check();
      return Object.freeze({ provider, claims: Object.freeze(claims),
        chainStatus: 'unavailable', requiresFreshVerification: true });
    } finally {
      operation.close(); signal?.removeEventListener('abort', cancel);
      if (discoveryController === controller) discoveryController = undefined;
    }
  }
  const verification = createVerification({ provider, config, fetcher, timeoutMs, workerFactory });
  const dispose = () => { disposed = true; discoveryController?.abort('superseded'); verification.dispose(); };
  return Object.freeze({ provider, discover, verify: verification.verify, dispose });
}
