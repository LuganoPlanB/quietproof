// Request feature rules. Canonical artifact validation remains owned by WASM.
import { encodeRequestOptions } from '../../wasm/codec.mjs';

export function selectionSummary(claims) {
  let total = 0n;
  const outpoints = new Set(), programs = new Set();
  for (const claim of claims) {
    if (!/^[1-9][0-9]*$/.test(claim.amountSats)) throw new Error('Invalid exact amount.');
    const amount = BigInt(claim.amountSats);
    if (amount > 2100000000000000n) throw new Error('Amount exceeds the Bitcoin supply.');
    const id = `${claim.txid}:${claim.vout}`;
    if (outpoints.has(id)) throw new Error('Duplicate output.');
    outpoints.add(id); programs.add(claim.program); total += amount;
  }
  if (claims.length > 16) throw new Error('Select at most 16 outputs.');
  if (programs.size > 1) throw new Error('Select outputs sharing one key fingerprint.');
  if (total > 2100000000000000n) throw new Error('Total exceeds the Bitcoin supply.');
  return { totalSats: total.toString(), keys: programs.size, count: claims.length };
}

export function validateForm(options) {
  const summary = selectionSummary(options.claims);
  if (!summary.count) throw new Error('Select at least one output.');
  if (!options.verifier.trim()) throw new Error('Enter the intended verifier.');
  if (!['proof-of-control', 'proof-of-funds'].includes(options.purpose)) throw new Error('Select a supported purpose.');
  if (!/^[1-9][0-9]*$/.test(String(options.lifetimeSeconds)) || BigInt(options.lifetimeSeconds) > 86400n)
    throw new Error('Lifetime must be a whole number from 1 to 86400 seconds.');
  encodeRequestOptions(options);
  return summary;
}

export function lookupError(error) {
  const messages = {
    unsupported_script: 'Unsupported address: use compressed-key P2PKH or native P2WPKH. Taproot, multisig, P2SH and P2WSH are unavailable.',
    wrong_network: 'The address does not match the selected network.',
    invalid_address: 'Check the address and its checksum.',
    duplicate_address: 'Enter each address once.',
    address_limit: 'Enter one or two addresses, one per line.',
    output_limit: 'This lookup exceeds the provider limit of 256 outputs. Try another address.',
    timeout: 'The explorer timed out. Try the lookup again.',
  };
  return messages[error?.code] ?? 'The explorer lookup failed. Check your connection or try again later. No outputs were retained.';
}
