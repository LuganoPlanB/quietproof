// Public signing material only. Signatures, keys and wallet RPC stay outside the page.
const encoder = new TextEncoder();
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

export async function signingMaterial(bytes, metadata, claims, crypto = globalThis.crypto) {
  if (metadata.proofMode !== 'signature-possession') return null;
  if (!(bytes instanceof ArrayBuffer) || new Uint8Array(bytes)[4] !== 4 ||
      metadata.statementVersion !== 4 || !['mainnet', 'signet'].includes(metadata.network))
    throw new Error('Signing instructions require a current v4 request.');
  const profile = metadata.signatureProfileName;
  const legacy = profile === 'bitcoin-message-ecdsa-v1';
  if ((!legacy && profile !== 'bip322-ecdsa-v1') ||
      !['p2pkh', 'p2wpkh'].includes(metadata.signingKind) || (legacy && metadata.signingKind !== 'p2pkh'))
    throw new Error('Unsupported wallet signing procedure.');
  const claim = claims.find(c => c.scriptKind === metadata.signingKind &&
    c.program === metadata.claims[0].program && /^[a-zA-Z0-9]+$/.test(c.address ?? ''));
  if (!claim) throw new Error('The signing address is missing from the selected outputs.');
  const tag = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode('QuietProof/statement/v4')));
  const preimage = new Uint8Array(64 + bytes.byteLength);
  preimage.set(tag); preimage.set(tag, 32); preimage.set(new Uint8Array(bytes), 64);
  const message = 'quietproof:signature:v4:' + hex(new Uint8Array(await crypto.subtle.digest('SHA-256', preimage)));
  const simple = !legacy && metadata.signingKind === 'p2wpkh';
  const cli = `bitcoin-cli${metadata.network === 'signet' ? ' -signet' : ''} -rpcconnect=127.0.0.1`;
  return Object.freeze({ message, address: claim.address, legacy, simple,
    format: legacy ? 'bitcoin-message' : simple ? 'bip322-simple' : 'bip322-full',
    label: legacy ? 'Bitcoin Signed Message (legacy)' : simple ? 'BIP322 Simple' : 'BIP322 Full',
    network: metadata.network, port: metadata.network === 'signet' ? 38332 : 8332,
    command: legacy || simple ? `${cli} signmessage '${claim.address}' '${message}'` : null });
}
