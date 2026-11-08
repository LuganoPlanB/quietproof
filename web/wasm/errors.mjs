// Map trusted worker error categories to bounded public guidance. Never echo
// arbitrary worker/proof text into product errors or let it choose another mode.
export function unsupportedArtifactError(data) {
  if (data?.name !== 'UnsupportedError') return null;
  if (data.message?.includes('unsupported_posc_v3')) return Object.assign(
    new Error('PoSC v3 is unsupported. Issue a fresh v4 request, signature, receipt and proof.'), { code: 'unsupported_posc_v3' });
  if (data.message?.includes('signature_mode_disabled')) return Object.assign(
    new Error('Signature possession is unavailable in this verifier build. Keep the selected mode and use a compatible verifier.'), { code: 'signature_mode_disabled' });
  return Object.assign(new Error('The signing profile, artifact version or circuit is unsupported by this verifier build. Keep the original expected request and use a compatible verifier.'),
    { code: 'unsupported_artifact' });
}
