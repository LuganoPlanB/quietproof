export const phaseLabel = Object.freeze({ reading: 'Reading bounded files', initializing: 'Initializing worker',
  preparing: 'Checking independent expected policy', verifying: 'Checking proof cryptography',
  fetching: 'Fetching fresh explorer observations', evaluating: 'Evaluating explorer observations' });

export function failureResult(error, progress = {}) {
  progress ??= {};
  const reasons = {
    policy_rejected: 'The expected request or policy was rejected, or its device-clock validity window expired. Choose the correct expectations or request a fresh proof.',
    invalid_manifest: 'The verified proof does not match the independently selected verification network or supported claim format.',
    verification_failed: 'Proof verification could not finish. The proof may be malformed or use an unsupported circuit, or this browser may lack resources.',
    worker_failed: 'The verification worker stopped. Retry, or use a supported browser with more memory.',
    timeout: 'Verification reached its time limit. Retry on a supported device.',
  };
  return { cryptography: progress.cryptography ?? 'not_checked',
    policy: error.code === 'policy_rejected' ? 'rejected' : 'not_checked',
    explorer: 'unavailable', reason: reasons[error.code] ?? error.message, online: false };
}

export function observationReasons(result) {
  if (!result) return [];
  if (result.reason) return [result.reason];
  if (result.cryptography !== 'valid') return ['Explorer checking requires valid cryptography and a matching independent policy.'];
  if (!result.online) return ['Offline check: no explorer observations were requested.'];
  if (result.providerError) return ['The selected explorer could not supply usable fresh observations. Check your connection or retry later.'];
  const labels = {
    funding_not_in_best_chain: 'A funding output is unconfirmed or no longer reported in the best chain.',
    changed_tip: 'The explorer tip changed during the bounded observations.',
    stale_observation: 'Observations became too old according to the device clock.',
    output_mismatch: 'The explorer output does not match the proof amount or script.',
    http_404: 'An expected funding output or transaction was not found.',
    http_429: 'The explorer rate limit prevented complete observations.',
    conflicting_status: 'The explorer returned conflicting funding statuses.',
    conflicting_outspend: 'The explorer returned inconsistent spend information.',
    cached_response: 'A cached response could not establish a fresh observation.',
  };
  const codes = new Set(result.provenance?.attempts.at(-1)?.reasons.map(r => r.code) ?? []);
  const reasons = [...codes].map(code => labels[code] ?? 'An explorer observation was missing, malformed or unavailable.');
  if (result.explorer === 'inconclusive' && !reasons.length)
    reasons.push('Observations did not meet the selected confirmation, amount or freshness limits.');
  if (result.explorer === 'reported_spent') reasons.push('The explorer reports a disclosed output as spent.');
  return reasons;
}
