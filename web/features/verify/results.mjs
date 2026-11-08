export const phaseLabel = Object.freeze({ reading: 'Reading bounded files', initializing: 'Initializing worker',
  preparing: 'Checking independent expected policy', verifying: 'Checking proof cryptography',
  fetching: 'Fetching fresh explorer observations', evaluating: 'Evaluating explorer observations' });

export function claimDetails(metadata) {
  if (metadata?.proofMode === 'signature-possession') return {
    label: 'Signature possession · request-bound authorization',
    meaning: 'Knowledge of a signature authorizing the exact retained request. This does not prove knowledge of the private key. The signature can be delegated for that same request; proof creation time does not establish signing time.',
    disclosure: 'The native prover receives the signature and public key as private witness. The verifier receives the public .qpf proof and .qpr request. Keep .qpa authorization receipts private and outside this page.',
  };
  return { label: 'Private-key knowledge',
    meaning: 'Knowledge of the private scalar for the disclosed key fingerprint. Key access may be shared or temporary.',
    disclosure: 'Private keys stay in native proving tools. The verifier receives the public proof and request.',
  };
}

export function fundsEvidenceLabel(result) {
  return result?.cryptography === 'valid' && result?.policy === 'matched' &&
    result?.fundsEvidence?.qualifiedAtCheck === true
    ? 'Provider-qualified at check time (trusted, non-atomic explorer)'
    : 'Not established by this check';
}

// A deliberately small public report. Never spread a worker result, binary
// artifact, receipt, witness, hidden public key or arbitrary metadata into it.
export function publicResultReport(result) {
  if (!result || !['valid', 'invalid', 'not_checked'].includes(result.cryptography))
    throw new Error('No completed public result to export.');
  const metadata = result.metadata;
  return {
    format: 'quietproof-public-result-v1', cryptography: result.cryptography,
    policy: result.policy, explorer: result.explorer, authorizes: false,
    fundsEvidence: { label: fundsEvidenceLabel(result), provider: result.fundsEvidence?.provider ?? null,
      qualifiedAtCheck: result.cryptography === 'valid' && result.policy === 'matched' && result.fundsEvidence?.qualifiedAtCheck === true,
      trust: 'trusted_explorer_non_atomic', validatedNode: false },
    claim: metadata ? { proofMode: metadata.proofMode ?? 'key-knowledge',
      signatureProfile: metadata.signatureProfile ?? null, signatureProfileVersion: metadata.signatureProfileVersion ?? null,
      signatureProfileName: metadata.signatureProfileName ?? null, statementVersion: metadata.statementVersion ?? null,
      signingKind: metadata.signingKind ?? null,
      network: metadata.network, verifier: metadata.verifier, purpose: metadata.purpose,
      nonce: metadata.nonce, messageHash: metadata.messageHash, notBefore: metadata.notBefore,
      expiresAt: metadata.expiresAt, claims: metadata.claims.map(({ txid, vout, amountSats, scriptKind, program }) =>
        ({ txid, vout, amountSats, scriptKind, program })) } : null,
    checkedAt: result.checkedAt ?? null,
    limits: result.expected ? { minConfirmations: result.expected.minConfirmations,
      minimumTotalSats: result.expected.minimumTotalSats,
      maxObservationAgeSeconds: result.expected.maxObservationAgeSeconds } : null,
    observations: result.provenance ? { provider: result.provenance.provider, atomic: false,
      attempts: result.provenance.attempts.map(({ observedAt, completedAt, tipBefore, tipAfter, reasons }) =>
        ({ observedAt, completedAt, tipBefore: { block: tipBefore.block, height: tipBefore.height },
          tipAfter: { block: tipAfter.block, height: tipAfter.height },
          reasons: reasons.map(({ code, txid, vout }) => ({ code, txid, vout })) })) } : null,
    limitations: ['Editable local report; independently verify the public proof and retained expected request.',
      'Explorer observations are trusted and non-atomic, not validated-node chain evidence.',
      'No acceptance authority or global replay prevention. Local history is editable and origin-scoped.',
      'Device clocks are untrusted; a check does not establish present ownership, exclusivity or solvency.'],
  };
}

export function failureResult(error, progress = {}) {
  progress ??= {};
  const reasons = {
    policy_rejected: 'The expected request or policy was rejected, or its device-clock validity window expired. Choose the correct expectations or request a fresh proof.',
    invalid_manifest: 'The verified proof does not match the independently selected verification network or supported claim format.',
    verification_failed: 'Proof verification could not finish. The proof may be malformed or use an unsupported circuit, or this browser may lack resources. Retry on a supported desktop with more available memory.',
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
