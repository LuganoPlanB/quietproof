// Feature-private orchestration. Only setupProvider wires this entry point.
import { createOperation, fail, hash, integer, status, LIMITS } from './esplora.mjs';
import { encodePolicy, MAX_ENVELOPE_BYTES } from '../../wasm/codec.mjs';

function script(claim) {
  if (!['p2wpkh', 'p2pkh'].includes(claim.scriptKind) || !/^[0-9a-f]{40}$/.test(claim.program)) fail('invalid_manifest');
  return claim.scriptKind === 'p2wpkh' ? `0014${claim.program}` : `76a914${claim.program}88ac`;
}
function freeze(value) {
  if (value && typeof value === 'object' && !(value instanceof ArrayBuffer)) {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
}

export function createVerification({ provider, config, fetcher, timeoutMs, workerFactory = () =>
  new Worker(new URL('../../wasm/worker.mjs', import.meta.url), { type: 'module' }) }) {
  // One live proof operation per selected adapter. A new operation consumes the
  // old one; dispose permanently invalidates a selection when the UI switches.
  let active, disposed = false, generation = 0;
  const dispose = () => { disposed = true; active?.abort('superseded'); };

  async function verify({ proof, wasmBytes, policy, signal, online = true, onProgress } = {}) {
    if (disposed) fail('disposed_provider');
    if (typeof online !== 'boolean') fail('invalid_mode');
    if (onProgress !== undefined && typeof onProgress !== 'function') fail('invalid_progress');
    if (!(proof instanceof ArrayBuffer) || !proof.byteLength || proof.byteLength > MAX_ENVELOPE_BYTES ||
        !(wasmBytes instanceof ArrayBuffer) || !wasmBytes.byteLength || wasmBytes.byteLength > 128 * 1024 * 1024)
      fail('invalid_binary');
    const expected = structuredClone(policy); // Independent caller policy, never proof metadata.
    encodePolicy(expected);
    if (online && expected.provider !== provider.endpoint) fail('provider_mismatch');
    // Take ownership immediately, before initialization can yield to the caller.
    const owned = structuredClone({ proof, wasmBytes }, { transfer: [proof, wasmBytes] });
    active?.abort('superseded');
    const controller = new AbortController(); active = controller;
    const currentGeneration = ++generation;
    const cancel = () => controller.abort('aborted');
    if (signal?.aborted) cancel();
    signal?.addEventListener('abort', cancel, { once: true });
    const check = () => {
      if (controller.signal.aborted || currentGeneration !== generation || disposed)
        fail(controller.signal.reason === 'superseded' || disposed ? 'superseded' : 'aborted');
    };
    const progress = (phase, result = {}) => {
      check();
      onProgress?.(Object.freeze({ phase, cryptography: result.cryptography ?? 'not_checked',
        policy: result.policy ?? 'not_checked', expiresAt: result.manifest?.expiresAt ?? null }));
      check();
    };
    let worker, sequence = 0;
    // This bounds an unresponsive worker, including synchronous verification.
    const timer = setTimeout(() => controller.abort('timeout'), 300000);
    function call(type, fields = {}, transfer = []) {
      check();
      const id = ++sequence;
      return new Promise((resolve, reject) => {
        const cleanup = () => {
          worker.removeEventListener('message', message); worker.removeEventListener('error', error);
          worker.removeEventListener('messageerror', error); controller.signal.removeEventListener('abort', abort);
        };
        const finish = (value, failure) => { cleanup(); failure ? reject(value) : resolve(value); };
        const error = () => finish(Object.assign(new Error('Verification worker failed.'), { code: 'worker_failed' }), true);
        const abort = () => { worker.terminate(); finish(Object.assign(new Error('Verification cancelled.'),
          { code: controller.signal.reason === 'timeout' ? 'timeout' : controller.signal.reason === 'superseded' ? 'superseded' : 'aborted' }), true); };
        const message = ({ data }) => {
          if (data?.id !== id) return;
          if (data.type === 'error') finish(Object.assign(new Error('Proof or expected policy was rejected.'),
            { code: data.name === 'PolicyError' ? 'policy_rejected' : 'verification_failed' }), true);
          else finish(data, false);
        };
        worker.addEventListener('message', message); worker.addEventListener('error', error);
        worker.addEventListener('messageerror', error); controller.signal.addEventListener('abort', abort, { once: true });
        try { worker.postMessage({ id, type, ...fields }, transfer); }
        catch { error(); }
      });
    }
    let operation;
    try {
      progress('initializing'); worker = workerFactory();
      const ready = await call('initialize', { bytes: owned.wasmBytes }, [owned.wasmBytes]);
      if (ready.type !== 'ready' || ready.abiVersion !== 2) fail('invalid_worker');
      progress('preparing');
      const prepared = await call('prepare', { bytes: owned.proof, policy: expected }, [owned.proof]);
      if (prepared.phase !== 'prepared' || prepared.policy !== 'matched' || prepared.cryptography !== 'not_checked') fail('invalid_worker');
      progress('verifying', prepared);
      const verified = await call('verify', { operationId: prepared.operationId, phaseToken: prepared.phaseToken });
      check();
      if (verified.policy !== 'matched' || verified.authorizes !== false) fail('invalid_worker');
      if (verified.cryptography !== 'valid') {
        if (verified.cryptography !== 'invalid') fail('invalid_worker');
        return freeze({ ...verified, explorer: 'unavailable', provenance: null });
      }
      if (verified.phase !== 'verified' || !verified.manifest || verified.manifest.network !== provider.network ||
          !Array.isArray(verified.manifest.claims) || !verified.manifest.claims.length || verified.manifest.claims.length > 16)
        fail('invalid_manifest');
      const manifest = structuredClone(verified.manifest), seen = new Set();
      for (const claim of manifest.claims) {
        hash(claim.txid); integer(claim.vout, 0xffffffff); script(claim);
        if (!/^[1-9][0-9]{0,15}$/.test(claim.amountSats) || BigInt(claim.amountSats) > 2100000000000000n) fail('invalid_manifest');
        const id = `${claim.txid}:${claim.vout}`; if (seen.has(id)) fail('invalid_manifest'); seen.add(id);
      }
      if (!online) return freeze({ ...verified, explorer: 'unavailable', provenance: null });
      progress('fetching', verified);
      operation = createOperation(config, fetcher, timeoutMs, controller.signal, true);
      const { get } = operation;
      const provenance = { provider: provider.endpoint, network: provider.network, trust: provider.trust,
        atomic: false, clock: 'untrusted_browser', attempts: [] };
      let evidence;
      try {
        if ((await get('/block-height/0', false, 128)).trim() !== config.genesis) fail('wrong_genesis');
        for (let attempt = 0; attempt < 2; attempt++) {
          const observedAt = Math.floor(Date.now() / 1000), reasons = [];
          const tip = async () => {
            const block = hash((await get('/blocks/tip/hash', false, 128)).trim());
            const info = await get(`/block/${block}`);
            if (info?.id !== block) fail('invalid_tip');
            return { block, height: integer(info.height, 0xffffffff) };
          };
          const tipBefore = await tip(), transactions = new Map(), memberships = new Map();
          const claims = [];
          for (const claim of manifest.claims) {
            const observation = { txid: claim.txid, vout: claim.vout, status: 'inconclusive',
              amountSats: '0', scriptPubKey: '', confirmations: 0, inBestChain: false };
            try {
              if (!transactions.has(claim.txid)) {
                transactions.set(claim.txid, (async () => {
                  const tx = await get(`/tx/${claim.txid}`);
                  if (!tx || tx.txid !== claim.txid || !Array.isArray(tx.vout) || !tx.vout.length || tx.vout.length > LIMITS.transactionOutputs)
                    fail('invalid_transaction');
                  const funding = status(tx.status), fresh = status(await get(`/tx/${claim.txid}/status`));
                  if (JSON.stringify(funding) !== JSON.stringify(fresh)) fail('conflicting_status');
                  return { tx, funding };
                })());
              }
              const { tx, funding } = await transactions.get(claim.txid), output = tx.vout[claim.vout];
              if (!output) { observation.status = 'missing'; fail('missing_output'); }
              const amount = integer(output.value, 2100000000000000, 1);
              if (String(amount) !== claim.amountSats || output.scriptpubkey !== script(claim)) fail('output_mismatch');
              observation.amountSats = String(amount); observation.scriptPubKey = output.scriptpubkey;
              const outspend = await get(`/tx/${claim.txid}/outspend/${claim.vout}`);
              if (!outspend || typeof outspend.spent !== 'boolean') fail('invalid_outspend');
              if (outspend.spent) {
                hash(outspend.txid); integer(outspend.vin, 0xffffffff); status(outspend.status);
              } else if (outspend.txid !== undefined || outspend.vin !== undefined || outspend.status !== undefined) fail('conflicting_outspend');
              if (funding.confirmed) {
                if (!memberships.has(funding.blockHash)) {
                  memberships.set(funding.blockHash, (async () => {
                    const membership = await get(`/block/${funding.blockHash}/status`);
                    if (typeof membership?.in_best_chain !== 'boolean') fail('invalid_membership');
                    const blockAtHeight = hash((await get(`/block-height/${funding.blockHeight}`, false, 128)).trim());
                    return { ...membership, blockAtHeight, height: funding.blockHeight };
                  })());
                }
                const membership = await memberships.get(funding.blockHash);
                observation.inBestChain = membership.in_best_chain && membership.blockAtHeight === funding.blockHash &&
                  membership.height === funding.blockHeight && funding.blockHeight <= tipBefore.height;
                if (observation.inBestChain) observation.confirmations = tipBefore.height - funding.blockHeight + 1;
              }
              observation.status = outspend.spent ? 'spent' : 'unspent';
              if (!observation.inBestChain) reasons.push({ txid: claim.txid, vout: claim.vout, code: 'funding_not_in_best_chain' });
            } catch (error) {
              check(); operation.check();
              if (error.code === 'http_404' || error.code === 'missing_output') observation.status = 'missing';
              else observation.status = 'inconclusive';
              reasons.push({ txid: claim.txid, vout: claim.vout, code: error.code ?? 'invalid_observation' });
            }
            claims.push(observation);
          }
          const tipAfter = await tip();
          evidence = { provider: provider.endpoint, network: provider.network, observedAt, tipBefore, tipAfter, claims };
          const changed = tipBefore.block !== tipAfter.block || tipBefore.height !== tipAfter.height;
          if (changed) reasons.push({ code: 'changed_tip' });
          const now = Math.floor(Date.now() / 1000);
          if (now < observedAt || BigInt(now - observedAt) > BigInt(expected.maxObservationAgeSeconds)) reasons.push({ code: 'stale_observation' });
          provenance.attempts.push({ observedAt, completedAt: now, tipBefore, tipAfter, reasons });
          if (!changed || attempt === 1) break;
          // Discard every claim/status cache and fetch again after a changed tip.
        }
      } catch (error) {
        check();
        return freeze({ ...verified, explorer: 'unavailable', provenance, providerError: error.code ?? 'invalid_observation' });
      }
      check();
      progress('evaluating', verified);
      const evaluated = await call('evaluate', { operationId: verified.operationId, phaseToken: verified.phaseToken, evidence });
      check();
      if (evaluated.phase !== 'finished' || evaluated.cryptography !== 'valid' || evaluated.authorizes !== false ||
          !['reported_unspent', 'reported_spent', 'inconclusive'].includes(evaluated.explorer)) fail('invalid_worker');
      return freeze({ ...evaluated, manifest: verified.manifest, provenance });
    } finally {
      operation?.close(); worker?.terminate(); clearTimeout(timer);
      signal?.removeEventListener('abort', cancel); if (active === controller) active = undefined;
    }
  }
  return { verify, dispose };
}
