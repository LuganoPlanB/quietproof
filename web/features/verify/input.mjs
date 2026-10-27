import { MAX_ENVELOPE_BYTES, encodePolicy } from '../../wasm/codec.mjs';
import { setupProvider } from '../provider/discovery.mjs';

export function preflight(file, kind) {
  const maximum = kind === 'proof' ? MAX_ENVELOPE_BYTES : 4096;
  const suffix = kind === 'proof' ? '.qpf' : '.qpr';
  if (!file || typeof file.name !== 'string' || !file.name.toLowerCase().endsWith(suffix))
    throw new Error(`Choose a ${suffix} ${kind} file.`);
  if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > maximum)
    throw new Error(`${kind === 'proof' ? 'Proof' : 'Request'} size must be from 1 to ${maximum} bytes.`);
}

export function expectedPolicy(options, expectedRequest) {
  if (options.mode === 'none') return undefined;
  if (!['request', 'explicit'].includes(options.mode)) throw new Error('Choose an expected policy.');
  const policy = { maxLifetimeSeconds: '86400', minConfirmations: '1', minimumTotalSats: '0',
    maxObservationAgeSeconds: '300', provider: 'offline', ...options };
  if (options.mode === 'request') {
    if (!(expectedRequest instanceof ArrayBuffer)) throw new Error('Choose the independent expected .qpr request.');
    policy.expectedRequest = expectedRequest;
  } else {
    if (!options.verifier?.trim()) throw new Error('Enter the expected verifier.');
    if (!['proof-of-control', 'proof-of-funds'].includes(options.purpose)) throw new Error('Choose the expected purpose.');
    if (!options.confirmed) throw new Error('Confirm the independently chosen message and policy.');
  }
  encodePolicy(policy); // Validate independent fields before reading the proof.
  if (BigInt(policy.maxObservationAgeSeconds) < 1n || BigInt(policy.maxObservationAgeSeconds) > 300n)
    throw new Error('Observation age must be a whole number from 1 to 300 seconds.');
  if (BigInt(policy.minimumTotalSats) > 2100000000000000n)
    throw new Error('Minimum total exceeds the Bitcoin supply.');
  return policy;
}

// Each import owns a fresh worker and bounded asset stream. File bytes are
// transferred, never encoded as JSON or copied back to the main thread.
export function setupProofInput({ wasmUrl, fetch: fetcher = globalThis.fetch,
  workerFactory = () => new Worker(new URL('../../wasm/worker.mjs', import.meta.url), { type: 'module' }),
  timeoutMs = 60000, verificationTimeoutMs = 300000, providerFactory = setupProvider } = {}) {
  let active, disposed = false;
  const aborted = reason => Object.assign(new Error('Import cancelled.'), { name: 'AbortError', code: reason === 'timeout' ? 'timeout' : 'aborted' });
  function cancel() { active?.abort(); }
  async function run({ proof, request, options, online = false, selectedNetwork, onProgress }, verifying = false) {
    if (disposed) throw new Error('Proof tools are closed.');
    cancel();
    preflight(proof, 'proof');
    if (options.mode === 'request') preflight(request, 'request');
    // Snapshot policy before asynchronous reads. Never derive it from metadata.
    const selected = structuredClone(options);
    if (verifying && selected.mode === 'none') throw new Error('Select an independent expected policy before verification.');
    if (verifying && !['mainnet', 'signet'].includes(selectedNetwork)) throw new Error('Choose the verification network independently.');
    if (typeof online !== 'boolean') throw new Error('Choose offline or explorer checking.');
    const controller = new AbortController(); active = controller;
    let worker, adapter, pending, sequence = 0;
    function check() { if (controller.signal.aborted) throw aborted(controller.signal.reason); }
    const abort = () => { worker?.terminate(); adapter?.dispose(); pending?.reject(aborted(controller.signal.reason)); pending = undefined; };
    controller.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => controller.abort('timeout'), verifying ? verificationTimeoutMs : timeoutMs);
    async function readFile(file) {
      check();
      let rejectAbort;
      const interrupted = new Promise((_, reject) => { rejectAbort = () => reject(aborted(controller.signal.reason)); });
      controller.signal.addEventListener('abort', rejectAbort, { once: true });
      try { return await Promise.race([file.arrayBuffer(), interrupted]); }
      finally { controller.signal.removeEventListener('abort', rejectAbort); }
    }
    function call(type, data = {}, transfer = []) {
      check();
      return new Promise((resolve, reject) => {
        const id = ++sequence; pending = { id, resolve, reject };
        try { worker.postMessage({ id, type, ...data }, transfer); }
        catch (error) { pending = undefined; reject(error); }
      });
    }
    try {
      if (verifying) { onProgress?.({ phase: 'reading', cryptography: 'not_checked', policy: 'not_checked' }); check(); }
      const requestBytes = selected.mode === 'request' ? await readFile(request) : undefined;
      if (requestBytes && (!(requestBytes instanceof ArrayBuffer) || requestBytes.byteLength !== request.size))
        throw new Error('Request read failed.');
      check(); const policy = expectedPolicy(selected, requestBytes);
      const bytes = await readFile(proof); check();
      if (!(bytes instanceof ArrayBuffer) || bytes.byteLength !== proof.size) throw new Error('Proof read failed.');
      const response = await fetcher(wasmUrl, { signal: controller.signal, credentials: 'omit' }); check();
      const maximum = 8 * 1024 * 1024;
      if (!response.ok || Number(response.headers.get('content-length')) > maximum) throw new Error('Could not load proof tools.');
      const reader = response.body?.getReader();
      if (!reader) throw new Error('This browser cannot load proof tools.');
      const chunks = []; let size = 0;
      try {
        while (true) {
          const { done, value } = await reader.read(); check();
          if (done) break;
          size += value.byteLength;
          if (size > maximum) throw new Error('Proof tools exceed the supported download size.');
          chunks.push(value);
        }
      } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
      const wasm = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { wasm.set(chunk, offset); offset += chunk.byteLength; }
      if (verifying) {
        check();
        adapter = providerFactory({ network: selectedNetwork, workerFactory });
        const outcome = await adapter.verify({ proof: bytes, wasmBytes: wasm.buffer,
          policy: { ...policy, provider: online ? adapter.provider.endpoint : '' },
          signal: controller.signal, online, onProgress: event => { check(); onProgress?.(event); } });
        check();
        return { ...outcome, metadata: outcome.manifest, selectedProvider: adapter.provider,
          online, checkedAt: Math.floor(Date.now() / 1000), expected: { minConfirmations: policy.minConfirmations,
            minimumTotalSats: policy.minimumTotalSats, maxObservationAgeSeconds: policy.maxObservationAgeSeconds } };
      }
      check(); worker = workerFactory();
      worker.onmessage = ({ data }) => {
        if (!pending || data?.id !== pending.id || controller.signal.aborted) return;
        const current = pending; pending = undefined;
        if (data.type === 'error') current.reject(new Error('Cannot decode this proof. It may be malformed, truncated, unsupported, or exceed browser resources.'));
        else current.resolve(data);
      };
      worker.onerror = event => { event.preventDefault?.(); pending?.reject(new Error('Proof tools stopped. Retry with a supported browser.')); pending = undefined; };
      await call('initialize', { bytes: wasm.buffer }, [wasm.buffer]);
      const transfer = requestBytes ? [bytes, requestBytes] : [bytes];
      const result = await call('inspectProofInput', { bytes, policy }, transfer); check();
      if (result.metadata?.verified !== false) throw new Error('Invalid inspection response.');
      return { metadata: result.metadata, binding: result.binding, cryptography: 'not_checked', explorer: 'unavailable' };
    } catch (error) {
      if (controller.signal.aborted) throw aborted(controller.signal.reason);
      throw error;
    } finally {
      clearTimeout(timer); controller.signal.removeEventListener('abort', abort);
      worker?.terminate(); adapter?.dispose(); if (active === controller) active = undefined;
    }
  }
  return { inspect: input => run(input), verify: input => run(input, true), cancel,
    dispose() { disposed = true; cancel(); } };
}
