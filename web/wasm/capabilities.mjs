import { loadWasmAsset } from './asset.mjs';

// Explicit, public capability lookup. It never receives a request, proof,
// receipt or provider URL, and always tears down its disposable worker.
export async function probeProofCapabilities({ wasmUrl, signal, fetch: fetcher = globalThis.fetch,
  workerFactory = () => new Worker(new URL('./worker.mjs', import.meta.url), { type: 'module' }),
  timeoutMs = 60000 } = {}) {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  if (signal?.aborted) cancel();
  const check = () => { if (controller.signal.aborted) throw Object.assign(new Error('Capability check cancelled.'), { name: 'AbortError' }); };
  let worker, timedOut = false;
  const timer = setTimeout(() => { timedOut = true; cancel(); }, timeoutMs);
  try {
    const bytes = await loadWasmAsset(wasmUrl, { fetch: fetcher, signal: controller.signal, check, label: 'capability' });
    check(); worker = workerFactory();
    const ready = await new Promise((resolve, reject) => {
      const abort = () => reject(Object.assign(new Error('Capability check cancelled.'), { name: 'AbortError' }));
      controller.signal.addEventListener('abort', abort, { once: true });
      const finish = (value, failed = false) => {
        controller.signal.removeEventListener('abort', abort);
        failed ? reject(value) : resolve(value);
      };
      worker.onmessage = ({ data }) => {
        if (data?.id === 1) finish(data);
      };
      worker.onerror = event => { event.preventDefault?.(); finish(new Error('Cannot check this verifier build.'), true); };
      worker.postMessage({ id: 1, type: 'initialize', bytes }, [bytes]);
    });
    check();
    if (ready.type !== 'ready' || ready.abiVersion !== 2 ||
        typeof ready.capabilities?.signaturePossession !== 'boolean')
      throw new Error('This verifier did not report its proof capabilities.');
    return Object.freeze({ keyKnowledge: ready.capabilities.keyKnowledge === true,
      signaturePossession: ready.capabilities.signaturePossession === true });
  } catch (error) {
    if (timedOut) throw new Error('Capability check timed out. Retry with the local verifier available.');
    throw error;
  } finally {
    clearTimeout(timer); signal?.removeEventListener('abort', cancel); worker?.terminate();
  }
}
