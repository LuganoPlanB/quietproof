import { instantiateReactor } from './runtime.mjs';

let reactor;
let initializing = false;
let operation;
let lastPreparedId = -1;
let poisoned = false;
self.onmessage = async ({ data }) => {
  const id = data?.id;
  try {
    if (!Number.isSafeInteger(id)) throw new Error('Invalid operation identifier.');
    if (poisoned) throw new Error('Worker is unusable; terminate and recreate it.');
    if (data.type === 'initialize') {
      if (initializing || reactor) throw new Error('Worker is already initialized.');
      if (!(data.bytes instanceof ArrayBuffer)) throw new Error('WASM bytes are required.');
      initializing = true;
      try { reactor = await instantiateReactor(data.bytes); }
      finally { initializing = false; }
      self.postMessage({ id, type: 'ready', abiVersion: 2 });
    } else if (data.type === 'createRequest') {
      if (!reactor) throw new Error('Worker is not initialized.');
      const bytes = reactor.createRequest(data.options);
      self.postMessage({ id, type: 'result', bytes }, [bytes]);
    } else if (data.type === 'inspectRequest' || data.type === 'inspectProof') {
      if (!reactor) throw new Error('Worker is not initialized.');
      const metadata = reactor.inspect(data.bytes, data.type === 'inspectProof');
      self.postMessage({ id, type: 'result', metadata }, [metadata.requestBytes]);
    } else if (data.type === 'inspectProofInput') {
      if (!reactor) throw new Error('Worker is not initialized.');
      operation = undefined; reactor.reset();
      // Inspection never establishes proof validity. The transferred proof stays
      // in this worker for both steps; no large copy returns to the UI.
      const metadata = reactor.inspect(data.bytes, true);
      let binding = 'not_checked';
      if (data.policy) {
        try {
          if (data.policy.expectedRequest) reactor.inspect(data.policy.expectedRequest, false);
          binding = reactor.prepare(data.bytes, data.policy).policy;
        } catch (error) {
          if (error.name === 'WorkerResetError') throw error;
          binding = error.name === 'UnsupportedError' ? 'unsupported' : 'rejected';
        } finally { reactor.reset(); }
      }
      self.postMessage({ id, type: 'result', metadata, binding }, [metadata.requestBytes]);
    } else if (data.type === 'prepare') {
      if (!reactor) throw new Error('Worker is not initialized.');
      operation = undefined;
      reactor.reset();
      if (id <= lastPreparedId) throw new Error('Preparation identifiers must increase.');
      lastPreparedId = id;
      const result = reactor.prepare(data.bytes, data.policy);
      operation = Object.freeze({ id, context: result.contextId, phase: 'prepared',
        token: `${id}:${result.contextId}:prepared` });
      self.postMessage({ id, type: 'result', ...result, operationId: id, phaseToken: operation.token,
        linearMemoryBytes: reactor.exports.memory.buffer.byteLength });
    } else if (data.type === 'verify' || data.type === 'evaluate') {
      if (!reactor || !operation || data.operationId !== operation.id || data.phaseToken !== operation.token ||
          operation.phase !== (data.type === 'verify' ? 'prepared' : 'verified'))
        throw new Error('Stale or substituted verification phase.');
      const current = operation; operation = undefined; // Consume before computation.
      const result = data.type === 'verify' ? reactor.verify(current.context) :
        reactor.evaluate(current.context, data.evidence);
      const token = `${current.id}:${current.context}:${result.phase}`;
      if (result.phase === 'verified') operation = Object.freeze({ ...current, phase: 'verified', token });
      const message = { id, type: 'result', ...result, operationId: current.id, phaseToken: token,
        linearMemoryBytes: reactor.exports.memory.buffer.byteLength };
      self.postMessage(message, result.manifest ? [result.manifest.requestBytes] : []);
    } else if (data.type === 'reset') {
      if (!reactor) throw new Error('Worker is not initialized.');
      operation = undefined; reactor.reset();
      self.postMessage({ id, type: 'reset', linearMemoryBytes: reactor.exports.memory.buffer.byteLength });
    } else if (data.type === 'smoke') {
      if (!reactor) throw new Error('Worker is not initialized.');
      const result = reactor.smoke();
      self.postMessage({ id, type: 'result', bytes: result }, [result]);
    } else { throw new Error('Unsupported worker operation.'); }
  } catch (error) {
    if (error.name === 'WorkerResetError') { poisoned = true; operation = undefined; }
    self.postMessage({ id, type: 'error', name: error.name, message: error.message,
      linearMemoryBytes: reactor?.exports.memory.buffer.byteLength ?? null });
  }
};
