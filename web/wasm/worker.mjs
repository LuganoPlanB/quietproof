import { instantiateReactor } from './runtime.mjs';

let reactor;
let initializing = false;
self.onmessage = async ({ data }) => {
  const id = data?.id;
  try {
    if (!Number.isSafeInteger(id)) throw new Error('Invalid operation identifier.');
    if (data.type === 'initialize') {
      if (initializing || reactor) throw new Error('Worker is already initialized.');
      if (!(data.bytes instanceof ArrayBuffer)) throw new Error('WASM bytes are required.');
      initializing = true;
      try { reactor = await instantiateReactor(data.bytes); }
      finally { initializing = false; }
      self.postMessage({ id, type: 'ready', abiVersion: 1 });
    } else if (data.type === 'smoke') {
      if (!reactor) throw new Error('Worker is not initialized.');
      const result = reactor.smoke();
      self.postMessage({ id, type: 'result', bytes: result }, [result]);
    } else { throw new Error('Unsupported worker operation.'); }
  } catch (error) {
    self.postMessage({ id, type: 'error', name: error.name, message: error.message });
  }
};
