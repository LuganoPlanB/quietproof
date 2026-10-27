import { encodeRequestOptions, decodeInspection, MAX_ENVELOPE_BYTES,
  encodePolicy, encodeEvidence, decodeVerification } from './codec.mjs';
// Minimal WASI preview1 adapter. Time is an untrusted browser observation.
const EFAULT = 21;
const EINVAL = 28;
const EIO = 29;
const IMPORTS = ['clock_time_get', 'fd_close', 'fd_seek', 'fd_write', 'random_get'];
const EXPORTS = ['_initialize', 'memory', 'quietproof_wasm_abi_version',
  'quietproof_wasm_alloc', 'quietproof_wasm_free', 'quietproof_wasm_smoke',
  'quietproof_wasm_create_request', 'quietproof_wasm_inspect',
  'quietproof_wasm_result_data', 'quietproof_wasm_result_size',
  'quietproof_wasm_error_data', 'quietproof_wasm_error_size',
  'quietproof_wasm_prepare', 'quietproof_wasm_verify',
  'quietproof_wasm_evaluate', 'quietproof_wasm_reset'].sort();

export class CapabilityError extends Error {
  constructor(message) { super(message); this.name = 'CapabilityError'; }
}

// v128.const requires WebAssembly SIMD even when a particular build's optimizer
// happens to emit only scalar instructions for the small bootstrap operation.
const SIMD_PROBE = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0,
  1, 5, 1, 96, 0, 1, 123, 3, 2, 1, 0, 10, 22, 1, 20, 0, 253, 12,
  ...Array(16).fill(0), 11]);

export function requireCapabilities(host = globalThis) {
  if (typeof host.WebAssembly?.validate !== 'function' ||
      !host.WebAssembly.validate(SIMD_PROBE))
    throw new CapabilityError('WebAssembly SIMD is required by this build.');
  if (typeof host.crypto?.getRandomValues !== 'function')
    throw new CapabilityError('Secure browser randomness is unavailable.');
  if (typeof host.performance?.now !== 'function' || typeof host.Date?.now !== 'function')
    throw new CapabilityError('Browser realtime and monotonic clocks are required.');
}

// The host argument is for adapter tests. The production worker never accepts
// host callbacks, nonce seeds or a clock from messages.
export function createWasiImports(getMemory, host = globalThis) {
  let diagnosticBytes = 0;
  function region(pointer, size) {
    const memory = getMemory();
    const start = pointer >>> 0;
    const length = size >>> 0;
    if (!memory || start > memory.buffer.byteLength ||
        length > memory.buffer.byteLength - start) return null;
    return new Uint8Array(memory.buffer, start, length);
  }
  return {
    // The sole descriptor is a bounded stderr diagnostic sink. It is host
    // owned and cannot be closed or sought. No filesystem descriptors exist.
    fd_close() { return 8; }, // EBADF: no closable descriptor capability.
    fd_seek(fd) { return fd === 2 ? 70 : 8; }, // ESPIPE / EBADF.
    fd_write(fd, iovs, count, written) {
      if (fd !== 2) return 8;
      count >>>= 0;
      if (count > 64) return EINVAL;
      const table = region(iovs, count * 8), output = region(written, 4);
      if (!table || !output) return EFAULT;
      const view = new DataView(table.buffer, table.byteOffset, table.byteLength);
      const chunks = []; let size = 0;
      for (let i = 0; i < count; i++) {
        const chunk = region(view.getUint32(i * 8, true), view.getUint32(i * 8 + 4, true));
        if (!chunk) return EFAULT;
        size += chunk.length;
        if (size > 65536 - diagnosticBytes) return 51; // ENOSPC, never fake success.
        chunks.push(chunk);
      }
      try {
        if (size) {
          const bytes = new Uint8Array(size); let offset = 0;
          for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
          host.console.warn(new TextDecoder().decode(bytes));
        }
      } catch { return EIO; }
      diagnosticBytes += size;
      new DataView(output.buffer, output.byteOffset, 4).setUint32(0, size, true);
      return 0;
    },
    random_get(pointer, size) {
      const bytes = region(pointer, size);
      if (!bytes) return EFAULT;
      try {
        // WebCrypto limits each call to 65536 bytes.
        for (let offset = 0; offset < bytes.length; offset += 65536)
          host.crypto.getRandomValues(bytes.subarray(offset, offset + 65536));
        return 0;
      } catch {
        bytes.fill(0);
        return EIO;
      }
    },
    clock_time_get(clockId, _precision, pointer) {
      if (clockId !== 0 && clockId !== 1) return EINVAL;
      const bytes = region(pointer, 8);
      if (!bytes) return EFAULT;
      try {
        const milliseconds = clockId === 0 ? host.Date.now() : host.performance.now();
        if (!Number.isFinite(milliseconds) || milliseconds < 0 ||
            !Number.isSafeInteger(Math.floor(milliseconds)) ||
            (clockId === 0 && !Number.isSafeInteger(milliseconds)))
          return EIO;
        const nanoseconds = BigInt(Math.floor(milliseconds)) * 1000000n +
          BigInt(Math.floor((milliseconds % 1) * 1000000));
        if (nanoseconds > 0xffffffffffffffffn) return EIO;
        new DataView(bytes.buffer, bytes.byteOffset, 8)
          .setBigUint64(0, nanoseconds, true);
        return 0;
      } catch { return EIO; }
    },
  };
}

export async function instantiateReactor(bytes) {
  requireCapabilities();
  let module;
  try { module = await WebAssembly.compile(bytes); }
  catch { throw new CapabilityError('The WASM artifact is invalid or unsupported.'); }
  const imports = WebAssembly.Module.imports(module);
  const names = imports.map(item => item.name).sort();
  if (JSON.stringify(names) !== JSON.stringify(IMPORTS) || imports.some(item =>
    item.module !== 'wasi_snapshot_preview1' || item.kind !== 'function'))
    throw new CapabilityError('The WASM artifact requires unsupported imports.');
  const exported = WebAssembly.Module.exports(module).map(item => item.name).sort();
  if (JSON.stringify(exported) !== JSON.stringify(EXPORTS))
    throw new CapabilityError('The WASM artifact has an unsupported ABI.');
  let memory;
  const instance = await WebAssembly.instantiate(module, {
    wasi_snapshot_preview1: createWasiImports(() => memory),
  });
  memory = instance.exports.memory;
  if (instance.exports.quietproof_wasm_abi_version() !== 2)
    throw new CapabilityError('The WASM ABI version is unsupported.');
  instance.exports._initialize();
  let poisoned = false;
  function invoke(name, ...args) {
    if (poisoned) throw new Error('WASM instance is unusable; recreate the worker.');
    try { return instance.exports[name](...args); }
    catch (error) {
      if (error instanceof WebAssembly.RuntimeError) {
        poisoned = true;
        const fatal = new Error('WASM computation trapped; recreate the worker.');
        fatal.name = 'WorkerResetError'; throw fatal;
      }
      throw error;
    }
  }
  function output(status) {
    const api = instance.exports;
    if (status) {
      const message = new TextDecoder().decode(new Uint8Array(memory.buffer,
        api.quietproof_wasm_error_data(), api.quietproof_wasm_error_size()));
      const error = new Error(`${message} (status ${status}).`);
      if (status === 4) error.name = 'PolicyError';
      if (status === 5) error.name = 'UnsupportedError';
      throw error;
    }
    const start = api.quietproof_wasm_result_data();
    return memory.buffer.slice(start, start + api.quietproof_wasm_result_size());
  }
  function input(buffer, maximum, callback) {
    if (!(buffer instanceof ArrayBuffer) || !buffer.byteLength || buffer.byteLength > maximum)
      throw new Error('Invalid or oversized binary input.');
    const pointer = invoke('quietproof_wasm_alloc', buffer.byteLength);
    if (!pointer) throw new Error('WASM allocation failed.');
    try {
      new Uint8Array(memory.buffer, pointer, buffer.byteLength).set(new Uint8Array(buffer));
      return callback(pointer, buffer.byteLength);
    } finally { if (!poisoned) invoke('quietproof_wasm_free', pointer); }
  }
  function operation(name, buffer, maximum, ...args) {
    return input(buffer, maximum, (pointer, size) => output(invoke(name, pointer, size, ...args)));
  }
  return {
    exports: instance.exports,
    reset() { invoke('quietproof_wasm_reset'); },
    prepare(proof, policy) {
      invoke('quietproof_wasm_reset');
      const expected = encodePolicy(policy);
      return input(expected, 8192, (policyPointer, policySize) =>
        input(proof, MAX_ENVELOPE_BYTES, (proofPointer, proofSize) =>
          decodeVerification(output(invoke('quietproof_wasm_prepare',
            proofPointer, proofSize, policyPointer, policySize)))));
    },
    verify(context) {
      integerContext(context);
      return decodeVerification(output(invoke('quietproof_wasm_verify', context)));
    },
    evaluate(context, evidence) {
      integerContext(context);
      return input(encodeEvidence(evidence), 4096, (pointer, size) =>
        decodeVerification(output(invoke('quietproof_wasm_evaluate', context, pointer, size))));
    },
    createRequest(options) {
      return operation('quietproof_wasm_create_request', encodeRequestOptions(options), 8192);
    },
    inspect(bytes, proof = false) {
      if (typeof proof !== 'boolean') throw new Error('Invalid inspection kind.');
      return decodeInspection(operation('quietproof_wasm_inspect', bytes,
        proof ? MAX_ENVELOPE_BYTES : 4096, proof ? 1 : 0));
    },
    smoke() {
      const pointer = invoke('quietproof_wasm_alloc', 72);
      if (!pointer) throw new Error('WASM allocation failed.');
      try {
        const status = invoke('quietproof_wasm_smoke', pointer, 72);
        if (status !== 0) throw new Error(`WASM smoke failed (status ${status}).`);
        // Copy before freeing. Transfer the owned copy, never linear memory.
        return memory.buffer.slice(pointer, pointer + 72);
      } finally { if (!poisoned) invoke('quietproof_wasm_free', pointer); }
    },
  };
}

function integerContext(context) {
  if (!Number.isInteger(context) || context < 1 || context > 0xffffffff)
    throw new Error('Invalid verification context.');
}
