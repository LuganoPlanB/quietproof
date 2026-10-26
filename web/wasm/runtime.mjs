// Minimal WASI preview1 adapter. Time is an untrusted browser observation.
const EFAULT = 21;
const EINVAL = 28;
const EIO = 29;
const IMPORTS = ['clock_time_get', 'random_get'];
const EXPORTS = ['_initialize', 'memory', 'quietproof_wasm_abi_version',
  'quietproof_wasm_alloc', 'quietproof_wasm_free', 'quietproof_wasm_smoke'];

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
}

// The host argument is for adapter tests. The production worker never accepts
// host callbacks, nonce seeds or a clock from messages.
export function createWasiImports(getMemory, host = globalThis) {
  function region(pointer, size) {
    const memory = getMemory();
    const start = pointer >>> 0;
    const length = size >>> 0;
    if (!memory || start > memory.buffer.byteLength ||
        length > memory.buffer.byteLength - start) return null;
    return new Uint8Array(memory.buffer, start, length);
  }
  return {
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
      if (clockId !== 0) return EINVAL;
      const bytes = region(pointer, 8);
      if (!bytes) return EFAULT;
      try {
        const milliseconds = host.Date.now();
        if (!Number.isSafeInteger(milliseconds) || milliseconds < 0)
          return EIO;
        const nanoseconds = BigInt(milliseconds) * 1000000n;
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
  if (instance.exports.quietproof_wasm_abi_version() !== 1)
    throw new CapabilityError('The WASM ABI version is unsupported.');
  instance.exports._initialize();
  return {
    exports: instance.exports,
    smoke() {
      const pointer = instance.exports.quietproof_wasm_alloc(72);
      if (!pointer) throw new Error('WASM allocation failed.');
      try {
        const status = instance.exports.quietproof_wasm_smoke(pointer, 72);
        if (status !== 0) throw new Error(`WASM smoke failed (status ${status}).`);
        // Copy before freeing. Transfer the owned copy, never linear memory.
        return memory.buffer.slice(pointer, pointer + 72);
      } finally { instance.exports.quietproof_wasm_free(pointer); }
    },
  };
}
