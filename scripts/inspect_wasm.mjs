import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const bytes = readFileSync(process.argv[2]);
const module = new WebAssembly.Module(bytes);
const imports = WebAssembly.Module.imports(module);
const exports = WebAssembly.Module.exports(module);
const allowedImports = new Set(['random_get', 'clock_time_get', 'fd_write', 'fd_seek', 'fd_close']);
for (const item of imports) {
  assert.equal(item.module, 'wasi_snapshot_preview1', 'unexpected import namespace');
  assert.equal(item.kind, 'function');
  assert(allowedImports.has(item.name), `unexpected WASI import: ${item.name}`);
}
for (const name of ['random_get', 'clock_time_get', 'fd_write', 'fd_seek', 'fd_close']) {
  assert(imports.some(item => item.name === name), `missing host contract: ${name}`);
}
const expectedExports = ['memory', '_initialize', 'quietproof_wasm_abi_version',
  'quietproof_wasm_alloc', 'quietproof_wasm_free', 'quietproof_wasm_smoke',
  'quietproof_wasm_create_request', 'quietproof_wasm_inspect',
  'quietproof_wasm_result_data', 'quietproof_wasm_result_size',
  'quietproof_wasm_error_data', 'quietproof_wasm_error_size',
  'quietproof_wasm_prepare', 'quietproof_wasm_verify',
  'quietproof_wasm_evaluate', 'quietproof_wasm_reset'].sort();
assert.deepEqual(exports.map(item => item.name).sort(), expectedExports);

// Read the declared memory limits, including a mandatory maximum, from the
// binary rather than relying on linker flags or a particular engine's API.
let offset = 8;
function uleb() {
  let value = 0;
  let shift = 0;
  let byte;
  do {
    assert(offset < bytes.length && shift < 35, 'malformed u32 LEB');
    byte = bytes[offset++];
    value += (byte & 127) * 2 ** shift;
    shift += 7;
  } while (byte & 128);
  return value;
}
let memory;
while (offset < bytes.length) {
  const section = bytes[offset++];
  const size = uleb();
  const end = offset + size;
  assert(end <= bytes.length);
  if (section === 5) {
    assert.equal(uleb(), 1, 'one linear memory required');
    assert.equal(uleb(), 1, 'unshared memory with explicit maximum required');
    memory = { initialPages: uleb(), maximumPages: uleb() };
    assert.deepEqual(memory, { initialPages: 256, maximumPages: 32768 });
  }
  offset = end;
}
assert(memory, 'missing memory section');
console.log(JSON.stringify({ imports, exports, memory }, null, 2));
