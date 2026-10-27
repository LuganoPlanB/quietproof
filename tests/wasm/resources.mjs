// Qualification budgets for the documented desktop reference environment.
// These are regression alarms, not protocol limits or device support detection.
export const RESOURCE_BUDGETS = Object.freeze({
  localAssetLoadMs: 10000, initializeMs: 10000, prepareMs: 10000,
  verifyMs: Object.freeze({ 'one-key': 100000, 'two-key': 200000 }),
  linearMemoryBytes: 1920 * 1024 * 1024, repeatGrowthBytes: 16 * 1024 * 1024,
  heartbeatGapMs: 2000, cancellationSettleMs: 2000,
});

// Test-only allocation-failure fixture. Preserve every instruction, export and
// cryptographic parameter; lower ONLY the module's memory maximum to 512 MiB.
// This exercises allocator failure; it does not emulate a physical low-RAM OS.
export function cappedMemoryArtifact(input, maximumPages = 8192) {
  const bytes = new Uint8Array(input).slice(); let cursor = 8;
  function uleb() {
    let value = 0, shift = 0, byte;
    do {
      if (cursor >= bytes.length || shift >= 35) throw new Error('Malformed WASM length.');
      byte = bytes[cursor++]; value += (byte & 127) * 2 ** shift; shift += 7;
    } while (byte & 128);
    return value;
  }
  while (cursor < bytes.length) {
    const section = bytes[cursor++], size = uleb(), end = cursor + size;
    if (end > bytes.length) throw new Error('Truncated WASM section.');
    if (section === 5) {
      if (uleb() !== 1 || uleb() !== 1) throw new Error('Expected one bounded unshared memory.');
      const initial = uleb(), start = cursor, maximum = uleb(), width = cursor - start;
      if (!Number.isInteger(maximumPages) || maximumPages < initial || maximumPages >= maximum)
        throw new Error('Invalid test memory ceiling.');
      let value = maximumPages;
      for (let i = 0; i < width; i++) {
        bytes[start + i] = (value & 127) | (i === width - 1 ? 0 : 128);
        value = Math.floor(value / 128);
      }
      if (value) throw new Error('Test ceiling does not fit original encoding.');
      return bytes;
    }
    cursor = end;
  }
  throw new Error('Missing module memory.');
}
