const MAX_WASM_BYTES = 8 * 1024 * 1024;

export function assetUrl(value, base = globalThis.location?.href ?? 'https://quietproof.invalid/') {
  const origin = new URL(base);
  const url = new URL(value, origin);
  if (typeof value !== 'string' || !value || /[\\\u0000-\u0020]/.test(value) ||
      !['https:', 'http:'].includes(url.protocol) || url.origin !== origin.origin ||
      url.username || url.password || url.search || url.hash || !url.pathname.endsWith('.wasm'))
    throw new Error('WASM tools must use a same-origin static asset URL.');
  return url;
}

// Both workflows share the same download policy. The reviewed site and its
// same-origin build artifacts remain trusted; ABI validation is not integrity
// authentication against a compromised deployment.
export async function loadWasmAsset(value, { fetch: fetcher, signal, check, label }) {
  const expected = assetUrl(value);
  const response = await fetcher(value, { signal, credentials: 'omit', mode: 'same-origin',
    redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-cache' });
  check();
  const reject = () => { void response.body?.cancel().catch(() => {});
    throw new Error(`Could not load ${label} tools.`); };
  const length = response.headers.get('content-length');
  if (!response.ok || response.redirected || (response.url && response.url !== expected.href) ||
      (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_WASM_BYTES))) reject();
  const reader = response.body?.getReader();
  if (!reader) reject();
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value: chunk } = await reader.read(); check();
      if (done) break;
      size += chunk.byteLength;
      if (size > MAX_WASM_BYTES) throw new Error(`${label} tools exceed the supported download size.`);
      chunks.push(chunk);
    }
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  if (!size) throw new Error(`Could not load ${label} tools.`);
  const wasm = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { wasm.set(chunk, offset); offset += chunk.byteLength; }
  return wasm.buffer;
}
