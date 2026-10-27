// Feature-private Esplora transport shared by discovery and verification.
export const NETWORKS = Object.freeze({
  mainnet: Object.freeze({ endpoint: 'https://blockstream.info/api', hrp: 'bc', version: 0,
    genesis: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f' }),
  signet: Object.freeze({ endpoint: 'https://blockstream.info/signet/api', hrp: 'tb', version: 111,
    genesis: '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6' })
});
export const LIMITS = Object.freeze({ addresses: 2, outputs: 256, responseBytes: 2 * 1024 * 1024,
  transactionOutputs: 20000, timeoutMs: 30000 });
const HEX32 = /^[0-9a-f]{64}$/;
export const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export function fail(code) { throw Object.assign(new Error(`Explorer discovery: ${code}.`), { code }); }
export function integer(value, max, min = 0) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('invalid_integer');
  return value;
}
export function hash(value) { if (typeof value !== 'string' || !HEX32.test(value)) fail('invalid_hash'); return value; }
export function status(value) {
  if (!value || typeof value.confirmed !== 'boolean') fail('invalid_status');
  if (!value.confirmed) {
    if (value.block_height !== undefined || value.block_hash !== undefined || value.block_time !== undefined)
      fail('invalid_status');
    return Object.freeze({ confirmed: false });
  }
  return Object.freeze({ confirmed: true, blockHeight: integer(value.block_height, 0xffffffff),
    blockHash: hash(value.block_hash), blockTime: integer(value.block_time, Number.MAX_SAFE_INTEGER) });
}

export function createOperation(config, fetcher, timeoutMs, signal, fresh = false) {
    const controller = new AbortController();
    const cancel = () => controller.abort(signal?.reason === 'superseded' ? 'superseded' : 'aborted');
    if (signal?.aborted) cancel();
    signal?.addEventListener('abort', cancel, { once: true });
    const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
    const cancellationCode = () => ['timeout', 'superseded'].includes(controller.signal.reason) ? controller.signal.reason : 'aborted';
    const check = () => { if (controller.signal.aborted) fail(cancellationCode()); };
    // Race even a fetch/body implementation that ignores the signal. Real fetch also
    // aborts the socket; late responses can never populate the returned result.
    async function bounded(work) {
      check();
      let listener;
      const aborted = new Promise((_, reject) => {
        listener = () => reject(Object.assign(new Error('Explorer operation cancelled.'),
          { code: cancellationCode() }));
        controller.signal.addEventListener('abort', listener, { once: true });
      });
      try { return await Promise.race([work(), aborted]); }
      finally { controller.signal.removeEventListener('abort', listener); }
    }
    async function get(path, json = true, maxBytes = LIMITS.responseBytes) {
      try {
        return await bounded(async () => {
          const response = await fetcher(`${config.endpoint}${path}`, { method: 'GET', mode: 'cors',
            credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal });
          const rejectResponse = code => { void response.body?.cancel().catch(() => {}); fail(code); };
          if (fresh && response.headers.get('age') !== null && response.headers.get('age') !== '0') rejectResponse('cached_response');
          if (!response.ok) rejectResponse(`http_${response.status}`);
          if (!response.body?.getReader) fail('unreadable_response');
          const length = response.headers.get('content-length');
          if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > maxBytes)) rejectResponse('response_limit');
          const reader = response.body.getReader(), chunks = []; let size = 0;
          const cancelReader = () => { void reader.cancel().catch(() => {}); };
          controller.signal.addEventListener('abort', cancelReader, { once: true });
          try {
            while (true) {
              check(); const { value, done } = await reader.read(); if (done) break;
              size += value.byteLength;
              if (size > maxBytes) fail('response_limit');
              chunks.push(value);
            }
          } finally {
            controller.signal.removeEventListener('abort', cancelReader);
            await reader.cancel().catch(() => {});
          }
          const bytes = new Uint8Array(size); let offset = 0;
          for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
          let text;
          try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
          catch { fail('malformed_response'); }
          if (!json) return text;
          // JSON.parse would silently round e.g. 1.0000000000000001 to 1.
          // Esplora numeric fields are integers. Check the original numeric
          // lexemes (skipping strings) before permitting binary64 conversion.
          for (const token of text.matchAll(/"(?:[^"\\]|\\.)*"|(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/g)) {
            if (token[1] && (!/^-?(0|[1-9][0-9]*)$/.test(token[1]) || !Number.isSafeInteger(Number(token[1]))))
              fail('invalid_integer');
          }
          try { return JSON.parse(text); } catch { fail('malformed_json'); }
        });
      } catch (error) {
        check();
        if (error.code) throw error;
        fail('network_or_cors');
      }
    }
    return { get, check, close() { controller.abort('closed'); clearTimeout(timer); signal?.removeEventListener('abort', cancel); } };
}
