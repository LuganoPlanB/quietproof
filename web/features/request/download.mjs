import { validateForm, selectionSummary } from './form.mjs';
import { loadWasmAsset } from '../../wasm/asset.mjs';

const cancelled = () => Object.assign(new Error('Request creation cancelled.'), { name: 'AbortError' });

// Feature boundary: each creation owns and tears down a fresh worker. Neither
// nonce nor clock sources are configurable through this interface.
export function setupRequest({ wasmUrl = '/wasm/quietproof.wasm', fetch: fetcher = globalThis.fetch,
  workerFactory = () => new Worker(new URL('../../wasm/worker.mjs', import.meta.url), { type: 'module' }),
  timeoutMs = 60000 } = {}) {
  let active, disposed = false;
  function cancel() { active?.abort(); }
  async function create(options) {
    if (disposed) throw new Error('Request tools are closed.');
    validateForm(options);
    const snapshot = structuredClone(options);
    cancel();
    const controller = new AbortController();
    active = controller;
    let worker, pending, sequence = 0;
    const abort = () => { worker?.terminate(); pending?.reject(cancelled()); pending = undefined; };
    controller.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    function check() { if (controller.signal.aborted) throw cancelled(); }
    function call(type, data = {}, transfer = []) {
      check();
      return new Promise((resolve, reject) => {
        const id = ++sequence; pending = { id, resolve, reject };
        try { worker.postMessage({ id, type, ...data }, transfer); }
        catch (error) { pending = undefined; reject(error); }
      });
    }
    try {
      const wasm = await loadWasmAsset(wasmUrl, { fetch: fetcher, signal: controller.signal, check, label: 'request' });
      check(); worker = workerFactory();
      worker.onmessage = ({ data }) => {
        if (!pending || data?.id !== pending.id) return;
        const current = pending; pending = undefined;
        if (data.type === 'error') current.reject(new Error('Request creation failed. Retry, or reload with a supported browser.'));
        else current.resolve(data);
      };
      worker.onerror = event => {
        event.preventDefault?.(); pending?.reject(new Error('Request tools stopped unexpectedly. Retry or reload this page.')); pending = undefined;
      };
      await call('initialize', { bytes: wasm }, [wasm]);
      const { bytes } = await call('createRequest', { options: snapshot });
      if (!(bytes instanceof ArrayBuffer) || !bytes.byteLength || bytes.byteLength > 4096)
        throw new Error('Request creation returned an invalid artifact.');
      // Request artifacts are small. Keep the returned canonical bytes for the
      // download while transferring a separate copy to canonical inspection.
      const inspectionBytes = bytes.slice(0);
      const { metadata } = await call('inspectRequest', { bytes: inspectionBytes }, [inspectionBytes]);
      check();
      const inspected = metadata?.requestBytes instanceof ArrayBuffer ? new Uint8Array(metadata.requestBytes) : null;
      if (!inspected || inspected.byteLength !== bytes.byteLength ||
          new Uint8Array(bytes).some((b, i) => b !== inspected[i]))
        throw new Error('Request inspection did not match its artifact.');
      return { bytes, metadata, summary: selectionSummary(metadata.claims) };
    } finally {
      clearTimeout(timer); controller.signal.removeEventListener('abort', abort);
      worker?.terminate(); if (active === controller) active = undefined;
    }
  }
  return { create, cancel, dispose() { disposed = true; cancel(); } };
}

// One live URL per committed preview. Repeated downloads reuse those same bytes;
// input edits, regeneration and unmount revoke the previous URL immediately.
export function setupDownload(urls = URL) {
  let url;
  function clear() { if (url) urls.revokeObjectURL(url); url = undefined; }
  return {
    clear,
    replace(bytes, metadata) {
      clear();
      url = urls.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
      return { url, filename: `quietproof-${metadata.network}-${metadata.nonce.slice(0, 16)}.qpr` };
    },
  };
}
