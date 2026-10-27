// Explicit, optional network probe. Never imported by required fixture tests.
import { createServer } from 'node:http';
import { writeFile } from 'node:fs/promises';
import { chromium, webkit } from 'playwright';
import { NETWORKS } from './esplora.mjs';

const server = createServer((_request, response) => {
  response.setHeader('Content-Type', 'text/html');
  response.end('<!doctype html><title>Public provider capability probe</title>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const report = { version: 1, startedAt: new Date().toISOString(), origin,
  productionOriginQualified: false, requestsContain: 'public genesis, tip hash and tip block metadata only',
  limits: { engines: 2, networks: 2, requestsPerNetwork: 3, retries: 0, requestTimeoutMs: 8000, responseBytes: 65536 },
  rateLimits: 'Guaranteed quota/SLA unknown. A successful small probe does not establish an available request budget.', engines: [] };
try {
  for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
    let browser;
    const entry = { engine: name, version: null, results: [] }; report.engines.push(entry);
    try {
      browser = await engine.launch({ headless: true,
        ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
      entry.version = browser.version();
      const page = await browser.newPage(); await page.goto(origin);
      for (const [network, { endpoint, genesis }] of Object.entries(NETWORKS)) {
        entry.results.push(await page.evaluate(async ({ network, endpoint, genesis }) => {
          const result = { network, endpoint, origin: location.origin, observedAt: new Date().toISOString(),
            available: false, genesisMatches: null, requests: [], tip: null, failure: null };
          async function request(path, json = false) {
            const startedAt = new Date().toISOString(), controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 8000);
            const observation = { path, startedAt, status: null, responseType: null, exposedHeaders: null };
            result.requests.push(observation);
            try {
              const response = await fetch(endpoint + path, { method: 'GET', mode: 'cors', credentials: 'omit',
                cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal });
              observation.status = response.status; observation.responseType = response.type;
              observation.exposedHeaders = Object.fromEntries(['age', 'retry-after', 'cache-control', 'access-control-allow-origin']
                .map(name => [name, response.headers.get(name)]));
              if (!response.ok) throw new Error(`http_${response.status}`);
              const reader = response.body.getReader(), chunks = []; let size = 0;
              try {
                while (true) {
                  const { value, done } = await reader.read(); if (done) break;
                  size += value.byteLength; if (size > 65536) throw new Error('response_limit'); chunks.push(value);
                }
              } finally { await reader.cancel(); }
              const bytes = new Uint8Array(size); let offset = 0;
              for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
              const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
              return json ? JSON.parse(text) : text.trim();
            } finally { clearTimeout(timer); observation.completedAt = new Date().toISOString(); }
          }
          try {
            result.genesisMatches = await request('/block-height/0') === genesis;
            if (!result.genesisMatches) throw new Error('wrong_genesis');
            const hash = await request('/blocks/tip/hash');
            if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('invalid_tip');
            const block = await request(`/block/${hash}`, true);
            if (block.id !== hash || !Number.isSafeInteger(block.height) || block.height < 0) throw new Error('invalid_tip');
            result.tip = { block: hash, height: block.height }; result.available = true;
          } catch (error) {
            result.failure = error.name === 'AbortError' ? 'timeout' : error.name === 'TypeError'
              ? 'network_cors_or_tls' : error.message;
          }
          result.completedAt = new Date().toISOString(); return result;
        }, { network, endpoint, genesis }));
      }
    } catch (error) { entry.failure = `browser_probe_failed: ${error.name}`; }
    finally { await browser?.close(); }
  }
} finally { await new Promise(resolve => server.close(resolve)); }
report.completedAt = new Date().toISOString();
report.available = report.engines.length === 2 && report.engines.every(e => e.results.length === 2 && e.results.every(r => r.available));
if (process.env.QUIETPROOF_PROVIDER_PROBE_REPORT)
  await writeFile(process.env.QUIETPROOF_PROVIDER_PROBE_REPORT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ available: report.available, origin, productionOriginQualified: false,
  results: report.engines.map(e => ({ engine: e.engine, version: e.version, failure: e.failure ?? null,
    networks: e.results.map(r => ({ network: r.network, available: r.available, failure: r.failure, requests: r.requests.length })) })) }));
process.exitCode = report.available ? 0 : 1;
