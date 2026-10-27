// Real, serialized browser qualification. Emits a complete durable JSON report;
// missing required engines fail; Firefox is unsupported diagnostic coverage.
import { chromium, firefox, webkit } from 'playwright';
import { createServer } from 'node:http';
import { createReadStream, readFileSync, writeFileSync, statSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { gzipSync, brotliCompressSync } from 'node:zlib';
import os from 'node:os';
import { REQUIRED_ENGINES, REQUIRED_KEYS, DIAGNOSTIC_ENGINES, parseSelection, assessCoverage } from './coverage.mjs';
import { cappedMemoryArtifact, RESOURCE_BUDGETS } from './resources.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const artifact = resolve(process.env.QUIETPROOF_WASM ?? 'missing.wasm');
const fixtures = resolve(process.env.QUIETPROOF_WASM_FIXTURES ?? 'missing-fixtures');
const destination = process.env.QUIETPROOF_FEASIBILITY_REPORT;
if (!destination) throw new Error('QUIETPROOF_FEASIBILITY_REPORT is required.');
const engineNames = parseSelection(process.env.QUIETPROOF_ENGINES, REQUIRED_ENGINES,
  [...REQUIRED_ENGINES, ...DIAGNOSTIC_ENGINES], 'engine');
const keyNames = parseSelection(process.env.QUIETPROOF_KEYS, REQUIRED_KEYS, REQUIRED_KEYS, 'key');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const wasm = readFileSync(artifact);
const cappedWasm = cappedMemoryArtifact(wasm);
const site = process.env.QUIETPROOF_FEASIBILITY_SITE ? resolve(process.env.QUIETPROOF_FEASIBILITY_SITE) : null;
const report = { version: 2, supportedBrowsers: [...REQUIRED_ENGINES],
  unsupportedBrowsers: [...DIAGNOSTIC_ENGINES], observedAt: new Date().toISOString(),
  environment: { platform: os.platform(), release: os.release(), architecture: os.arch(),
    cpu: os.cpus()[0]?.model ?? null, logicalCPUs: os.cpus().length, hostMemoryBytes: os.totalmem(), node: process.version },
  wasm: { path: artifact, sha256: digest(wasm), bytes: wasm.length,
    gzip9Bytes: gzipSync(wasm, { level: 9 }).length, brotliBytes: brotliCompressSync(wasm).length },
  fixtures: {}, engines: [], completeness: 'running',
  budgets: RESOURCE_BUDGETS, site: site ? { directory: site, entry: { path: resolve(site, 'tool.html'), sha256: digest(readFileSync(resolve(site, 'tool.html'))) } } : null,
  controlledMemoryFailure: { maximumBytes: 512 * 1024 * 1024, sha256: digest(cappedWasm), scope: 'Test-only module memory ceiling; not physical low-memory hardware.' },
  sources: ['web/wasm/asset.mjs', 'web/wasm/codec.mjs', 'web/wasm/runtime.mjs', 'web/wasm/worker.mjs',
    'tests/wasm/feasibility.mjs', 'tests/wasm/measured-worker.mjs', 'tests/wasm/resources.mjs',
    'package.json', 'package-lock.json'].map(path => ({ path: resolve(root, path), sha256: digest(readFileSync(resolve(root, path))) })),
  memoryScope: 'Linear memory high-water allocation observed after synchronous calls; WASM memory never shrinks. Not process RSS or JS heap.',
  copyScope: 'Sender detachment is observed per transferred proof; implementation copy inventory is documented separately. Engine-internal physical copies are not measurable here.' };
for (const key of ['one-key', 'two-key']) {
  const provenance = JSON.parse(readFileSync(resolve(fixtures, key + '.json')));
  if (provenance.expiresAt <= Math.floor(Date.now() / 1000) + 3600)
    throw new Error(`${key} fixture expires within one hour; regenerate native fixtures.`);
  report.fixtures[key] = { provenance, files: ['qpr', 'qpf'].map(ext => {
    const path = resolve(fixtures, `${key}.${ext}`), bytes = readFileSync(path);
    return { path, bytes: bytes.length, sha256: digest(bytes) };
  }) };
}
function save() { writeFileSync(resolve(destination), JSON.stringify(report, null, 2) + '\n'); }
save();
const server = createServer((request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    if (path === '/' && !site) { response.setHeader('Content-Type', 'text/html'); response.end('<!doctype html><title>Real proof feasibility</title>'); return; }
    if (path === '/quietproof-low-memory.wasm') {
      response.setHeader('Content-Type', 'application/wasm'); response.end(cappedWasm); return;
    }
    let local;
    if (path === '/quietproof.wasm') { local = artifact; response.setHeader('Content-Type', 'application/wasm'); }
    else if (/^\/fixtures\/(one-key|two-key)\.(qpf|qpr)$/.test(path)) local = resolve(fixtures, basename(path));
    else if (/^\/(web\/wasm\/[a-z]+|tests\/wasm\/(measured-worker|resources))\.mjs$/.test(path)) {
      local = resolve(root, '.' + path); response.setHeader('Content-Type', 'text/javascript');
    } else if (site && (path === '/' || /^\/assets\/[a-zA-Z0-9_.-]+\.(js|css|woff2)$/.test(path))) {
      local = resolve(site, path === '/' ? 'tool.html' : '.' + path);
      response.setHeader('Content-Type', path === '/' ? 'text/html' : path.endsWith('.css') ? 'text/css' : path.endsWith('.woff2') ? 'font/woff2' : 'text/javascript');
    } else { response.writeHead(404).end(); return; }
    response.setHeader('Content-Length', statSync(local).size);
    createReadStream(local).pipe(response);
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
try {
  for (const name of engineNames) {
    const type = { chromium, firefox, webkit }[name];
    const engine = { name, supported: REQUIRED_ENGINES.includes(name),
      coverageRole: REQUIRED_ENGINES.includes(name) ? 'required' : 'unsupported-diagnostic', observedAt: new Date().toISOString(), status: 'running', checks: [] };
    report.engines.push(engine); save();
    let browser;
    try {
      const executablePath = process.env[`QUIETPROOF_${name.toUpperCase()}_EXECUTABLE`];
      browser = await type.launch({ headless: true, timeout: 20000, ...(executablePath ? { executablePath } : {}) });
      engine.version = browser.version();
      engine.executablePath = executablePath ?? null;
      engine.driverDefaultExecutablePath = type.executablePath();
      const page = await browser.newPage();
      page.on('console', message => {
        if (message.text().startsWith('qp-feasibility:')) console.log(`${name} ${message.text()}`);
      });
      await page.goto(origin);
      // Checks run serially and persist after each key, so a later engine or
      // memory failure cannot erase earlier observed qualification evidence.
      for (const key of keyNames) {
        const result = await page.evaluate(async key => {
          const { RESOURCE_BUDGETS: budgets } = await import('/tests/wasm/resources.mjs');
          const { loadWasmAsset } = await import('/web/wasm/asset.mjs');
          const records = [];
          let ticks = 0, maximumGap = 0, lastTick = performance.now();
          const heartbeat = setInterval(() => { const now = performance.now(); maximumGap = Math.max(maximumGap, now - lastTick); lastTick = now; ticks++; }, 20);
          const clients = new Set();
          function client() {
            const worker = new Worker('/tests/wasm/measured-worker.mjs', { type: 'module' });
            let next = 0, closed = false, late = 0;
            const pending = new Map();
            worker.onmessage = ({ data }) => {
              if (closed) { late++; return; }
              const entry = pending.get(data.id); if (!entry) return;
              if (data.type === 'enteredVerification') { entry.enter(); return; }
              clearTimeout(entry.timer); pending.delete(data.id); entry.enter();
              if (data.type === 'error') {
                const error = new Error(`${data.name}: ${data.message}`); error.linearMemoryBytes = data.linearMemoryBytes;
                entry.reject(error);
              } else entry.resolve(data);
            };
            worker.onerror = event => { for (const entry of pending.values()) { clearTimeout(entry.timer); entry.enter(); entry.reject(new Error(event.message)); } pending.clear(); };
            const api = {
              send(type, fields = {}) {
                if (closed) throw new Error('Client already terminated');
                const id = ++next; let enter;
                const entered = new Promise(resolve => { enter = resolve; });
                const result = new Promise((resolve, reject) => {
                  const timer = setTimeout(() => { pending.delete(id); enter(); reject(new Error(`Timed out in ${type}`)); }, 600000);
                  pending.set(id, { resolve, reject, enter, timer });
                  const bytes = fields.bytes;
                  worker.postMessage({ id, type, ...fields }, bytes ? [bytes] : []);
                  if (bytes && bytes.byteLength !== 0) throw new Error('Binary ownership transfer did not detach sender');
                });
                return { result, entered };
              },
              terminate() {
                closed = true; worker.terminate(); clients.delete(api);
                for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error('Canceled')); entry.enter(); }
                pending.clear();
              },
              late: () => late,
            };
            clients.add(api); return api;
          }
          const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
          async function initialize(capped = false) {
            const api = client();
            const start = performance.now();
            const bytes = await loadWasmAsset(capped ? '/quietproof-low-memory.wasm' : '/quietproof.wasm',
              { fetch, check() {}, label: 'qualification' });
            const loadMs = performance.now() - start, initializeStart = performance.now();
            await api.send('initialize', { bytes }).result;
            const initializeMs = performance.now() - initializeStart;
            records.push({ label: capped ? 'controlled-low-memory-load' : 'load', loadMs, initializeMs,
              senderDetached: bytes.byteLength === 0 });
            if (loadMs > budgets.localAssetLoadMs || initializeMs > budgets.initializeMs)
              throw new Error('Local asset/initialization regression budget exceeded');
            return api;
          }
          async function prepare(api, changed = false) {
            const proof = await (await fetch(`/fixtures/${key}.qpf`)).arrayBuffer();
            const request = await (await fetch(`/fixtures/${key}.qpr`)).arrayBuffer();
            const inputBytes = proof.byteLength;
            if (changed) new Uint8Array(proof)[proof.byteLength - 1] ^= 1;
            const start = performance.now();
            const prepared = await api.send('prepare', { bytes: proof, policy: {
              expectedRequest: request, provider: '', maxLifetimeSeconds: 86400,
              minConfirmations: 1, minimumTotalSats: 0, maxObservationAgeSeconds: 60 } }).result;
            return { prepared, inputBytes, prepareMs: performance.now() - start, senderDetached: proof.byteLength === 0 };
          }
          async function verify(api, label, changed = false) {
            const input = await prepare(api, changed), start = performance.now();
            const record = { label, inputBytes: input.inputBytes, senderDetached: input.senderDetached,
              prepareMs: input.prepareMs, verifyMs: performance.now() - start,
              preparedLinearMemoryBytes: input.prepared.linearMemoryBytes,
              cryptography: 'pending' };
            records.push(record);
            let output;
            try { output = await api.send('verify', { operationId: input.prepared.operationId, phaseToken: input.prepared.phaseToken }).result; }
            catch (error) { record.verifyMs = performance.now() - start; record.failureMemoryBytes = error.linearMemoryBytes ?? null; throw error; }
            Object.assign(record, { verifyMs: performance.now() - start,
              peakObservedLinearMemoryBytes: output.linearMemoryBytes,
              cryptography: output.cryptography, policy: output.policy, explorer: output.explorer, authorizes: output.authorizes });
            if (output.cryptography !== (changed ? 'invalid' : 'valid') || output.authorizes !== false || output.explorer !== 'unavailable')
              throw new Error('Real verification or trust separation failed');
            if (record.prepareMs > budgets.prepareMs || record.verifyMs > budgets.verifyMs[key] ||
                record.peakObservedLinearMemoryBytes > budgets.linearMemoryBytes)
              throw new Error('Verification regression budget exceeded');
            console.info(`qp-feasibility: ${key} ${label} ${Math.round(record.verifyMs)}ms ${record.peakObservedLinearMemoryBytes} bytes`);
            return record;
          }
          try {
            let api = await initialize();
            const cold = await verify(api, 'cold');
            const warm = await verify(api, 'repeat');
            // Linear-memory pages cannot shrink. Bound retained high-water growth
            // across identical operations; 16MiB allows allocator page rounding.
            if (warm.peakObservedLinearMemoryBytes > cold.peakObservedLinearMemoryBytes + budgets.repeatGrowthBytes)
              throw new Error('Linear memory grows across repeated identical verification');
            await verify(api, 'changed-proof', true);
            const reset = await api.send('reset').result;
            records.push({ label: 'reset', retainedLinearMemoryBytes: reset.linearMemoryBytes });
            api.terminate();
            api = await initialize();
            const input = await prepare(api);
            const ongoing = api.send('verify', { operationId: input.prepared.operationId, phaseToken: input.prepared.phaseToken });
            ongoing.result.catch(() => {});
            await ongoing.entered; const ticksBefore = ticks; await pause(200);
            const cancelStart = performance.now(); api.terminate();
            await pause(200);
            if (ticks <= ticksBefore + 3 || api.late()) throw new Error('Main thread froze or terminated worker delivered a response');
            records.push({ label: 'hard-cancel', cancellationObservationMs: performance.now() - cancelStart,
              heartbeatTicksDuringComputeAndCancel: ticks - ticksBefore, lateResponses: api.late() });
            if (performance.now() - cancelStart > budgets.cancellationSettleMs) throw new Error('Cancellation regression budget exceeded');
            api = await initialize();
            await verify(api, 'fresh-after-cancel'); api.terminate();
            api = await initialize(true);
            let memoryFailure;
            try { await verify(api, 'controlled-low-memory'); }
            catch (error) { memoryFailure = { name: error.name, message: error.message, linearMemoryBytes: error.linearMemoryBytes ?? null }; }
            if (!memoryFailure || !/alloc|memory|trap|WorkerResetError/i.test(memoryFailure.message))
              throw new Error('Controlled low-memory fixture did not fail at its expected allocation boundary');
            records.push({ label: 'controlled-low-memory-failure', ...memoryFailure }); api.terminate();
            api = await initialize(); await verify(api, 'fresh-after-low-memory'); api.terminate();
            if (maximumGap > budgets.heartbeatGapMs || ticks < 10) throw new Error('Main thread responsiveness gate failed');
            return { key, status: 'passed', records, heartbeat: { intervalMs: 20, ticks, maximumGapMs: maximumGap },
              memoryScope: 'Observed linear-memory high-water allocation; no claim about process RSS/JS heap' };
          } catch (error) {
            return { key, status: 'failed', error: { name: error.name, message: error.message, stack: error.stack }, records,
              heartbeat: { intervalMs: 20, ticks, maximumGapMs: maximumGap } };
          } finally { clearInterval(heartbeat); for (const api of clients) api.terminate(); }
        }, key);
        engine.checks.push(result); save();
        if (result.status !== 'passed') { engine.status = 'failed'; break; }
      }
      if (engine.status === 'running') engine.status = 'passed';
    } catch (error) { engine.status = engine.version ? 'failed' : 'unavailable'; engine.error = error.stack ?? String(error); }
    finally { await browser?.close(); engine.completedAt = new Date().toISOString(); save(); }
  }
} finally { await new Promise(resolve => server.close(resolve)); }
report.completeness = 'complete'; report.completedAt = new Date().toISOString();
report.requiredCoverage = assessCoverage(report); save();
console.log(JSON.stringify({ engines: report.engines.map(engine => ({ name: engine.name, status: engine.status, version: engine.version ?? null })), report: resolve(destination) }));
if (!report.requiredCoverage.passed) process.exitCode = 1;
