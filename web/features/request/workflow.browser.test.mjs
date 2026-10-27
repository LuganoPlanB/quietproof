import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { openSync, closeSync } from 'node:fs';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chromium, webkit } from 'playwright';
import { workflows, providerResponse } from './workflow-fixtures.mjs';
import { decodeInspection } from '../../wasm/codec.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4174';
const cli = process.env.QUIETPROOF_NATIVE_CLI;
const output = process.env.QUIETPROOF_WORKFLOW_ARTIFACTS || resolve(tmpdir(), `quietproof-request-workflow-${process.pid}`);
const runDirectory = resolve(output, `${Date.now()}-${process.pid}`);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function requestNonce(bytes) {
  // Decode the canonical statement using the existing inspection transport;
  // this is metadata-only and never stands in for proof verification.
  const inspection = new Uint8Array(61 + bytes.byteLength);
  inspection.set(new TextEncoder().encode('QWI1')); inspection.set(bytes, 61);
  return decodeInspection(inspection.buffer).nonce;
}

for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
  test(`${name}: mainnet/signet v1, v2 and mixed downloads consumed by real native proving`, { timeout: 1200000 }, async () => {
    assert(cli, 'Set QUIETPROOF_NATIVE_CLI to the current native CLI.');
    const browser = await engine.launch({ headless: true,
      ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
    console.log(`${name} ${browser.version()}`);
    const directory = resolve(runDirectory, name); await mkdir(directory, { recursive: true });
    const records = [];
    try {
      for (const workflow of workflows) {
        for (const [width, height] of [[390, 844], [1440, 900]]) for (const scale of [100, 200]) {
          const page = await browser.newPage({ viewport: { width, height }, acceptDownloads: true });
          const requests = [];
          await page.route('https://blockstream.info/**', route => {
            requests.push(route.request().url());
            assert.equal(route.request().method(), 'GET'); assert.equal(route.request().postData(), null);
            return route.fulfill(providerResponse(workflow, route.request().url()));
          });
          await page.goto(origin + '/tool');
          const create = page.getByRole('button', { name: 'Create request', exact: true }); await create.waitFor();
          await page.getByLabel('Bitcoin network', { exact: true }).selectOption(workflow.network);
          await page.getByLabel('Bitcoin addresses').fill(workflow.claims.map(c => c.address).join('\n'));
          assert.equal(requests.length, 0);
          await page.getByRole('button', { name: 'Look up outputs', exact: true }).click();
          await page.locator('.quietproof-claims').getByRole('checkbox').first().waitFor();
          for (const checkbox of await page.locator('.quietproof-claims').getByRole('checkbox').all()) await checkbox.check();
          assert.equal(await page.locator('.quietproof-claims').getByRole('checkbox').count(), workflow.claims.length);
          await page.getByLabel('Intended verifier').fill('workflow.example');
          await page.getByLabel('Purpose', { exact: true }).selectOption('proof-of-funds');
          await page.getByLabel('Message (optional').fill('Public disposable request interoperability');
          assert.equal(await page.getByLabel('Request lifetime').inputValue(), '300');
          await page.addStyleTag({ content: `html { font-size: ${16 * scale / 100}px !important; } .quietproof-request { font-size: ${16 * scale / 100}px !important; line-height: 1.6; }` });
          await create.click();
          const preview = page.getByRole('region', { name: 'Canonical request preview' }); await preview.waitFor();
          assert.match(await preview.innerText(), new RegExp(`${workflow.network} · v${workflow.version}`));
          const total = workflow.claims.reduce((n, c) => n + BigInt(c.amountSats), 0n).toString();
          assert.match(await preview.innerText(), new RegExp(total + ' sats'));
          const id = `${workflow.id}-${width}-${scale}`, qpr = resolve(directory, id + '.qpr');
          const downloadEvent = page.waitForEvent('download');
          await page.getByRole('link', { name: 'Download .qpr request', exact: true }).click();
          await (await downloadEvent).saveAs(qpr);
          const bytes = await readFile(qpr);
          const inspected = JSON.parse(execFileSync(cli, ['inspect', qpr], { encoding: 'utf8' }));
          assert.equal(inspected.network, workflow.network); assert.equal(inspected.statement_version, workflow.version);
          assert.equal(inspected.claims, workflow.claims.length);
          assert.deepEqual(inspected.script_kinds, workflow.claims.map(c => c.scriptKind));
          assert.equal(inspected.expires_at - inspected.not_before, 300);
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
          await page.evaluate(() => scrollTo(0, 0)); await page.waitForTimeout(100);
          await page.screenshot({ path: resolve(directory, id + '-complete.png'), fullPage: true });
          await preview.scrollIntoViewIfNeeded();
          await page.screenshot({ path: resolve(directory, id + '-detail.png') });
          const record = { workflow: workflow.id, engine: name, browserVersion: browser.version(), width, height, textScale: scale,
            qpr, requestSha256: digest(bytes), requestBytes: bytes.length, nonce: requestNonce(bytes), inspected, nativeProving: null,
            providerRequests: requests, observedAt: new Date().toISOString() };
          // One genuine native proof for every engine/network/script family.
          // Other viewport cases exercise identical behavior with fresh nonces.
          if (width === 390 && scale === 100) {
            const proof = resolve(directory, id + '.qpf'), log = resolve(directory, id + '-prove.log');
            const command = [cli, 'prove', '--request', qpr, '--output', proof, '--network', workflow.network];
            const observedAt = new Date().toISOString(), start = performance.now(), fd = openSync(log, 'w');
            let result;
            try {
              // These well-known disposable scalars are process stdin only;
              // they never enter a page, worker, URL or explorer request.
              const input = workflow.publicDisposableScalars.map(n => n.toString(16).padStart(64, '0')).join('\n') + '\n';
              result = execFileSync(command[0], command.slice(1), { input, encoding: 'utf8', timeout: 600000, stdio: ['pipe', 'pipe', fd] });
            } finally { closeSync(fd); }
            const summary = JSON.parse(result); assert.equal(summary.result, 'proof_created');
            assert(summary.proof_bytes > 40 * 1024 * 1024, 'real native proof payload required');
            const proofInspection = JSON.parse(execFileSync(cli, ['inspect', proof], { encoding: 'utf8' }));
            const proofBytes = await readFile(proof);
            assert.equal(proofBytes.subarray(0, 4).toString(), 'QPE1');
            assert.deepEqual(proofBytes.subarray(9, 9 + proofBytes.readUInt32BE(5)), bytes, 'native proof embeds the exact downloaded request');
            assert.equal(proofInspection.statement_version, workflow.version);
            assert.equal(proofInspection.network, workflow.network); assert.equal(proofInspection.claims, workflow.claims.length);
            record.nativeProving = { command, cwd: process.cwd(), exit: 0, observedAt, completedAt: new Date().toISOString(),
              elapsedSeconds: (performance.now() - start) / 1000, publicDisposableScalars: workflow.publicDisposableScalars,
              inputChannel: 'native stdin only', proof, log, proofBytes: proofBytes.length, proofSha256: digest(proofBytes), exactEmbeddedRequest: true, summary, proofInspection };
            console.log(`${name} ${workflow.id}: genuine native proof created`);
          }
          records.push(record);
          await writeFile(resolve(directory, 'provenance.json'), JSON.stringify(records, null, 2));
          // Regeneration changes the canonical nonce, while expiry gates download.
          if (workflow === workflows.at(-1)) {
            await page.getByLabel('Request lifetime').fill('1'); await create.click(); await preview.waitFor();
            await page.getByText('This request has expired according to your device clock. Regenerate it before sending it to a prover.', { exact: true }).waitFor({ timeout: 5000 });
            assert.equal(await page.getByRole('link', { name: 'Download .qpr request', exact: true }).count(), 0);
            await page.screenshot({ path: resolve(directory, `expired-${width}-${scale}.png`) });
            await page.getByLabel('Request lifetime').fill('300'); await create.click(); await preview.waitFor();
            const fresh = page.waitForEvent('download'); await page.getByRole('link', { name: 'Download .qpr request', exact: true }).click();
            const newBytes = await readFile(await (await fresh).path());
            assert.notEqual(digest(newBytes), digest(bytes));
            assert.notEqual(requestNonce(newBytes), requestNonce(bytes));
          }
          await page.close();
        }
      }
      assert.equal(records.length, 24); assert.equal(records.filter(r => r.nativeProving).length, 6);
    } finally { await browser.close(); }
  });
}
