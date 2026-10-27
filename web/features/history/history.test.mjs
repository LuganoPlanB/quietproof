import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { setupHistory, HISTORY_LIMITS } from './history.mjs';
function persistence(initial) {
  let state = initial, queue = Promise.resolve(), failWrite = false;
  return { read: async () => structuredClone(state),
    update(fn) { const work = queue.then(() => { const next = fn(structuredClone(state)); if (failWrite) throw new Error('Quota'); state = structuredClone(next); return structuredClone(state); }); queue = work.catch(() => {}); return work; },
    raw: () => state, fail: () => { failWrite = true; } };
}
function harness(store = persistence(), extra = {}) {
  return { store, history: setupHistory({ store, crypto: webcrypto, channelFactory: () => null, events: {}, now: () => 123, ...extra }) };
}
const bytes = n => new Uint8Array([n, 1, 2, 3]).buffer;
const metadata = n => ({ nonce: n.toString(16).padStart(64, '0'), network: 'mainnet', verifier: 'Independent', expiresAt: '9999999999', requestBytes: bytes(n) });
const outcome = { cryptography: 'valid', policy: 'matched', explorer: 'unavailable' };

test('history starts off and stores nothing without an explicit consent ticket', async () => {
  const { history, store } = harness();
  assert.equal(await history.ticket(), null);
  assert.equal(await history.saveRequest(bytes(1), metadata(1), null), false);
  assert.equal(await history.recordCheck(metadata(1), outcome, null), null);
  assert.equal(store.raw(), undefined); history.dispose();
});
test('consented canonical request bytes survive reload without proof payloads or automatic policy selection', async () => {
  const { history, store } = harness(); await history.enable(true);
  const token = await history.ticket(); assert.equal(await history.saveRequest(bytes(1), metadata(1), token), true);
  const next = harness(store).history; await next.refresh();
  assert.deepEqual(new Uint8Array(next.snapshot().requests[0].bytes), new Uint8Array(bytes(1)));
  assert.equal(next.snapshot().requests[0].proof, undefined); assert.equal(next.snapshot().checks.length, 0);
  history.dispose(); next.dispose();
});
test('repeat markers are scoped to retained request/nonce data and never authorize acceptance', async () => {
  const { history } = harness(); await history.enable(true); const token = await history.ticket();
  assert.equal((await history.recordCheck(metadata(1), outcome, token)).repeat, false);
  assert.equal((await history.recordCheck(metadata(1), outcome, token)).repeat, true);
  const reusedNonce = { ...metadata(1), requestBytes: bytes(2) };
  assert.equal((await history.recordCheck(reusedNonce, outcome, token)).repeat, true);
  assert.equal(history.snapshot().checks[0].authorizes, undefined); history.dispose();
});
test('two service instances serialize check markers for cross-tab duplicate warnings', async () => {
  const store = persistence(), a = harness(store).history, b = harness(store).history;
  await a.enable(true); const token = await a.ticket();
  const results = await Promise.all([a.recordCheck(metadata(1), outcome, token), b.recordCheck(metadata(1), outcome, token)]);
  assert.deepEqual(results.map(r => r.repeat).sort(), [false, true]); await a.refresh(); assert.equal(a.snapshot().checks.length, 2);
  a.dispose(); b.dispose();
});
test('clear in another tab fences a pending digest and keeps all data off', async () => {
  let entered, release; const ready = new Promise(r => { entered = r; });
  const slowCrypto = { randomUUID: webcrypto.randomUUID.bind(webcrypto), subtle: { digest: async (...args) => { entered(); await new Promise(r => { release = r; }); return webcrypto.subtle.digest(...args); } } };
  const store = persistence(), a = harness(store, { crypto: slowCrypto }).history, b = harness(store).history;
  await a.enable(true); const token = await a.ticket(); const pending = a.saveRequest(bytes(1), metadata(1), token);
  let timer;
  try {
    await Promise.race([ready, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Digest gate not reached')), 5000); })]);
    await b.clear(); release(); assert.equal(await pending, false); await a.refresh();
    assert.equal(a.snapshot().enabled, false); assert.equal(a.snapshot().requests.length, 0);
  } finally { clearTimeout(timer); release?.(); await pending; a.dispose(); b.dispose(); }
});
test('delete rotates the fence while retaining other requests and removes linked markers', async () => {
  const { history } = harness(); await history.enable(true); const token = await history.ticket();
  await history.saveRequest(bytes(1), metadata(1), token); await history.saveRequest(bytes(2), metadata(2), token);
  await history.recordCheck(metadata(1), outcome, token); const first = history.snapshot().requests[0];
  await history.remove('requests', first.id);
  assert.equal(history.snapshot().requests.length, 1); assert.equal(history.snapshot().checks.length, 0);
  assert.equal(await history.saveRequest(bytes(1), metadata(1), token), false); history.dispose();
});
test('history is bounded and evicts oldest request/check records', async () => {
  const { history } = harness(); await history.enable(true); const token = await history.ticket();
  for (let i = 0; i < 35; i++) { await history.saveRequest(bytes(i), metadata(i), token); await history.recordCheck(metadata(i), outcome, token); }
  assert.equal(history.snapshot().requests.length, HISTORY_LIMITS.requests);
  assert.equal(history.snapshot().checks.length, HISTORY_LIMITS.checks);
  assert.equal(history.snapshot().requests[0].nonce, metadata(27).nonce);
  assert.equal(await history.saveRequest(new ArrayBuffer(4097), metadata(1), token), false);
  history.dispose();
});
test('quota errors never report a successful save', async () => {
  const { history, store } = harness(); await history.enable(true); const token = await history.ticket(); store.fail();
  assert.equal(await history.saveRequest(bytes(1), metadata(1), token), false);
  assert.equal(await history.recordCheck(metadata(1), outcome, token), null);
  assert.equal(history.snapshot().available, false); assert.equal(store.raw().requests.length, 0); history.dispose();
});
test('unavailable storage and malformed state fail locally and can be cleared without affecting crypto', async () => {
  const unavailable = harness({ read: async () => { throw new Error('Private mode'); }, update: async () => { throw new Error('Private mode'); } }).history;
  assert.equal(await unavailable.ticket(), null); assert.match(unavailable.snapshot().error, /verification still work/); unavailable.dispose();
  const broken = harness(persistence({ version: 9 })).history; await broken.refresh(); assert.equal(broken.snapshot().available, false);
  assert.equal(await broken.clear(), true); assert.equal(broken.snapshot().available, true); assert.equal(broken.snapshot().enabled, false); broken.dispose();
});
test('only completed matching crypto results create markers', async () => {
  const { history } = harness(); await history.enable(true); const token = await history.ticket();
  assert.equal(await history.recordCheck(metadata(1), { ...outcome, cryptography: 'invalid' }, token), null);
  assert.equal(await history.recordCheck(metadata(1), { ...outcome, policy: 'rejected' }, token), null);
  assert.equal(history.snapshot().checks.length, 0); history.dispose();
});
test('focus refresh does not reset unchanged history and dispose fences pending work', async () => {
  let focus; const { history } = harness(undefined, { events: { addEventListener(_, fn) { focus = fn; }, removeEventListener() {} } });
  await history.enable(true); const events = []; history.subscribe((_, kind) => events.push(kind));
  focus(); await history.refresh(); assert.equal(events.includes('reset'), false);
  const token = await history.ticket(); history.dispose(); assert.equal(await history.saveRequest(bytes(1), metadata(1), token), false);
});
test('ticket refresh detects a missed cross-tab deletion before pending work can use the new epoch', async () => {
  const store = persistence(), a = harness(store).history, b = harness(store).history;
  await a.enable(true); const token = await a.ticket();
  await a.saveRequest(bytes(1), metadata(1), token); await b.refresh();
  const events = []; a.subscribe((_, kind) => events.push(kind));
  await b.remove('requests', b.snapshot().requests[0].id);
  assert.notEqual(await a.ticket(), token); assert.equal(events.at(-1), 'reset');
  assert.equal(a.snapshot().requests.length, 0);
  await a.ticket(); assert.equal(events.at(-1), 'entries');
  a.dispose(); b.dispose();
});
