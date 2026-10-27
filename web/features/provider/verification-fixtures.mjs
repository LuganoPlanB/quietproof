import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { setupProvider } from './discovery.mjs';
import { fixtures, outputFixture } from './fixtures.mjs';

// This double checks orchestration/transport contracts only. The companion
// browser test exercises the actual cryptographic worker and WASM evaluator.
export function verificationHarness({ change, respond, invalid = false, policyError = false, network = 'mainnet', timeoutMs, holdWorker, claims } = {}) {
  const data = outputFixture(); change?.(data);
  const claim = { txid: fixtures.txid, vout: 0, amountSats: '12345', scriptKind: 'p2wpkh', program: fixtures.program };
  const manifestClaims = claims ?? [claim];
  const requests = [], workers = [], evidence = [];
  const policy = { network, verifier: 'test', purpose: 'proof-of-funds', message: '',
    provider: network === 'mainnet' ? 'https://blockstream.info/api' : 'https://blockstream.info/signet/api',
    maxLifetimeSeconds: 3600, minConfirmations: 1, minimumTotalSats: 12345, maxObservationAgeSeconds: 60 };
  class FixtureWorker extends EventTarget {
    terminated = false;
    messages = [];
    terminate() { this.terminated = true; }
    postMessage(input, transfer) {
      const message = structuredClone(input, { transfer }); this.messages.push(message);
      if (holdWorker?.(message)) return;
      const common = { id: message.id, type: 'result', operationId: 2, contextId: 1,
        policy: 'matched', authorizes: false, explorer: 'unavailable', totalSats: '0' };
      let result;
      if (message.type === 'initialize') result = { ...common, type: 'ready', abiVersion: 2 };
      else if (message.type === 'prepare') result = policyError ? { ...common, type: 'error', name: 'PolicyError' }
        : { ...common, phase: 'prepared', phaseToken: '2:1:prepared', cryptography: 'not_checked' };
      else if (message.type === 'verify') result = { ...common, phase: invalid ? 'finished' : 'verified',
        phaseToken: '2:1:verified', cryptography: invalid ? 'invalid' : 'valid',
        manifest: invalid ? null : { network, claims: manifestClaims } };
      else {
        assert.equal(message.operationId, 2); assert.equal(message.phaseToken, '2:1:verified');
        const e = message.evidence; evidence.push(e);
        const stale = Math.floor(Date.now() / 1000) - e.observedAt > policy.maxObservationAgeSeconds;
        const bad = e.claims.some((c, i) => {
          const expected = manifestClaims[i], script = expected.scriptKind === 'p2wpkh' ? '0014' + expected.program : '76a914' + expected.program + '88ac';
          return c.txid !== expected.txid || c.vout !== expected.vout || c.amountSats !== expected.amountSats || c.scriptPubKey !== script ||
            !c.inBestChain || !['unspent', 'spent'].includes(c.status) || c.confirmations < policy.minConfirmations;
        }) || stale || e.tipBefore.block !== e.tipAfter.block || e.tipBefore.height !== e.tipAfter.height;
        result = { ...common, phase: 'finished', cryptography: 'valid',
          explorer: bad ? 'inconclusive' : e.claims.some(c => c.status === 'spent') ? 'reported_spent' : 'reported_unspent' };
      }
      queueMicrotask(() => { if (!this.terminated) this.dispatchEvent(new MessageEvent('message', { data: structuredClone(result) })); });
    }
  }
  const adapter = setupProvider({ network, crypto: webcrypto, timeoutMs,
    workerFactory: () => { const worker = new FixtureWorker(); workers.push(worker); return worker; },
    fetch: async (url, options) => {
      requests.push({ url, options });
      if (respond) { const response = await respond(url, options); if (response !== undefined) return response; }
      let value;
      if (url.endsWith('/block-height/0')) return new Response(fixtures[network].genesis);
      if (url.endsWith('/blocks/tip/hash')) return new Response('56'.repeat(32));
      if (url.endsWith('/block-height/100')) return new Response(fixtures.block);
      if (/\/outspend\/[0-9]+$/.test(url)) value = { spent: false };
      else if (url.endsWith(`/tx/${fixtures.txid}/status`)) value = data.tx.status;
      else if (url.endsWith(`/tx/${fixtures.txid}`)) value = data.tx;
      else if (url.endsWith('/status')) value = { in_best_chain: true };
      else value = { id: url.split('/').pop(), height: 110 };
      return new Response(JSON.stringify(value));
    } });
  return { ...adapter, data, policy, requests, workers, evidence,
    run: (extra = {}) => adapter.verify({ proof: new ArrayBuffer(1), wasmBytes: new ArrayBuffer(1), policy, ...extra }) };
}
