import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probeProofCapabilities } from './capabilities.mjs';
for (const supported of [true,false]) test(`explicit probe reports signature support=${supported} and terminates worker`, async () => {
  let terminated=0;
  const result=await probeProofCapabilities({ wasmUrl:'/verifier.wasm', fetch:async()=>new Response(new Uint8Array([1])),
    workerFactory:()=>({ terminate() { terminated++; }, postMessage(data, transfer) {
      assert.deepEqual(Object.keys(data).sort(),['bytes','id','type']); assert(transfer.includes(data.bytes));
      queueMicrotask(()=>this.onmessage({ data:{ id:data.id,type:'ready',abiVersion:2,
        capabilities:{ keyKnowledge:true,signaturePossession:supported } } }));
    } }) });
  assert.equal(result.signaturePossession,supported); assert.equal(terminated,1);
});
test('probe never infers signature support from a missing capability response', async () => {
  let terminated=0;
  await assert.rejects(probeProofCapabilities({ wasmUrl:'/verifier.wasm', fetch:async()=>new Response(new Uint8Array([1])),
    workerFactory:()=>({ terminate() { terminated++; }, postMessage(data) {
      queueMicrotask(()=>this.onmessage({ data:{ id:data.id,type:'ready',abiVersion:2 } }));
    } }) }),/did not report/);
  assert.equal(terminated,1);
});
test('stalled capability worker times out explicitly and is terminated', async () => {
  let terminated=0;
  await assert.rejects(probeProofCapabilities({ wasmUrl:'/verifier.wasm', timeoutMs:10,
    fetch:async()=>new Response(new Uint8Array([1])),
    workerFactory:()=>({ terminate() { terminated++; }, postMessage() {} }) }),/timed out/);
  assert.equal(terminated,1);
});
test('caller cancellation terminates the capability worker', async () => {
  const controller=new AbortController();let terminated=0;
  await assert.rejects(probeProofCapabilities({ wasmUrl:'/verifier.wasm', signal:controller.signal,
    fetch:async()=>new Response(new Uint8Array([1])),
    workerFactory:()=>({ terminate() { terminated++; }, postMessage() { queueMicrotask(()=>controller.abort()); } }) }),
    error=>error.name==='AbortError');
  assert.equal(terminated,1);
});
