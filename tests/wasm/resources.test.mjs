import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cappedMemoryArtifact, RESOURCE_BUDGETS } from './resources.mjs';

test('controlled memory fixture changes only maximum pages with valid padded LEB encoding', () => {
  // One memory, initial 256 pages, original max 32768 pages; no functions.
  const bytes = Uint8Array.from([0,97,115,109,1,0,0,0,5,7,1,1,128,2,128,128,2]);
  const capped = cappedMemoryArtifact(bytes);
  assert(WebAssembly.validate(bytes)); assert(WebAssembly.validate(capped));
  assert.deepEqual([...bytes.slice(0,14)], [...capped.slice(0,14)]);
  assert.deepEqual([...capped.slice(14)], [128,192,0]);
  assert.deepEqual([...bytes.slice(14)], [128,128,2], 'source artifact stays untouched');
  for (const max of [0,255,32768,NaN,1.5]) assert.throws(() => cappedMemoryArtifact(bytes,max));
  assert.throws(() => cappedMemoryArtifact(bytes.slice(0,10)));
  assert(RESOURCE_BUDGETS.linearMemoryBytes < 2 * 1024 ** 3);
});
