import { test } from 'node:test';
import assert from 'node:assert/strict';
import { roundtrips, witnessAddress, observationResponse } from './fixtures.mjs';
import { fixtures } from '../features/provider/fixtures.mjs';
import { setupProvider } from '../features/provider/discovery.mjs';

test('matrix uniquely covers both networks and all one/two-key supported script compositions', async () => {
  assert.equal(roundtrips.length,10); assert.equal(new Set(roundtrips.map(w=>w.id)).size,10);
  for (const network of ['mainnet','signet']) {
    const selected=roundtrips.filter(w=>w.network===network);
    assert.deepEqual(selected.map(w=>w.claims.map(c=>c.scriptKind).join('+')).sort(),
      ['p2pkh','p2pkh+p2pkh','p2wpkh','p2wpkh+p2pkh','p2wpkh+p2wpkh'].sort());
    assert.equal(witnessAddress(network,fixtures.program),fixtures[network].p2wpkh);
  }
  for (const workflow of roundtrips) {
    const provider=setupProvider({network:workflow.network,fetch:async url=>{
      const response=observationResponse(workflow,url);return new Response(response.body??JSON.stringify(response.json));
    }});
    try {
      const result=await provider.discover({addresses:workflow.claims.map(c=>c.address)});
      assert.equal(result.claims.length,workflow.keyCount);
      assert.deepEqual(result.claims.map(c=>({program:c.program,scriptKind:c.scriptKind,amountSats:c.amountSats})),
        workflow.claims.map(c=>({program:c.program,scriptKind:c.scriptKind,amountSats:c.amountSats})));
      assert.equal(new Set(result.claims.map(c=>c.program)).size,workflow.keyCount);
    } finally {provider.dispose();}
  }
});
