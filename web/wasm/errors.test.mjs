import { test } from 'node:test';
import assert from 'node:assert/strict';
import { unsupportedArtifactError } from './errors.mjs';
test('unsupported artifact guidance is bounded and never echoes untrusted worker text',()=>{
  for(const [message,code,pattern] of [['unsupported_posc_v3','unsupported_posc_v3',/fresh v4/],
    ['signature_mode_disabled','signature_mode_disabled',/unavailable/],['UNTRUSTED','unsupported_artifact',/profile.*unsupported/]]) {
    const error=unsupportedArtifactError({name:'UnsupportedError',message});
    assert.equal(error.code,code);assert.match(error.message,pattern);assert(!error.message.includes('UNTRUSTED'));
  }
  assert.equal(unsupportedArtifactError({name:'Error',message:'unsupported_posc_v3'}),null);
});
