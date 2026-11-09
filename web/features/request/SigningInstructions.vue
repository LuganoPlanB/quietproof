<script setup>
import { ref } from 'vue';
defineProps({ material: { type: Object, required: true } });
const copied = ref('');
async function copy(value, label) {
  try { await navigator.clipboard.writeText(value); copied.value = `${label} copied.`; }
  catch { copied.value = 'Clipboard unavailable. Select the text above and copy it manually.'; }
}
</script>

<template>
  <section class="quietproof-signing" aria-label="Wallet signing instructions">
    <h3>Sign this request in your wallet</h3>
    <p>Use <strong>{{ material.label }}</strong> for <strong class="signing-address">{{ material.address }}</strong>.</p>
    <label for="qp-signing-message">Exact message to sign</label>
    <textarea id="qp-signing-message" :value="material.message" readonly rows="3" spellcheck="false" />
    <button type="button" @click="copy(material.message, 'Message')">Copy signing message</button>
    <p>Copy all 88 ASCII characters, without adding spaces or a newline. This message commits to the entire request, including its outputs, verifier, signing procedure and expiry.</p>
    <template v-if="material.command">
      <h4>Bitcoin Core or Bitcoin Roots · RPC</h4>
      <p v-if="material.simple">Requires a Core or Roots build with BIP322 support in <code>signmessage</code>. A legacy-only build cannot sign this SegWit request.</p>
      <p v-else>Uses the existing <code>signmessage</code> RPC for a compressed-key P2PKH address.</p>
      <label for="qp-signing-command">RPC command</label>
      <textarea id="qp-signing-command" :value="material.command" readonly rows="4" spellcheck="false" />
      <button type="button" @click="copy(material.command, 'RPC command')">Copy RPC command</button>
      <p>Run with the wallet’s <code>bitcoin-cli</code>. Connects to localhost on the default {{ material.network }} port, {{ material.port }}, using your configured RPC authentication or local cookie. The wallet must be loaded and unlocked for signing. If more than one wallet is loaded, add <code>-rpcwallet="WALLET_NAME"</code> before <code>signmessage</code>.</p>
      <h4>Sparrow · Sign/Verify Message</h4>
      <p>Sparrow has no equivalent public signing RPC. Open <strong>Tools → Sign/Verify Message</strong>, enter the address above, paste the exact message, choose <strong>{{ material.simple ? 'BIP322 Simple' : 'Standard (Electrum)' }}</strong>, then sign and copy the signature.</p>
      <p>Give the signature directly to your native prover as <code>{{ material.format }}</code>. Keep signatures and private authorization receipts out of this page.</p>
    </template>
    <template v-else>
      <h4>Bitcoin Core or Bitcoin Roots · native authorization</h4>
      <p>P2PKH BIP322 Full requires the native QuietProof <code>authorize</code> adapter. The <code>signmessage</code> RPC returns a legacy signature for this address, not BIP322 Full. Download the request and follow the Core signing guide, or regenerate it with the default Bitcoin Signed Message procedure.</p>
      <h4>Sparrow</h4>
      <p>Sparrow’s message dialog does not produce this P2PKH BIP322 Full transport. Use native authorization or regenerate the request with the default legacy signing procedure.</p>
    </template>
    <p role="status" aria-live="polite">{{ copied }}</p>
  </section>
</template>

<style scoped>
.quietproof-signing { margin-block: 1.5rem; padding: 1rem; border: 1px solid var(--vp-c-divider); border-radius: .5rem; min-width: 0; }
label { display: block; font-weight: 600; margin-top: 1rem; }
textarea { display: block; width: 100%; box-sizing: border-box; padding: .75rem; border: 1px solid var(--vp-c-text-2); border-radius: .25rem; color: var(--vp-c-text-1); background: var(--vp-c-bg); font: .9em/1.6 var(--vp-font-family-mono); resize: vertical; overflow-wrap: anywhere; }
button { font: inherit; font-weight: 600; border: 1px solid var(--vp-c-brand-1); border-radius: .25rem; min-height: 44px; padding: .6rem 1rem; margin-top: .5rem; color: var(--vp-c-brand-1); }
:is(textarea, button):focus-visible { outline: 3px solid var(--planb-color-focus, var(--vp-c-brand-1)); outline-offset: 3px; }
.signing-address { overflow-wrap: anywhere; }
</style>
