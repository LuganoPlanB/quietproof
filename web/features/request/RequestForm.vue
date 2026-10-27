<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { setupProvider } from '../provider/discovery.mjs';
import { lookupError, selectionSummary, validateForm } from './form.mjs';
import { setupRequest, setupDownload } from './download.mjs';

const props = defineProps({ wasmUrl: { type: String, required: true } });

const network = ref('mainnet'), addresses = ref(''), claims = ref([]), selected = ref([]);
const verifier = ref(''), purpose = ref('proof-of-control'), message = ref(''), lifetime = ref('300');
const state = ref('idle'), error = ref(''), provider = ref(null), now = ref(Date.now());
let adapter, generation = 0, timer;
let requestTools, download, requestGeneration = 0;
const requestState = ref('idle'), requestError = ref(''), preview = ref(null), artifact = ref(null);
function invalidateRequest() {
  requestGeneration++; requestTools?.cancel(); download?.clear();
  preview.value = null; artifact.value = null; requestState.value = 'idle'; requestError.value = '';
}
function reset() {
  generation++; adapter?.dispose();
  adapter = setupProvider({ network: network.value }); provider.value = adapter.provider;
  claims.value = []; selected.value = []; state.value = 'idle'; error.value = '';
}
onMounted(() => {
  reset(); requestTools = setupRequest({ wasmUrl: props.wasmUrl }); download = setupDownload();
  timer = setInterval(() => { now.value = Date.now(); }, 1000);
});
onUnmounted(() => { generation++; adapter?.dispose(); requestTools?.dispose(); download?.clear(); clearInterval(timer); });
watch(network, reset);
watch([network, addresses, selected, verifier, purpose, message, lifetime], invalidateRequest, { deep: true, flush: 'sync' });
watch(addresses, () => {
  // Editing an address invalidates and cancels even an already pending lookup.
  if (adapter) reset();
});
const chosen = computed(() => claims.value.filter((_, i) => selected.value.includes(i)));
const summary = computed(() => selectionSummary(chosen.value));
const options = computed(() => ({ network: network.value, claims: chosen.value, verifier: verifier.value,
  purpose: purpose.value, message: message.value, lifetimeSeconds: lifetime.value }));
const validation = computed(() => { try { validateForm(options.value); return ''; } catch (e) { return e.message; } });
const expiry = computed(() => /^[1-9][0-9]*$/.test(lifetime.value) && Number(lifetime.value) <= 86400
  ? new Date(now.value + Number(lifetime.value) * 1000).toISOString() : 'Choose a valid lifetime');
function blocked(index) {
  if (selected.value.includes(index)) return false;
  try { selectionSummary([...chosen.value, claims.value[index]]); return false; } catch { return true; }
}
async function lookup() {
  invalidateRequest();
  const operation = ++generation;
  claims.value = []; selected.value = []; error.value = ''; state.value = 'loading';
  try {
    const result = await adapter.discover({ addresses: addresses.value.split(/\r?\n/).map(a => a.trim()).filter(Boolean) });
    if (operation !== generation) return;
    claims.value = result.claims; state.value = result.claims.length ? 'ready' : 'empty';
  } catch (e) { if (operation === generation) { state.value = 'error'; error.value = lookupError(e); } }
}
const requestExpired = computed(() => preview.value && Math.floor(now.value / 1000) >= Number(preview.value.metadata.expiresAt));
function timestamp(seconds) { return new Date(Number(seconds) * 1000).toISOString(); }
async function createRequest() {
  invalidateRequest();
  const operation = requestGeneration;
  try {
    validateForm(options.value); requestState.value = 'creating';
    const result = await requestTools.create(options.value);
    if (operation !== requestGeneration) return;
    preview.value = result; artifact.value = download.replace(result.bytes, result.metadata);
    requestState.value = 'ready';
  } catch (e) {
    if (operation !== requestGeneration) return;
    requestState.value = e.name === 'AbortError' ? 'cancelled' : 'error';
    requestError.value = e.name === 'AbortError' ? '' : e.message;
  }
}
function cancelRequest() { invalidateRequest(); requestState.value = 'cancelled'; }
</script>

<template>
  <section class="quietproof-request" aria-label="Create a request">
    <p>Choose disclosed Bitcoin outputs to request proof of spend-key control. Proving happens in the external CLI or a wallet; keep private keys there.</p>
    <p>This static tool has no authoritative challenge service. A proof does not establish exclusive control, ownership, reserves or solvency.</p>
    <form @submit.prevent="lookup">
      <fieldset>
        <legend>1. Find outputs</legend>
        <label for="qp-network">Bitcoin network</label>
        <select id="qp-network" v-model="network"><option value="mainnet">Mainnet</option><option value="signet">Signet</option></select>
        <p v-if="provider" class="quietproof-provider"><strong>Provider: {{ provider.name }}</strong><br>{{ provider.endpoint }}<br>{{ provider.privacy }}</p>
        <p>Nothing is sent until you select Look up outputs. Explorer reports are trusted, non-atomic observations, not authenticated chain snapshots. Funding block metadata does not establish current unspentness.</p>
        <label for="qp-addresses">Bitcoin addresses (one or two, one per line)</label>
        <textarea id="qp-addresses" v-model="addresses" rows="3" maxlength="182" spellcheck="false" autocomplete="off" aria-describedby="qp-scripts" required />
        <p id="qp-scripts">Supported: compressed-key P2PKH and native P2WPKH (a common Bitcoin address with a key fingerprint). Taproot, multisig, P2SH and P2WSH are unsupported. Signet shares testnet address encoding; the chosen endpoint determines the network.</p>
        <button type="submit" :disabled="!provider || state === 'loading'">Look up outputs</button>
        <button v-if="state === 'loading'" type="button" @click="reset">Cancel lookup</button>
      </fieldset>
    </form>
    <p role="status" aria-live="polite">{{ state === 'loading' ? 'Looking up outputs…' : state === 'empty' ? 'No unspent outputs reported for these addresses.' : state === 'ready' ? `${claims.length} outputs reported. Select the outputs to disclose.` : state === 'idle' ? 'Ready for an explicit lookup.' : '' }}</p>
    <p v-if="error" role="alert">{{ error }}</p>
    <fieldset v-if="claims.length" :aria-busy="state === 'loading'">
      <legend>2. Select disclosed outputs</legend>
      <p>At most 16 outputs and two distinct key fingerprints. Selected coins, amounts and wallet links become public to the proof recipient. Fresh chain observations are needed when verifying a proof.</p>
      <ul class="quietproof-claims">
        <li v-for="(claim, index) in claims" :key="`${claim.txid}:${claim.vout}`">
          <label :for="`qp-claim-${index}`"><input :id="`qp-claim-${index}`" v-model="selected" type="checkbox" :value="index" :disabled="blocked(index)">
            <strong>{{ claim.amountSats }} sats · {{ claim.scriptKind.toUpperCase() }}</strong>
            <span class="quietproof-outpoint">{{ claim.txid }}:{{ claim.vout }}</span>
            <span>{{ claim.address }} · {{ claim.funding.confirmed ? 'Funding confirmed (provider report)' : 'Funding unconfirmed (provider report)' }}</span>
            <span v-if="blocked(index)">Selection limit reached; deselect an output to add this one.</span>
          </label>
        </li>
      </ul>
    </fieldset>
    <p class="quietproof-total" role="status">Selected: {{ summary.count }}/16 outputs · {{ summary.keys }}/2 key fingerprints · <strong>{{ summary.totalSats }} sats</strong></p>
    <fieldset>
      <legend>3. Set the request context</legend>
      <label for="qp-verifier">Intended verifier (up to 256 UTF-8 bytes)</label>
      <input id="qp-verifier" v-model="verifier" maxlength="256" autocomplete="off" required>
      <label for="qp-purpose">Purpose</label>
      <select id="qp-purpose" v-model="purpose"><option value="proof-of-control">Proof of control</option><option value="proof-of-funds">Proof of funds</option></select>
      <label for="qp-message">Message (optional, up to 4096 UTF-8 bytes)</label>
      <textarea id="qp-message" v-model="message" maxlength="4096" rows="3" />
      <label for="qp-lifetime">Request lifetime in seconds (1–86400)</label>
      <input id="qp-lifetime" v-model="lifetime" type="number" min="1" max="86400" step="1" required aria-describedby="qp-expiry">
      <p id="qp-expiry">Default: 300 seconds. Estimated expiry if created now: <strong>{{ expiry }}</strong>. Your device clock is untrusted; the final request will show its committed expiry.</p>
      <p role="status">{{ validation || 'Selection and context are ready for request creation.' }}</p>
    </fieldset>
    <button type="button" :disabled="!!validation || requestState === 'creating'" @click="createRequest">{{ preview ? 'Regenerate request' : 'Create request' }}</button>
    <button v-if="requestState === 'creating'" type="button" @click="cancelRequest">Cancel creation</button>
    <p role="status">{{ requestState === 'creating' ? 'Creating the canonical request…' : requestState === 'cancelled' ? 'Request creation cancelled. You can retry.' : requestState === 'ready' ? 'Request created. Review the committed facts before downloading.' : '' }}</p>
    <p v-if="requestError" role="alert">{{ requestError }}</p>
    <section v-if="preview" class="quietproof-preview" aria-label="Canonical request preview">
      <h2>Review the request</h2>
      <p>These facts were decoded from the canonical request. Editing any input clears this preview. A new creation generates a fresh nonce.</p>
      <dl>
        <dt>Network · statement version</dt><dd>{{ preview.metadata.network }} · v{{ preview.metadata.statementVersion }}</dd>
        <dt>Intended verifier</dt><dd>{{ preview.metadata.verifier }}</dd>
        <dt>Purpose</dt><dd>{{ preview.metadata.purpose }}</dd>
        <dt>Created at (device clock)</dt><dd>{{ timestamp(preview.metadata.notBefore) }}</dd>
        <dt>Committed expiry (device clock)</dt><dd>{{ timestamp(preview.metadata.expiresAt) }}</dd>
        <dt>Nonce</dt><dd class="quietproof-outpoint">{{ preview.metadata.nonce }}</dd>
        <dt>Message commitment (BIP322 hash)</dt><dd class="quietproof-outpoint">{{ preview.metadata.messageHash }}</dd>
        <dt>Disclosed total</dt><dd>{{ preview.summary.totalSats }} sats · {{ preview.summary.count }} outputs · {{ preview.summary.keys }} key fingerprints</dd>
      </dl>
      <ul class="quietproof-claims">
        <li v-for="claim in preview.metadata.claims" :key="`${claim.txid}:${claim.vout}`">
          <strong>{{ claim.amountSats }} sats · {{ claim.scriptKind.toUpperCase() }}</strong>
          <span class="quietproof-outpoint">{{ claim.txid }}:{{ claim.vout }}</span>
          <span class="quietproof-outpoint">Key fingerprint: {{ claim.program }}</span>
        </li>
      </ul>
      <p v-if="requestExpired" role="status">This request has expired according to your device clock. Regenerate it before sending it to a prover.</p>
      <a v-else-if="artifact" class="quietproof-download" :href="artifact.url" :download="artifact.filename">Download .qpr request</a>
      <h3>Prove outside the browser</h3>
      <p>Send this request to the prover through your chosen channel. On the prover’s machine, inspect it and use the existing CLI with protected key input or a supported wallet. Private keys stay outside this page.</p>
      <pre><code>quietproof inspect {{ artifact?.filename }}
quietproof prove --request {{ artifact?.filename }} --output proof.qpf --network {{ preview.metadata.network }}</code></pre>
      <p>The CLI prompts for protected key input. See the auditor workflow for wallet options. Return the resulting .qpf proof to the verifier together with this exact expected .qpr request. Request creation does not check a proof or authenticate current chain state.</p>
    </section>
    <p>Historical snapshots and bridge authorization are unavailable in this workflow. Supported browsers: Chromium and WebKit; Firefox is unsupported and unqualified.</p>
  </section>
</template>

<style scoped>
.quietproof-request { overflow-wrap: anywhere; line-height: 1.6; }
.quietproof-request p, .quietproof-request li { line-height: 1.6; }
fieldset { border: 1px solid var(--vp-c-divider); border-radius: .5rem; padding: 1rem; margin: 1.25rem 0; min-width: 0; }
legend { font-weight: 700; padding: 0 .35rem; }
label { display: block; font-weight: 600; margin-top: 1rem; }
input:not([type=checkbox]), textarea, select { display: block; width: 100%; box-sizing: border-box; border: 1px solid var(--vp-c-text-2); border-radius: .25rem; padding: .65rem; color: var(--vp-c-text-1); background: var(--vp-c-bg); font: inherit; }
button { font: inherit; font-weight: 600; border: 1px solid var(--vp-c-brand-1); border-radius: .25rem; min-height: 44px; padding: .6rem 1rem; margin: .5rem .5rem .5rem 0; color: var(--vp-c-brand-1); }
button:disabled { opacity: .65; cursor: wait; }
:is(input, textarea, select, button):focus-visible { outline: 3px solid var(--planb-color-focus, var(--vp-c-brand-1)); outline-offset: 3px; }
.quietproof-claims { list-style: none; padding: 0; }
.quietproof-claims li { border-top: 1px solid var(--vp-c-divider); padding: .5rem 0; }
.quietproof-claims label { font-weight: 400; cursor: pointer; margin: 0; min-height: 44px; }
.quietproof-claims input { width: 1.25rem; height: 1.25rem; margin-right: .5rem; }
.quietproof-claims span { display: block; margin: .35rem 0; }
.quietproof-outpoint { font-family: var(--vp-font-family-mono); font-size: .9em; }
.quietproof-total { border-block: 2px solid var(--vp-c-divider); padding: 1rem 0; }
.quietproof-preview { border-top: 2px solid var(--vp-c-divider); margin-top: 1.5rem; padding-top: 1rem; }
dt { font-weight: 700; margin-top: .75rem; }
dd { margin: .25rem 0; }
.quietproof-download { display: inline-block; padding: .65rem 1rem; border: 1px solid var(--vp-c-brand-1); border-radius: .25rem; min-height: 44px; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; padding: 1rem; background: var(--vp-c-bg-alt); }
</style>
