<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { setupProofInput } from './input.mjs';
import { setupProvider } from '../provider/discovery.mjs';
import { phaseLabel, failureResult, observationReasons } from './results.mjs';
import LocalHistory from '../history/LocalHistory.vue';
const props = defineProps({ wasmUrl: { type: String, required: true } });
const proof = ref(null), request = ref(null), mode = ref('none');
const network = ref(''), verifier = ref(''), purpose = ref(''), message = ref(''), confirmed = ref(false);
const result = ref(null), state = ref('idle'), error = ref(''), ready = ref(false);
const selectedNetwork = ref(''), online = ref(false), minConfirmations = ref('1'), minimumTotalSats = ref('0'), maxAge = ref('300');
const verification = ref(null), progress = ref(null), now = ref(Date.now()), startedAt = ref(null);
const history = ref(null), savedRequest = ref(null), expectedInput = ref(null), repeat = ref(false);
const busy = computed(() => ['loading', 'verifying'].includes(state.value));
const elapsed = computed(() => startedAt.value === null ? 0 : Math.max(0, Math.floor((now.value - startedAt.value) / 1000)));
const descriptor = computed(() => {
  if (!selectedNetwork.value) return null;
  const provider = setupProvider({ network: selectedNetwork.value });
  try { return provider.provider; } finally { provider.dispose(); }
});
const currentPolicy = computed(() => verification.value?.metadata && Math.floor(now.value / 1000) >= Number(verification.value.metadata.expiresAt)
  ? 'expired' : verification.value?.policy);
const reasons = computed(() => observationReasons(verification.value));
let tools, generation = 0, timer;
onMounted(() => { tools = setupProofInput({ wasmUrl: props.wasmUrl }); ready.value = true; timer = setInterval(() => { now.value = Date.now(); }, 250); });
onUnmounted(() => { generation++; tools?.dispose(); clearInterval(timer); });
function invalidate() {
  generation++; tools?.cancel(); result.value = null; verification.value = null; progress.value = null;
  startedAt.value = null; state.value = 'idle'; error.value = '';
  repeat.value = false;
}
watch([proof, request, mode, network, verifier, purpose, message, confirmed, selectedNetwork, online, minConfirmations, minimumTotalSats, maxAge], invalidate, { flush: 'sync' });
watch([network, verifier, purpose, message], () => { confirmed.value = false; }, { flush: 'sync' });
async function inspect() {
  invalidate(); const current = generation; state.value = 'loading';
  try {
    const imported = await tools.inspect({ proof: proof.value, request: request.value,
      options: { mode: mode.value, network: network.value, verifier: verifier.value,
        purpose: purpose.value, message: message.value, confirmed: confirmed.value } });
    if (current !== generation) return;
    result.value = imported; state.value = 'inspected';
  } catch (e) { if (current === generation) { error.value = e.message; state.value = 'error'; } }
}
function cancel() { invalidate(); state.value = 'cancelled'; }
function chooseSaved(row) {
  if (expectedInput.value) expectedInput.value.value = '';
  mode.value = 'request'; request.value = new File([row.bytes], row.name, { type: 'application/octet-stream' });
  savedRequest.value = row;
}
function historyReset() { invalidate(); if (savedRequest.value) { request.value = null; savedRequest.value = null; } }
function chooseFile(event) { savedRequest.value = null; request.value = event.target.files?.[0] ?? null; }
async function verify() {
  invalidate(); const current = generation; state.value = 'verifying'; startedAt.value = Date.now();
  try {
    const ticket = await history.value?.ticket();
    if (current !== generation) return;
    if (savedRequest.value && !history.value?.containsRequest(savedRequest.value.id)) {
      request.value = null; savedRequest.value = null; state.value = 'error'; error.value = 'The saved request was removed. Choose an independent expectation again.'; return;
    }
    const checked = await tools.verify({ proof: proof.value, request: request.value,
      options: { mode: mode.value, network: network.value, verifier: verifier.value, purpose: purpose.value,
        message: message.value, confirmed: confirmed.value, minConfirmations: minConfirmations.value,
        minimumTotalSats: minimumTotalSats.value, maxObservationAgeSeconds: maxAge.value },
      online: online.value, selectedNetwork: selectedNetwork.value,
      onProgress(event) { if (current === generation) progress.value = event; } });
    if (current !== generation) return;
    verification.value = checked; state.value = 'checked';
    if (checked.metadata) {
      const marker = await history.value?.recordCheck(checked.metadata, checked, ticket);
      if (current === generation) repeat.value = marker?.repeat === true;
    }
  } catch (e) {
    if (current !== generation) return;
    verification.value = failureResult(e, progress.value); state.value = 'checked';
  }
}
function timestamp(seconds) {
  const date = new Date(Number(seconds) * 1000);
  return Number.isFinite(date.getTime()) ? date.toISOString() : `${seconds} seconds since Unix epoch`;
}
</script>

<template>
  <section class="quietproof-verify" aria-label="Import a proof">
    <p>Import the .qpf returned by an external CLI or wallet. Private keys stay outside the browser. Files stay on this device. Inspection and offline verification make no explorer requests.</p>
    <p>Metadata is untrusted until cryptographic verification. A matching policy alone does not prove spend-key control, exclusive control, ownership or solvency.</p>
    <LocalHistory ref="history" selectable @select="chooseSaved" @reset="historyReset" />
    <form @submit.prevent="inspect">
      <fieldset>
        <legend>1. Choose a proof</legend>
        <label for="qp-proof">Proof file (.qpf)</label>
        <input id="qp-proof" type="file" accept=".qpf" @change="proof = $event.target.files?.[0] ?? null">
        <p>Maximum file size: 134221889 bytes (128 MiB plus envelope). Size is checked before the file is read. Decoding runs in a disposable worker.</p>
      </fieldset>
      <fieldset>
        <legend>2. Choose independent expectations</legend>
        <label for="qp-policy">Expected policy source</label>
        <select id="qp-policy" v-model="mode">
          <option value="none">Inspection only — no expected policy</option>
          <option value="request">Exact expected .qpr request</option>
          <option value="explicit">Explicit expected context</option>
        </select>
        <p>Obtain the expected request or context through your own trusted channel. Proof metadata never fills these fields.</p>
        <template v-if="mode === 'request'">
          <label for="qp-expected">Expected request file (.qpr)</label>
          <input id="qp-expected" ref="expectedInput" type="file" accept=".qpr" @change="chooseFile">
          <p v-if="savedRequest">Using explicitly selected local request: {{ savedRequest.name }}. Review its source; local storage is editable and is not authority.</p>
          <p>Maximum request size: 4096 bytes. The exact canonical statement, including nonce and claims, must match.</p>
        </template>
        <template v-if="mode === 'explicit'">
          <label for="qp-expected-network">Expected Bitcoin network</label>
          <select id="qp-expected-network" v-model="network"><option value="">Choose a network</option><option value="mainnet">Mainnet</option><option value="signet">Signet</option></select>
          <label for="qp-expected-verifier">Expected verifier</label>
          <input id="qp-expected-verifier" v-model="verifier" maxlength="256" autocomplete="off">
          <label for="qp-expected-purpose">Expected purpose</label>
          <select id="qp-expected-purpose" v-model="purpose"><option value="">Choose a purpose</option><option value="proof-of-control">Proof of control</option><option value="proof-of-funds">Proof of funds</option></select>
          <label for="qp-expected-message">Expected message (empty is allowed)</label>
          <textarea id="qp-expected-message" v-model="message" rows="3" maxlength="4096" />
          <label class="quietproof-confirm"><input v-model="confirmed" type="checkbox"> I independently chose this context, including the exact message.</label>
          <p>Context matching does not bind an independently retained nonce or exact set of claims. Prefer the exact .qpr when available.</p>
        </template>
        <p>Policy limit: request lifetime at most 86400 seconds; device clock checks freshness. Historical snapshots and bridge authorization can be inspected but are unsupported for acceptance.</p>
      </fieldset>
      <button type="submit" :disabled="!ready || busy">Inspect proof and policy</button>
      <button v-if="state === 'loading'" type="button" @click="cancel">Cancel import</button>
    </form>
    <p role="status" aria-live="polite">{{ state === 'loading' ? 'Reading and inspecting in a worker…' : state === 'cancelled' ? 'Import cancelled. No result retained.' : state === 'idle' ? 'Choose a proof to inspect.' : '' }}</p>
    <p v-if="error" role="alert">{{ error }}</p>
    <section v-if="result" aria-label="Unverified inspection" class="quietproof-inspection">
      <h2>Inspection only · cryptography not checked</h2>
      <p v-if="result.binding === 'not_checked'" role="status">No expected policy selected. Verification requires an independent expected request or context.</p>
      <p v-else-if="result.binding === 'matched'" role="status">Expected policy matched at inspection time. Cryptographic verification has not run.</p>
      <p v-else role="alert">Expected policy rejected, expired or unsupported. Do not accept this proof.</p>
      <p>Chain status: unavailable. Disconnected checking needs the local application and WASM asset; no explorer is required for policy or cryptographic checks. This import step inspects metadata only.</p>
      <dl>
        <dt>Claimed network / statement version</dt><dd>{{ result.metadata.network }} / v{{ result.metadata.statementVersion }}</dd>
        <dt>Claimed verifier / purpose</dt><dd>{{ result.metadata.verifier }} / {{ result.metadata.purpose }}</dd>
        <dt>Message hash</dt><dd>{{ result.metadata.messageHash }}</dd>
        <dt>Nonce</dt><dd>{{ result.metadata.nonce }}</dd>
        <dt>Validity window (device clock)</dt><dd>{{ timestamp(result.metadata.notBefore) }} — {{ timestamp(result.metadata.expiresAt) }}</dd>
        <dt>Envelope / circuit</dt><dd>v{{ result.metadata.envelopeVersion }} / v{{ result.metadata.circuitVersion }} · {{ result.metadata.proofBytes }} payload bytes</dd>
        <dt>Circuit digest</dt><dd>{{ result.metadata.circuitDigest }}</dd>
        <dt>Historical snapshot / bridge</dt><dd>{{ result.metadata.snapshot ? 'Present; unsupported' : 'Absent' }} / {{ result.metadata.bridge ? 'Present; unsupported' : 'Absent' }}</dd>
      </dl>
      <ul>
        <li v-for="claim in result.metadata.claims" :key="`${claim.txid}:${claim.vout}`">
          {{ claim.amountSats }} sats · {{ claim.scriptKind.toUpperCase() }}<br>{{ claim.txid }}:{{ claim.vout }}<br>Key fingerprint: {{ claim.program }}
        </li>
      </ul>
    </section>
    <fieldset>
      <legend>3. Verify proof cryptography</legend>
      <label for="qp-verification-network">Verification network (chosen independently)</label>
      <select id="qp-verification-network" v-model="selectedNetwork"><option value="">Choose a network</option><option value="mainnet">Mainnet</option><option value="signet">Signet</option></select>
      <p>The selected network must match your expected request or explicit context.</p>
      <label class="quietproof-confirm"><input v-model="online" type="checkbox"> After valid cryptography, check fresh public explorer observations</label>
      <p v-if="descriptor"><strong>Selected provider: {{ descriptor.name }}</strong><br>{{ descriptor.endpoint }}<br>{{ descriptor.trust }}</p>
      <p v-if="online">Only after you select Verify and check explorer and cryptography succeeds, funding transaction IDs and output indices are sent to this provider. No proof bytes or keys are sent. Observations are trusted and non-atomic; funding block metadata is not a current chain snapshot.</p>
      <p v-else>Offline mode checks cryptography and expected policy without explorer access. The application and WASM asset must already be available locally. Chain status remains unavailable.</p>
      <label for="qp-confirmations">Minimum confirmations</label><input id="qp-confirmations" v-model="minConfirmations" inputmode="numeric" maxlength="20">
      <label for="qp-minimum-total">Minimum unspent total (sats)</label><input id="qp-minimum-total" v-model="minimumTotalSats" inputmode="numeric" maxlength="16">
      <label for="qp-observation-age">Maximum observation age (seconds, 1–300)</label><input id="qp-observation-age" v-model="maxAge" inputmode="numeric" maxlength="3">
      <p>These limits apply to explorer assessment. Device time is untrusted. Large proofs can take minutes and need up to 2 GiB of WASM memory; verification stops after five minutes. Cancel terminates the worker.</p>
      <button type="button" :disabled="!ready || busy" @click="verify">{{ online ? 'Verify and check explorer' : 'Verify offline' }}</button>
      <button v-if="state === 'verifying'" type="button" @click="cancel">Cancel verification</button>
    </fieldset>
    <p v-if="state === 'verifying'" role="status" aria-live="polite">{{ phaseLabel[progress?.phase] ?? 'Preparing verification' }}… {{ elapsed }} seconds elapsed. Cryptography: {{ progress?.cryptography === 'valid' ? 'valid' : 'not checked yet' }}.</p>
    <section v-if="verification" aria-label="Verification results" class="quietproof-inspection">
      <h2>Separate verification results</h2>
      <p v-if="repeat" role="status">Local repeat warning: this request or nonce already has a retained check marker in this browser origin. Rechecking does not imply authorization or global replay prevention.</p>
      <dl>
        <dt>Proof cryptography</dt><dd data-result="crypto">{{ verification.cryptography === 'valid' ? 'Valid' : verification.cryptography === 'invalid' ? 'Invalid — do not accept' : 'Not checked to completion' }}</dd>
        <dt>Independent expected policy</dt><dd data-result="policy">{{ currentPolicy === 'matched' ? 'Matched at check time' : currentPolicy === 'expired' ? 'Expired according to device clock — do not accept' : currentPolicy === 'rejected' ? 'Rejected — do not accept' : 'Not checked to completion' }}</dd>
        <dt>Explorer-reported chain status</dt><dd data-result="explorer">{{ { unavailable: 'Unavailable', reported_unspent: 'Reported unspent under selected limits', reported_spent: 'Reported spent — do not accept', inconclusive: 'Inconclusive — retry or investigate' }[verification.explorer] }}</dd>
        <template v-if="verification.metadata">
          <dt>Disclosed claim total</dt><dd>{{ verification.metadata.claims.reduce((total, claim) => total + BigInt(claim.amountSats), 0n).toString() }} sats · {{ verification.metadata.network }}</dd>
          <dt>Request expires (device clock)</dt><dd>{{ timestamp(verification.metadata.expiresAt) }}</dd>
        </template>
        <template v-if="verification.expected">
          <dt>Selected observation limits</dt><dd>{{ verification.expected.minConfirmations }} confirmations; minimum {{ verification.expected.minimumTotalSats }} sats; at most {{ verification.expected.maxObservationAgeSeconds }} seconds old</dd>
          <dt>Explorer-assessed unspent total</dt><dd>{{ verification.explorer === 'reported_unspent' ? `${verification.totalSats} sats` : 'Unavailable under selected limits' }}</dd>
        </template>
        <template v-if="verification.provenance">
          <dt>Observation provider</dt><dd>{{ verification.provenance.provider }}</dd>
          <dt v-if="verification.provenance.attempts.length">Observation window (untrusted device time)</dt><dd v-for="(attempt, index) in verification.provenance.attempts" :key="index">{{ timestamp(attempt.observedAt) }} — {{ timestamp(attempt.completedAt) }}; tip {{ attempt.tipBefore.block }} → {{ attempt.tipAfter.block }}</dd>
        </template>
        <dt v-if="verification.checkedAt">Check completed (device clock)</dt><dd v-if="verification.checkedAt">{{ timestamp(verification.checkedAt) }}</dd>
      </dl>
      <ul v-if="reasons.length"><li v-for="reason in reasons" :key="reason">{{ reason }}</li></ul>
      <p>This static tool does not authorize acceptance. Explorer reports do not establish strict current or historical chain validity. Proofs disclose coins and wallet links. Key access may be shared or temporary; a proof does not establish exclusive control, ownership or solvency.</p>
      <button type="button" @click="verify">Retry verification</button>
    </section>
    <p>Supported browsers: Chromium and WebKit; Firefox is unsupported and unqualified. This static tool has no server or global acceptance authority.</p>
  </section>
</template>

<style scoped>
.quietproof-verify { overflow-wrap: anywhere; line-height: 1.6; }
.quietproof-verify p, .quietproof-verify li { line-height: 1.6; }
fieldset { min-width: 0; border: 1px solid var(--vp-c-divider); border-radius: .5rem; padding: 1rem; margin: 1.25rem 0; }
legend, dt { font-weight: 700; }
label { display: block; font-weight: 600; margin-top: 1rem; }
input:not([type=checkbox]), textarea, select { display: block; width: 100%; min-width: 0; box-sizing: border-box; border: 1px solid var(--vp-c-text-2); border-radius: .25rem; padding: .65rem; color: var(--vp-c-text-1); background: var(--vp-c-bg); font: inherit; }
/* WebKit's native select can contribute its full option text to fieldset
   overflow at enlarged text sizes even while its border box fits. */
select { overflow: hidden; }
button { font: inherit; font-weight: 600; border: 1px solid var(--vp-c-brand-1); border-radius: .25rem; min-height: 44px; padding: .6rem 1rem; margin: .5rem .5rem .5rem 0; color: var(--vp-c-brand-1); }
button:disabled { opacity: .65; }
:is(input, textarea, select, button):focus-visible { outline: 3px solid var(--planb-color-focus, var(--vp-c-brand-1)); outline-offset: 3px; }
.quietproof-confirm { min-height: 44px; }
.quietproof-confirm input { width: 1.25rem; height: 1.25rem; }
.quietproof-inspection { border-top: 2px solid var(--vp-c-divider); padding-top: 1rem; margin-top: 1.5rem; }
dt { margin-top: .75rem; } dd { margin: .25rem 0; } li { margin-block: .75rem; }
</style>
