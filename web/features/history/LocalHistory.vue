<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { setupHistory } from './history.mjs';
const props = defineProps({ selectable: { type: Boolean, default: false } });
const emit = defineEmits(['select', 'reset']);
const state = ref({ enabled: false, available: true, requests: [], checks: [], synchronized: true, error: '' });
const ready = ref(false), pending = ref(false), notice = ref('');
let history, unsubscribe;
const duplicates = computed(() => {
  const seen = new Set(); let count = 0;
  for (const row of state.value.checks) { const key = `${row.network}:${row.nonce}`; if (seen.has(key)) count++; seen.add(key); }
  return count;
});
onMounted(async () => {
  history = setupHistory();
  unsubscribe = history.subscribe((value, kind) => {
    state.value = value;
    if (kind === 'reset') { notice.value = 'Local history changed or was cleared. Pending work was cancelled.'; emit('reset'); }
  });
  await history.refresh(); ready.value = true;
});
onUnmounted(() => { unsubscribe?.(); history?.dispose(); });
async function enable(event) { pending.value = true; await history.enable(event.target.checked); event.target.checked = state.value.enabled; pending.value = false; }
async function clear() { pending.value = true; const ok = await history.clear(); notice.value = ok ? 'Local history cleared and turned off.' : ''; pending.value = false; }
async function remove(kind, id) { pending.value = true; const ok = await history.remove(kind, id); notice.value = ok ? 'Local entry deleted. Pending work was cancelled.' : ''; pending.value = false; }
function choose(row) { emit('select', { id: row.id, bytes: row.bytes.slice(0), name: `saved-${row.nonce.slice(0, 16)}.qpr` }); }
async function saveRequest(bytes, metadata, token) {
  const saved = await history?.saveRequest(bytes, metadata, token);
  if (saved) notice.value = 'Canonical request saved locally.';
  else if (!state.value.error) notice.value = 'No request was saved. Enable local history first; deleting or clearing during creation also prevents saving.';
  return saved;
}
defineExpose({ ticket: () => history?.ticket() ?? Promise.resolve(null), saveRequest,
  containsRequest: id => state.value.requests.some(row => row.id === id),
  recordCheck: (metadata, outcome, token) => history?.recordCheck(metadata, outcome, token) ?? Promise.resolve(null) });
</script>

<template>
  <section class="quietproof-history" aria-label="Local request history">
    <h2>Local request history</h2>
    <p v-if="state.error" role="alert">{{ state.error }}</p>
    <p v-else role="status">{{ state.enabled ? `${state.requests.length} saved requests; ${state.checks.length} completed check markers.` : 'Local history is off. Nothing new is saved.' }}</p>
    <p v-if="notice" role="status">{{ notice }}</p>
    <p v-if="duplicates" role="status">Local repeat warning: {{ duplicates }} repeated check marker(s) for retained request nonces. This is not authorization or global replay prevention.</p>
    <details :open="state.enabled">
    <summary>Manage local history (optional)</summary>
    <p>Optional, unencrypted history in this browser profile and origin only. Saved requests disclose coins, amounts, wallet links, verifier, nonce and message hash. Check markers contain request fingerprints and outcomes; proof files and private keys are never stored.</p>
    <label class="quietproof-history-consent"><input type="checkbox" :checked="state.enabled" :disabled="!ready || pending || !state.available" @change="enable"> Keep future requests and completed check records locally</label>
    <p>This is a convenience, not authorization or global replay prevention. Clearing storage, private sessions, other profiles, origins and devices reset local warnings. Other tabs may already hold copies; same-origin code can read or change this data. Device times are untrusted.</p>
    <p>At most 8 requests and 24 check markers are retained; oldest entries are removed. Deleting or clearing history cancels pending work in connected app tabs. Reinspection and repeat warnings never establish acceptance.</p>
    <p v-if="!state.synchronized">Immediate tab notifications are unavailable. Focus or reload a tab to refresh its list; transactional writes still fence cleared history.</p>
    <button type="button" :disabled="!ready || pending" @click="clear">Clear history and turn off</button>
    <ul v-if="state.requests.length">
      <li v-for="row in state.requests" :key="row.id">
        <strong>{{ row.verifier }} · {{ row.network }}</strong><br>Nonce {{ row.nonce }}<br>Expiry {{ row.expiresAt }} (Unix seconds; device-clock policy)
        <button v-if="props.selectable" type="button" @click="choose(row)">Use saved request as explicit expectation</button>
        <button type="button" @click="remove('requests', row.id)">Delete saved request {{ row.nonce.slice(0, 8) }}</button>
      </li>
    </ul>
    <ul v-if="state.checks.length">
      <li v-for="row in state.checks" :key="row.id">
        Local check · {{ row.network }} · {{ { unavailable: 'Chain observations unavailable', reported_unspent: 'Explorer reported unspent', reported_spent: 'Explorer reported spent', inconclusive: 'Explorer observations inconclusive' }[row.explorer] }}<br>Request fingerprint {{ row.hash }}<br>Device time {{ row.time }} (Unix seconds)
        <button type="button" @click="remove('checks', row.id)">Delete check marker</button>
      </li>
    </ul>
    </details>
  </section>
</template>

<style scoped>
.quietproof-history { overflow-wrap: anywhere; border-block: 1px solid var(--vp-c-divider); margin-block: 1.5rem; padding-block: 1rem; line-height: 1.6; }
.quietproof-history p, .quietproof-history li { line-height: 1.6; }
.quietproof-history-consent { display: block; min-height: 44px; font-weight: 600; }
summary { cursor: pointer; min-height: 44px; font-weight: 600; }
input { width: 1.25rem; height: 1.25rem; }
button { font: inherit; color: var(--vp-c-brand-1); border: 1px solid var(--vp-c-brand-1); border-radius: .25rem; padding: .6rem; min-height: 44px; margin: .5rem .5rem .5rem 0; }
button:disabled { opacity: .65; }
:is(input, button):focus-visible { outline: 3px solid var(--planb-color-focus, var(--vp-c-brand-1)); outline-offset: 3px; }
</style>
