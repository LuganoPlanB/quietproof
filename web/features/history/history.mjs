// Browser-local convenience only. No proof payload or acceptance decision is stored.
export const HISTORY_LIMITS = Object.freeze({ requests: 8, checks: 24, requestBytes: 4096, totalBytes: 65536 });
const DATABASE = 'quietproof-local-history-v1';
const CHANNEL = 'quietproof-local-history-v1';
const empty = () => ({ version: 1, enabled: false, epoch: '', requests: [], checks: [] });
const hex = /^[0-9a-f]{64}$/;
const uint = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value);
const text = (value, maximum) => typeof value === 'string' && value.length <= maximum;
const network = value => ['mainnet', 'signet'].includes(value);
function validate(raw) {
  if (raw === undefined) return empty();
  if (!raw || raw.version !== 1 || typeof raw.enabled !== 'boolean' || !text(raw.epoch, 64) ||
      !Array.isArray(raw.requests) || raw.requests.length > HISTORY_LIMITS.requests ||
      !Array.isArray(raw.checks) || raw.checks.length > HISTORY_LIMITS.checks) throw new Error('Invalid local history.');
  for (const row of [...raw.requests, ...raw.checks]) {
    if (!text(row.id, 64) || !hex.test(row.hash) || !hex.test(row.nonce) || !network(row.network) ||
        !Number.isSafeInteger(row.time) || row.time < 0) throw new Error('Invalid local history entry.');
  }
  for (const row of raw.requests) if (!(row.bytes instanceof ArrayBuffer) || !row.bytes.byteLength ||
      row.bytes.byteLength > HISTORY_LIMITS.requestBytes || !text(row.verifier, 256) || !uint(row.expiresAt))
    throw new Error('Invalid saved request.');
  for (const row of raw.checks) if (row.cryptography !== 'valid' || row.policy !== 'matched' ||
      !['unavailable', 'reported_unspent', 'reported_spent', 'inconclusive'].includes(row.explorer)) throw new Error('Invalid local check marker.');
  if (size(raw) > HISTORY_LIMITS.totalBytes || (!raw.enabled && (raw.requests.length || raw.checks.length)))
    throw new Error('Local history exceeds its limits.');
  const common = row => ({ id: row.id, hash: row.hash, nonce: row.nonce, network: row.network, time: row.time });
  return { version: 1, enabled: raw.enabled, epoch: raw.epoch,
    requests: raw.requests.map(row => ({ ...common(row), bytes: row.bytes, verifier: row.verifier, expiresAt: row.expiresAt })),
    checks: raw.checks.map(row => ({ ...common(row), cryptography: row.cryptography, policy: row.policy, explorer: row.explorer })) };
}
function size(state) { return state.requests.reduce((n, row) => n + row.bytes.byteLength + 1024, 0) + state.checks.length * 512; }
function trim(state) {
  state.requests = state.requests.slice(-HISTORY_LIMITS.requests); state.checks = state.checks.slice(-HISTORY_LIMITS.checks);
  while (size(state) > HISTORY_LIMITS.totalBytes) {
    if (state.checks.length) state.checks.shift(); else state.requests.shift();
  }
  return state;
}

// A read/write transaction serializes consent, deletion and recording across tabs.
// Async digest work happens before this transaction, never between its read/write.
export function browserHistoryStore(indexedDB) {
  let opening, closed = false;
  function open() {
    try { indexedDB ??= globalThis.indexedDB; }
    catch { return Promise.reject(new Error('Local storage unavailable.')); }
    if (closed || !indexedDB) return Promise.reject(new Error('Local storage unavailable.'));
    opening ??= new Promise((resolve, reject) => {
      let abandoned = false;
      const request = indexedDB.open(DATABASE, 1);
      request.onupgradeneeded = () => { request.result.createObjectStore('state'); };
      request.onerror = () => reject(new Error('Local storage unavailable.'));
      request.onblocked = () => { abandoned = true; reject(new Error('Local storage is blocked by another tab.')); };
      request.onsuccess = () => {
        const db = request.result;
        if (abandoned || closed) { db.close(); reject(new Error('Local storage is closed.')); return; }
        db.onversionchange = () => db.close(); resolve(db);
      };
    });
    return opening;
  }
  async function operation(mutator) {
    const db = await open();
    if (closed) throw new Error('Local storage is closed.');
    return new Promise((resolve, reject) => {
      const tx = db.transaction('state', mutator ? 'readwrite' : 'readonly');
      const store = tx.objectStore('state'), get = store.get('local'); let value, failure;
      get.onsuccess = () => {
        try { value = mutator ? mutator(get.result) : get.result; if (mutator) store.put(value, 'local'); }
        catch (error) { failure = error; tx.abort(); }
      };
      tx.oncomplete = () => resolve(value);
      tx.onabort = tx.onerror = () => reject(failure ?? new Error('Local storage could not be updated.'));
    });
  }
  return { read: () => operation(), update: operation, dispose() { closed = true; opening?.then(db => db.close()).catch(() => {}); } };
}

export function setupHistory({ store = browserHistoryStore(), crypto = globalThis.crypto,
  channelFactory = name => typeof BroadcastChannel === 'function' ? new BroadcastChannel(name) : null,
  events = globalThis, now = () => Math.floor(Date.now() / 1000) } = {}) {
  let state = empty(), available = true, error = '', disposed = false, channel;
  const listeners = new Set();
  const snapshot = () => ({ ...structuredClone(state), available, error, synchronized: !!channel });
  function emit(kind) { if (!disposed) for (const listener of listeners) listener(snapshot(), kind); }
  function failed() { available = false; error = 'Local history is unavailable. Downloads and verification still work; nothing new was saved. Reload to retry storage.'; emit('unavailable'); }
  async function refresh(kind = 'entries') {
    if (disposed) return;
    try { const previous = state.epoch; state = validate(await store.read()); available = true; error = ''; emit(previous && previous !== state.epoch ? 'reset' : 'entries'); }
    catch { failed(); }
  }
  try { channel = channelFactory(CHANNEL); if (channel) channel.onmessage = event => refresh(event.data?.kind === 'reset' ? 'reset' : 'entries'); }
  catch { channel = null; }
  const focus = () => refresh('reset'); events.addEventListener?.('focus', focus);
  function id() { if (!crypto?.randomUUID) throw new Error('Secure local identifiers unavailable.'); return crypto.randomUUID(); }
  async function change(transform, kind) {
    if (disposed) return false;
    try {
      const next = await store.update(transform);
      if (disposed) return false;
      state = validate(next); available = true; error = ''; emit(kind);
      try { channel?.postMessage({ kind }); } catch { channel?.close(); channel = null; emit('entries'); }
      return true;
    } catch { failed(); return false; }
  }
  async function ticket() { await refresh(); return available && state.enabled && !disposed ? state.epoch : null; }
  async function fingerprint(bytes) {
    if (!(bytes instanceof ArrayBuffer) || !bytes.byteLength || bytes.byteLength > HISTORY_LIMITS.requestBytes)
      throw new Error('Invalid local request.');
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
  }
  async function saveRequest(bytes, metadata, token) {
    if (!token || disposed) return false;
    try {
      const copy = bytes.slice(0), hash = await fingerprint(copy);
      const row = { id: id(), hash, bytes: copy, nonce: metadata.nonce, network: metadata.network,
        verifier: metadata.verifier, expiresAt: metadata.expiresAt, time: now() };
      let saved = false;
      const committed = await change(raw => {
        const current = validate(raw);
        if (!current.enabled || current.epoch !== token) return current;
        current.requests = current.requests.filter(item => item.hash !== hash); current.requests.push(row);
        saved = true; return validate(trim(current));
      }, 'entries');
      return committed && saved;
    } catch { failed(); return false; }
  }
  async function recordCheck(metadata, outcome, token) {
    if (!token || disposed || outcome.cryptography !== 'valid' || outcome.policy !== 'matched') return null;
    try {
      const hash = await fingerprint(metadata.requestBytes);
      const row = { id: id(), hash, nonce: metadata.nonce, network: metadata.network, time: now(),
        cryptography: outcome.cryptography, policy: outcome.policy, explorer: outcome.explorer };
      let repeat = false, saved = false;
      const committed = await change(raw => {
        const current = validate(raw);
        if (!current.enabled || current.epoch !== token) return current;
        repeat = current.checks.some(item => item.hash === hash || (item.nonce === row.nonce && item.network === row.network));
        current.checks.push(row); saved = true; return validate(trim(current));
      }, 'entries');
      return committed && saved ? { repeat, hash } : null;
    } catch { failed(); return null; }
  }
  return {
    snapshot, refresh, ticket, saveRequest, recordCheck,
    subscribe(listener) { listeners.add(listener); listener(snapshot(), 'initial'); return () => listeners.delete(listener); },
    enable: enabled => change(raw => {
      const current = validate(raw);
      return enabled ? { ...current, enabled: true, epoch: id() } : { ...empty(), epoch: id() };
    }, enabled ? 'entries' : 'reset'),
    clear: () => change(() => ({ ...empty(), epoch: id() }), 'reset'),
    remove: (kind, key) => change(raw => {
      if (!['requests', 'checks'].includes(kind)) throw new Error('Invalid local history kind.');
      const current = validate(raw), removed = current[kind].find(row => row.id === key);
      current[kind] = current[kind].filter(row => row.id !== key);
      if (kind === 'requests' && removed) current.checks = current.checks.filter(row => row.hash !== removed.hash);
      current.epoch = id(); return current;
    }, 'reset'),
    dispose() { disposed = true; listeners.clear(); channel?.close(); events.removeEventListener?.('focus', focus); store.dispose?.(); },
  };
}
