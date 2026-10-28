---
title: Create a request
outline: false
---

<script setup>
import RequestForm from '../web/features/request/RequestForm.vue';
import wasmUrl from 'virtual:quietproof-wasm';
</script>

# Create a request

<ClientOnly><RequestForm :wasm-url="wasmUrl" /></ClientOnly>

When the external prover returns a .qpf, [verify the proof](./verify) with your retained expected .qpr. Choose offline cryptography or explicitly request fresh explorer observations. Inspection alone does not check cryptography.

Follow the [browser request and verifier guide](./guide/browser-tool) for the
download, external CLI/wallet proving and independent-expectation handoff.
See the [auditor workflow](./guide/auditor-workflow) and [limits and trust](./limitations)
before relying on a proof.

Trust the site and browser delivering this tool. A compromised deployment can replace its verifier and results. Read [browser security and hosting](./browser-security) for input controls, privacy and hosting limitations.
