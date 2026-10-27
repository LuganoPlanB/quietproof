---
title: Create a request
outline: false
---

<script setup>
import RequestForm from '../web/features/request/RequestForm.vue';
import { withBase } from 'vitepress';
</script>

# Create a request

<ClientOnly><RequestForm :wasm-url="withBase('/wasm/quietproof.wasm')" /></ClientOnly>

When the external prover returns a .qpf, [verify the proof](./verify) with your retained expected .qpr. Choose offline cryptography or explicitly request fresh explorer observations. Inspection alone does not check cryptography.

See the [auditor workflow](./guide/auditor-workflow) for the request, external proving and verification handoff, and [limits and trust](./limitations) before relying on a proof.

Trust the site and browser delivering this tool. A compromised deployment can replace its verifier and results. Read [browser security and hosting](./browser-security) for input controls, privacy and hosting limitations.
