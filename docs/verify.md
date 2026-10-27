---
title: Verify a proof
outline: false
---

<script setup>
import ProofInput from '../web/features/verify/ProofInput.vue';
import { withBase } from 'vitepress';
</script>

# Verify a proof

<ClientOnly><ProofInput :wasm-url="withBase('/wasm/quietproof.wasm')" /></ClientOnly>

Return to [request creation](./tool) or read the [auditor workflow](./guide/auditor-workflow) and [limits and trust](./limitations).

Trust the site and browser delivering this verifier. A compromised deployment can replace its computation and displayed results. Read [browser security and hosting](./browser-security) for input controls, privacy and hosting limitations.
