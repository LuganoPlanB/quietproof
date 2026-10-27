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

See the [auditor workflow](./guide/auditor-workflow) for the request, external proving and verification handoff, and [limits and trust](./limitations) before relying on a proof.
