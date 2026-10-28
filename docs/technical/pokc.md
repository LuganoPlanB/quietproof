---
title: PoKC v1 circuit
description: Complete circuit relation, single-key circuit, scaling, witness construction, and validation notes.
outline: deep
---

<!--@include: ../../pokc.md-->

## Independent P2SH 2-of-3 extension

The [P2SH multisig circuit](./p2sh-multisig.md) adds a separate library relation:
each signer independently proves one scalar at a public position of a private
canonical 2-of-3 script. The circuit constrains all points, distinctness,
position selection, and the complete 105-byte script HASH160. An auditor checks
two valid proofs against its expected hash and requires distinct positions.
Existing PoKC circuits and formats are unchanged by this extension. The linked
specification documents the C++ API, adversarial tests and historical benchmarks.
