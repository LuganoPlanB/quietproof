---
title: Practical guides
description: Choose a QuietProof guide based on what you are trying to do.
---

# Practical guides

Use these guides to move from the concept to a testable workflow.

## Use the browser tool

[Browser request and verifier](/guide/browser-tool) walks through a public
request, external CLI/wallet proving, independent expected policy and separate
cryptography/explorer results. Private keys stay outside the browser. Mainnet
and signet are supported; the static tool supplies no acceptance backend.

::: warning
This is free and open source software provided without warranty under
the terms of the GNU GPL v3 license. Professional support,
maintenance, integration services, and contractual warranty options
are available separately. Please contact us for further information.
:::

## Understand the exchange

[How a proof works](/guide/how-it-works) follows the verifier and prover from a fresh request through the final application decision. It is the best next page if you understand the use case but not the protocol.

## Plan an audit

[Auditor workflow](/guide/auditor-workflow) turns the primitive into a bounded custody-attestation process, including what evidence to retain and which conclusions remain out of scope.

## Build and try the CLI

[Build and try it](/guide/getting-started) gives the dependency, build, Signet request, proof, and verification commands.

## Operate it carefully

[Operations and production controls](/operations) documents Bitcoin network selection, Bitcoin Core isolation, nonce handling, audit logging, resource controls, and the release gate.
