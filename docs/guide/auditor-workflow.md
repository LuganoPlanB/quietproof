---
title: Auditor workflow
description: A bounded custody-attestation workflow using fresh QuietProof challenges.
---

# Auditor workflow

This workflow demonstrates current key knowledge for disclosed native P2WPKH
or compressed-key P2PKH outputs. It is not a complete proof of reserves or solvency.
The [browser handoff](./browser-tool) and native Core-backed verifier have
different chain-evidence and replay boundaries; choose one explicitly.

## Define the claim before asking for a proof

The auditor should document:

- the organization and system being reviewed;
- the purpose of the attestation;
- the exact disclosed outpoints, values, and witness programs;
- accepted Bitcoin network and confirmation policy;
- freshness window;
- minimum total value, if applicable;
- Bitcoin data source and node identity; and
- the conclusions explicitly outside scope.

The auditor, not the custodian, selects and authenticates the Bitcoin data source used for verification.

## Issue a short-lived challenge

Generate the nonce with the operating-system CSPRNG and use a lifetime measured in minutes. Name the auditor and purpose precisely enough that the proof cannot be confused with another engagement.

The custodian should inspect the canonical request before proving. If any claim, purpose, verifier name, network, or expiry is unexpected, it should refuse.

## Verify independently

For native Core-backed verification, use a trusted fully validated node on the
expected network, independent expected metadata/policy, resource limits and an
owner-only atomic nonce store. Native RPC is the default; `bitcoin-cli` is only
an explicitly selected deprecated compatibility path.

For the static browser verifier, retain your own expected `.qpr` or choose an
independent explicit context. Read crypto, policy and explorer results
separately. The pinned explorer is trusted and its observations are non-atomic;
the browser does not authenticate a chain snapshot or authorize acceptance.
Device time and editable origin-local history do not provide a durable global
nonce store. A separate integration must provide any authoritative acceptance
and replay enforcement the engagement requires.

Record non-authorization outcomes rather than trying to reinterpret them. `state_inconclusive`, `stale_snapshot`, `spent_at_snapshot`, `unsupported`, `bridge_rejected`, and every parse or proof failure must fail closed.

## Write the conclusion precisely

A supported conclusion is:

> At the recorded time, the custodian answered the auditor’s fresh challenge with a valid QuietProof for the disclosed P2WPKH programs, and the selected Bitcoin provider confirmed the stated current output evidence under the recorded policy.

That chain-evidence conclusion requires the native/integrated provider profile.
For the browser profile, record the narrower observation: local cryptography
and independently chosen policy passed, and the named explorer reported the
listed outputs unspent within the recorded observation window. Preserve the
explorer's trust/non-atomic limitation; this is not strict current or historical
chain validity.

Unsupported conclusions include:

- “The custodian exclusively owns these funds.”
- “The custodian is solvent.”
- “No liabilities or undisclosed wallets exist.”
- “The funds cannot move after this report.”
- “The key was never shared or temporarily supplied.”

## Retain the evidence

Retain the request, proof, result, nonce evidence, node/tip, circuit/software versions, policy, and approvals in append-only records. Restrict access: these records link identified clients to disclosed coins.

If the engagement requires a historical snapshot, the bundled CLI is not enough. Use a separately implemented authenticated historical provider through the library API and document its trust and finality model.

## Add the missing reserve layers

For a proof-of-reserves engagement, add mechanisms for:

- completeness of the asset set;
- customer liability commitments and inclusion;
- prevention of negative or omitted balances;
- valuation and time consistency;
- treatment of shared, delegated, or borrowed key access; and
- independent review of the complete protocol.

[Continue with operations and production controls →](/operations)
