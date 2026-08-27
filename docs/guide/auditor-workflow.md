---
title: Auditor workflow
description: A bounded custody-attestation workflow using fresh QuietProof challenges.
---

# Auditor workflow

This workflow demonstrates current key knowledge for a disclosed set of native P2WPKH outputs. It is not a complete proof of reserves or solvency.

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

Verification should run with a fully validated Bitcoin Core node on the expected network, an absolute `bitcoin-cli` path, resource limits, and an owner-only atomic nonce store.

Record non-authorization outcomes rather than trying to reinterpret them. `state_inconclusive`, `stale_snapshot`, `spent_at_snapshot`, `unsupported`, `bridge_rejected`, and every parse or proof failure must fail closed.

## Write the conclusion precisely

A supported conclusion is:

> At the recorded time, the custodian answered the auditor’s fresh challenge with a valid QuietProof for the disclosed P2WPKH programs, and the selected Bitcoin provider confirmed the stated current output evidence under the recorded policy.

Unsupported conclusions include:

- “The custodian exclusively owns these funds.”
- “The custodian is solvent.”
- “No liabilities or undisclosed wallets exist.”
- “The funds cannot move after this report.”
- “The key was never shared or temporarily supplied.”

## Retain the evidence

Store the canonical request, proof envelope, result, consumed nonce evidence, node identity and tip, circuit digest, software version, verification policy, and any human approvals in an append-only audit record.

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
