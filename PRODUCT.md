# Product

## Register

brand

## Platform

web

## Users

QuietProof serves two audiences at once:

- Custodians, auditors, OTC counterparties, lenders, escrow operators, and collaborative-protocol designers who need to establish control of disclosed Bitcoin funds before a transaction takes place.
- Bitcoin engineers, cryptographers, integrators, and independent reviewers who need the exact protocol, circuit, operational, and security details before relying on an implementation.

Newcomers may understand Bitcoin addresses and balances without understanding public-key hashes, zero-knowledge proofs, circuit families, or Fiat–Shamir transcripts. The site must let them understand the value and limits of QuietProof before introducing those terms.

## Product Purpose

Explain and document QuietProof: a challenge-bound, off-chain proof that a prover knows the spend key corresponding to one compressed-key hash across native P2WPKH/P2PKH outputs without revealing private keys or compressed public keys.

The site should explain custody, disclosed proof-of-funds, collateral and protocol admission, with technical documentation. Describe key privacy accurately: proofs expose coins, amounts, and wallet links; recipients can trace them and associate known identities.

QuietProof is a proof-of-key-control primitive, not a complete proof-of-reserves or solvency system. The site must make that boundary unmistakable.

## Brand Personality

Calm, civic, and exact. QuietProof should feel like capable public-interest infrastructure: welcoming enough for a curious non-specialist, rigorous enough for a security reviewer, and never promotional about guarantees it does not provide.

## Anti-references

- Crypto-bro branding, speculative language, trading imagery, coins, rockets, locks, or anonymous-hoodie clichés.
- Dense cryptographic notation on the landing page before the visitor understands the practical job.
- Vague “military-grade privacy” claims or language that implies ownership, exclusivity, solvency, legal title, or locked funds.
- Generic SaaS card walls and developer-terminal aesthetics used as a substitute for explanation.
- Hiding risk, trust assumptions, or limitations behind marketing language.

## Design Principles

1. Lead with the human job: prove control before moving money or revealing more than necessary.
2. Explain in layers: plain language first, operational detail second, normative cryptography always available.
3. State the boundary with the claim: every “proves” statement should sit near the corresponding “does not prove” statement.
4. Show a verifier–prover flow so challenge freshness and off-chain verification are concrete rather than abstract.
5. Preserve reviewer confidence: source-linked, searchable, complete technical documentation is a primary product feature.

## Accessibility & Inclusion

Target WCAG 2.2 AA. Use semantic landmarks and sequential headings, visible keyboard focus, non-color status cues, readable line lengths, and sufficient contrast in both light and dark themes. Respect reduced-motion and system color preferences. Define unfamiliar Bitcoin and cryptographic terms at first use, provide a glossary, and avoid requiring mathematical knowledge for the core explanation.
