<template>
  <div class="quietproof-home">
    <section class="planb-hero quietproof-hero" aria-labelledby="quietproof-title">
      <div class="planb-hero__overlay" aria-hidden="true"></div>
      <div class="planb-container planb-hero__inner">
        <div class="quietproof-hero__copy">
          <p class="planb-eyebrow">Off-chain proof of key control</p>
          <h1 id="quietproof-title">Prove you control bitcoin. Keep your keys quiet.</h1>
          <p class="planb-lede">
            Prove control of disclosed bitcoin without moving it or revealing keys.
            Recipients can trace the coins and associate them with a known identity.
          </p>
          <div class="quietproof-actions">
            <a class="planb-button-link" :href="withBase('/what-it-proves')">See what it proves</a>
            <a class="quietproof-text-action" :href="withBase('/technical/architecture')">Read the technical docs</a>
          </div>
        </div>

        <aside class="quietproof-address" aria-label="A plain-language explanation">
          <p class="quietproof-address__label">The public clue</p>
          <code>bc1q ···· 7k3p</code>
          <p>
            A common Bitcoin address contains a fingerprint of a public key. QuietProof can show
            that you know the matching spend key without revealing either key.
          </p>
        </aside>
      </div>
    </section>

    <div class="planb-container planb-main quietproof-main">
      <section class="quietproof-profile" aria-labelledby="profile-title">
        <div class="quietproof-section-heading">
          <h2 id="profile-title">Built for deliberate attestations</h2>
          <p>
            QuietProof v1 works off-chain in tens of seconds and produces proof envelopes measured
            in tens of megabytes. It fits audits, qualification, and preflight checks—not a
            transaction path or a high-frequency request loop.
          </p>
        </div>

        <div
          class="quietproof-benchmark-table"
          role="region"
          aria-label="QuietProof benchmark measurements"
          tabindex="0"
        >
          <table>
            <caption>Observed end-to-end native API performance</caption>
            <thead>
              <tr>
                <th scope="col">Circuit shape</th>
                <th scope="col">Prove</th>
                <th scope="col">Verify</th>
                <th scope="col">Full envelope</th>
                <th scope="col">Quadratic terms</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <th scope="row">1 distinct key</th>
                <td>29.892 s</td>
                <td>19.899 s</td>
                <td>44.71 MiB</td>
                <td>2,067,522</td>
              </tr>
              <tr>
                <th scope="row">2 distinct keys</th>
                <td>60.200 s</td>
                <td>38.967 s</td>
                <td>87.04 MiB</td>
                <td>4,133,092</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="quietproof-benchmark-note">
          Single observations from 21 August 2026 on Linux x86-64, Intel Core i9-12900HK,
          Debian clang 19.1.7, C++17 hardened release. Verification followed proving in the same
          process, so its expected-circuit-digest cache was warm. These figures are indicative,
          not performance requirements. <a :href="withBase('/performance')">Methodology and raw sizes</a>
        </p>

        <div class="quietproof-contract">
          <div class="quietproof-contract__intro">
            <h3>What crosses the boundary</h3>
            <p>
              The expensive work happens locally. The exchanged artifact is a challenge-bound
              proof envelope, not a transaction and not a Bitcoin-valid signature.
            </p>
          </div>
          <dl>
            <div>
              <dt>Public request</dt>
              <dd>
                Network, verifier, purpose, nonce, expiry, and 1–16 disclosed UTXO claims. Each
                claim supplies an outpoint, value, script kind, and 20-byte compressed-key hash.
              </dd>
            </div>
            <div>
              <dt>Private prover input</dt>
              <dd>
                One 32-byte spend key for each distinct compressed-key hash—exactly one or two.
                Keys stay local and should enter through protected standard input.
              </dd>
            </div>
            <div>
              <dt>Proof artifact</dt>
              <dd>
                A <code>.qpf</code> envelope containing the canonical statement, circuit identity,
                parameters, and zero-knowledge proof. It reveals neither private nor compressed
                public keys.
              </dd>
            </div>
            <div>
              <dt>Verifier output</dt>
              <dd>
                A policy result after proof verification, independent Bitcoin chain evidence,
                confirmation and value thresholds, and atomic replay-nonce consumption.
              </dd>
            </div>
          </dl>
        </div>

        <aside class="quietproof-workload-fit" aria-labelledby="workload-fit-title">
          <h3 id="workload-fit-title">Why this is not transaction-pace technology</h3>
          <div>
            <p>
              <strong>Current cost follows distinct keys.</strong> Each key adds an elliptic-curve,
              SHA-256, and RIPEMD-160 relation. More claims are comparatively cheap only when they
              reuse one of the same one or two key hashes across P2WPKH/P2PKH kinds.
            </p>
            <p>
              <strong>Use it at discrete decision points.</strong> A custody review, OTC
              qualification, collateral negotiation, wallet migration, or protocol admission can
              tolerate deliberate proof generation and verification. Per-payment authorization,
              high-rate API gating, and large HD wallets with fresh keys are not v1 targets.
            </p>
          </div>
        </aside>
      </section>

      <section class="quietproof-jobs" aria-labelledby="jobs-title">
        <div class="quietproof-section-heading quietproof-section-heading--wide">
          <h2 id="jobs-title">Useful before anyone moves money</h2>
          <p>
            The proof creates an off-chain preflight step: establish key control first, then decide
            whether a transaction, contract, audit, or protocol session should begin.
          </p>
        </div>
        <div class="quietproof-job-list">
          <article>
            <p class="quietproof-job-list__context">Custody & audit</p>
            <h3>Answer a fresh auditor challenge</h3>
            <p>Demonstrate current key knowledge for disclosed custody outputs without exposing their public keys.</p>
          </article>
          <article>
            <p class="quietproof-job-list__context">Deals & credit</p>
            <h3>Qualify a counterparty before negotiation</h3>
            <p>Check proposed funds or collateral before spending time on legal work, escrow, or settlement.</p>
          </article>
          <article>
            <p class="quietproof-job-list__context">Off-chain continuity</p>
            <h3>Show common key knowledge across wallets</h3>
            <p>The two-key proof reveals the link to recipients without publishing an on-chain transaction.</p>
          </article>
          <article>
            <p class="quietproof-job-list__context">Collaborative protocols</p>
            <h3>Check capability before admission</h3>
            <p>Verify that proposed participants control their inputs before a CoinJoin or other coordinated transaction begins.</p>
          </article>
        </div>
        <a class="quietproof-inline-link" :href="withBase('/use-cases')">Explore all use cases <span aria-hidden="true">→</span></a>
      </section>

      <section class="planb-panel quietproof-flow" aria-labelledby="flow-title">
        <div class="quietproof-flow__intro">
          <h2 id="flow-title">A proof belongs to one conversation</h2>
          <p>
            A verifier creates a short-lived challenge. That challenge is bound into the proof, so
            an old file cannot simply be copied into a new audit or negotiation.
          </p>
        </div>
        <ol class="quietproof-flow__steps">
          <li>
            <span>1</span>
            <div><h3>Ask</h3><p>The verifier names the outputs, purpose, expiry, and a fresh nonce.</p></div>
          </li>
          <li>
            <span>2</span>
            <div><h3>Prove</h3><p>The holder creates the proof locally. Secret keys never enter the request or proof.</p></div>
          </li>
          <li>
            <span>3</span>
            <div><h3>Check</h3><p>The verifier checks the proof, policy, replay state, and independent Bitcoin chain data.</p></div>
          </li>
          <li>
            <span>4</span>
            <div><h3>Decide</h3><p>The application decides whether to continue. A valid proof is evidence, not an automatic authorization.</p></div>
          </li>
        </ol>
        <a class="quietproof-inline-link" :href="withBase('/guide/how-it-works')">Follow the proof step by step <span aria-hidden="true">→</span></a>
      </section>

      <section class="quietproof-two-key" aria-labelledby="two-key-title">
        <div>
          <h2 id="two-key-title">One proof can connect two keys off-chain</h2>
          <p>
            QuietProof v1 has exact circuit shapes for one or two distinct compressed-key hashes. In the
            two-key case, a selected verifier can learn that the same prover knows both keys without
            learning either public key and without creating an on-chain connection.
          </p>
          <p>
            This supports wallet continuity and reputation rollover. Recipients learn the link
            and can share the proof. Native P2WPKH and compressed-key P2PKH are supported;
            uncompressed P2PKH is unsupported. Public outpoints, key hashes and amounts stay
            linkable. Earlier spends or key reuse may already reveal a public key; proving
            cannot undo that exposure or provide anonymity.
          </p>
        </div>
        <div class="quietproof-linkage" role="img" aria-label="Old and new wallet outputs linked for the verifier by QuietProof">
          <div><span>Old wallet</span><code>bc1q ··· a91x</code></div>
          <div class="quietproof-linkage__proof"><span>QuietProof</span><small>knows both keys</small></div>
          <div><span>New wallet</span><code>bc1q ··· m42c</code></div>
        </div>
      </section>

      <section class="quietproof-depth" aria-labelledby="depth-title">
        <div>
          <h2 id="depth-title">Start simple. Go all the way down.</h2>
          <p>
            The approachable explanation and the exact specification live together. Engineers and
            reviewers can inspect the canonical encoding, transcript, circuit identity, negative
            test corpus, security boundaries, and current performance measurements.
          </p>
        </div>
        <nav aria-label="Documentation depth">
          <a :href="withBase('/guide/')"><span>Practical guides</span><small>Workflows and commands</small></a>
          <a :href="withBase('/security')"><span>Security matrix</span><small>Claims, checks, residual limits</small></a>
          <a :href="withBase('/technical/protocol')"><span>Normative protocol</span><small>QuietProof v1, field by field</small></a>
        </nav>
      </section>

      <aside class="quietproof-warning" aria-labelledby="experimental-title">
        <div aria-hidden="true">!</div>
        <section>
          <h2 id="experimental-title">Free without warranty</h2>
          <p>
This is <b>free and open source software</b> provided without warranty under
the terms of the <a href="https://www.gnu.org/licenses">GNU GPL v3 license</a>. Professional support,
maintenance, integration services, and contractual warranty options
are available separately. Please <a href="mailto:info@plan-b.foundation">contact us for further information</a>.
          </p>
        </section>
        <a :href="withBase('/limitations')">Understand the limits</a>
      </aside>
    </div>
  </div>
</template>

<script setup>
import { withBase } from "vitepress";
</script>
