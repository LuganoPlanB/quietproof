# Stock Core signing qualification

This opt-in native test harness qualifies the frozen QuietProof virtual signing
profile with stock Bitcoin Core 32.1 descriptor wallets. It is test support;
the shipping adapter and signature circuit are separate work. Existing build
defaults and installed libraries do not require Core or the verification oracle.

Use the verified Core 32.1 binary and source archives. Build and install the
bundled `src/secp256k1` (0.8.1) into a separate local test prefix, then configure
QuietProof with `BUILD_TESTING=ON`, `QUIETPROOF_ENABLE_CORE32_SIGNING_TEST=ON`,
`QUIETPROOF_CORE32_DIR` pointing to its binary directory, and `CMAKE_PREFIX_PATH`
including the installed base SDK, curl and test-only secp256k1 prefixes. The
oracle links only public key/signature parsing and ECDSA verification APIs;
it is never installed, exported or linked into production/WASM targets.

Run both required targets, for example:

```sh
ctest --test-dir <native-test-build> --output-on-failure --no-tests=error \
  -R '^quietproof-signing-(oracle|regtest)-test$'
```

All nodes use internally allocated disposable datadirs, loopback RPC, disabled
networking, explicit standard relay policy and bounded startup/RPC/cleanup.
Version probes also use fresh datadirs. Only public disposable scalars 1 and
n−1 are imported during fixture setup. Missing inputs fail; tests do not skip.
Normal diagnostics omit signatures, public keys and cookie credentials. The
successful harness JSON records case IDs, counters and rejection reasons;
retain the complete same-run `Testing/Temporary/LastTest.log`, since CTest JUnit
may truncate successful output.

The non-spending matrix covers both source signing kinds, both mature real
output kinds, and both public-key parities. Each of the 56 real-spend templates
has a newly wallet-signed positive control: every input verifies with independent
Python integer ECDSA and the native oracle, and `testmempoolaccept` accepts it.
Templates cover alternate mature outpoints, changed outputs, an added mixed
input, and ALL/NONE/SINGLE/ALL|ANYONECANPAY flags. The reference's additional
sighash branches are only exercised for these bounded fixtures; historical
out-of-range SINGLE behavior is excluded.

Only input zero's DER signature is replaced with the virtual signature;
the flag-changing cases also replace its trailing flag. The same compressed
key and all other inputs' valid wallet signatures are preserved. Each negative
must have a different independently derived digest, fail both ECDSA verifiers,
and receive Core's exact failed-CHECKSIG script rejection for the submitted
transaction identity. A generic RPC error, missing input, fee/policy rejection
or wrong response identity fails the test. A regression deliberately substitutes
a missing-input rejection and verifies that it earns no transplant credit.
No transaction is broadcast; authorization and all dry-run checks preserve the
real UTXO set, wallet unspent/locked outputs and mempool. Mining happens only
before these observations, during disposable fixture setup.

Virtual-parent coinbase rejection, original-child version rejection, and a
relay-shaped modified child's missing-parent rejection are recorded separately.
They are not counted as cryptographic non-spending evidence.

These finite tests qualify implementation compatibility and digest separation
for the exercised templates. They are not a universal proof that no real spend
can ever be authorized: that conclusion additionally depends on the fixed
construction, correct Bitcoin sighash semantics, normal hash collision and
preimage assumptions, and secp256k1 ECDSA security. Delegation and replay of the
same authorized request remain possible under its expiry/replay policy. No
signing-time, private-scalar knowledge, exclusive-control, or circuit-soundness
claim follows from these tests.
