#!/usr/bin/env bash
set -Eeuo pipefail

readonly quietproof_bin="${1:-./quietproof}"
readonly claim='0100000000000000000000000000000000000000000000000000000000000000:0:7:0400000000000000000000000000000000000000'
test_dir=''

cleanup() {
  if [[ -n "${test_dir}" && -d "${test_dir}" ]]; then
    rm -rf -- "${test_dir}"
  fi
}
trap cleanup EXIT

fail() {
  printf 'not ok - %s\n' "$1" >&2
  exit 1
}

[[ -x "${quietproof_bin}" ]] || fail "QuietProof binary is not executable"
version_output="$("${quietproof_bin}" --version)"
[[ "$version_output" =~ ^QuietProof\ (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  fail "version output is not a semantic release version"
test_dir="$(mktemp -d)"
readonly request="${test_dir}/request.qpr"
readonly testnet4_request="${test_dir}/testnet4.qpr"

"${quietproof_bin}" --help >"${test_dir}/help.out" 2>"${test_dir}/help.err"
grep -q 'testnet4' "${test_dir}/help.out" || fail "help omits testnet4"
grep -q 'signet' "${test_dir}/help.out" || fail "help omits signet"
grep -q 'prove you control bitcoin without revealing your public key' \
  "${test_dir}/help.out" || fail "help omits the QuietProof tagline"

"${quietproof_bin}" challenge create \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --message reserve-test \
  --expires-in 300 \
  --claim "${claim}" \
  --output "${request}" >"${test_dir}/challenge.json"

[[ "$(stat -c '%a' "${request}" 2>/dev/null || stat -f '%Lp' "${request}")" == '600' ]] ||
  fail "request permissions are not 0600"
"${quietproof_bin}" inspect "${request}" >"${test_dir}/inspect.json"
grep -q '"network":"signet"' "${test_dir}/inspect.json" ||
  fail "signet request did not round-trip"
grep -q '"verifier":"auditor.example"' "${test_dir}/inspect.json" ||
  fail "verifier identity did not round-trip"

if "${quietproof_bin}" challenge create \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --message reserve-test \
  --claim "${claim}" \
  --output "${request}" >/dev/null 2>&1; then
  fail "existing request was overwritten"
fi

"${quietproof_bin}" challenge create \
  --network testnet4 \
  --verifier auditor.example \
  --purpose proof-of-control \
  --message control-test \
  --claim "${claim}" \
  --output "${testnet4_request}" >/dev/null
"${quietproof_bin}" inspect "${testnet4_request}" >"${test_dir}/testnet4.json"
grep -q '"network":"testnet4"' "${test_dir}/testnet4.json" ||
  fail "testnet4 request did not round-trip"

if "${quietproof_bin}" challenge create \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --message reserve-test \
  --claim '0100000000000000000000000000000000000000000000000000000000000000:0:0:0400000000000000000000000000000000000000' \
  --output "${test_dir}/invalid.qpr" >/dev/null 2>&1; then
  fail "zero-value claim was accepted"
fi

if "${quietproof_bin}" prove --secret=01 --request "${request}" \
  --output "${test_dir}/proof.qpf" >/dev/null 2>&1; then
  fail "secret argv was accepted"
fi

# Discovery flags on manual requests and every RPC flag on prove are rejected.
for flag in --rpc-url --rpc-cookie --rpc-datadir --rpc-timeout --rpc-scan-timeout --rpc-wallet --min-confirmations; do
  if "${quietproof_bin}" challenge create --network signet \
      --verifier auditor.example --purpose proof-of-funds --message reserve-test \
      --claim "${claim}" --output "${test_dir}/flags.qpr" "${flag}" unused >/dev/null 2>&1; then
    fail "manual challenge accepted ${flag}"
  fi
  if "${quietproof_bin}" prove --request "${request}" \
      --output "${test_dir}/flags.qpf" "${flag}" unused >/dev/null 2>&1; then
    fail "prove accepted ${flag}"
  fi
done
[[ ! -e "${test_dir}/flags.qpr" && ! -e "${test_dir}/flags.qpf" ]] ||
  fail "rejected flags created output"

printf 'QuietProof CLI tests passed\n'
