// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Live-test helper only. Proof stages use the shipped C++ example unchanged.
#include <array>
#include <charconv>
#include <iostream>
#include <fstream>
#include <iterator>
#include <string>

#include "pokc/prover.h"
#include "quietproof/bitcoin_rpc.h"
#include "quietproof/bitcoin_core.h"

namespace {
using namespace proofs;
template <class Range>
std::string Hex(const Range& bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (auto byte : bytes) {
    out += digits[byte >> 4];
    out += digits[byte & 15];
  }
  return out;
}
int Run(int argc, char** argv) {
  if (argc == 5 && std::string(argv[1]) == "mutate") {
    std::ifstream input(argv[2], std::ios::binary);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    QuietProofEnvelopeV1 envelope;
    if (!input.is_open() || !DecodeQuietProofEnvelope(bytes, &envelope)) return 1;
    const std::string field = argv[3];
    if (field == "kind") envelope.statement.claims[0].script_kind = QuietProofScriptKind::kP2wpkh;
    else if (field == "hash") envelope.statement.claims[0].program[0] ^= 1;
    else if (field == "amount") ++envelope.statement.claims[0].amount_sats;
    else if (field == "request-time") --envelope.statement.not_before;
    else if (field == "proof-time") ++envelope.proof_created_at;
    else if (field == "expired") {
      envelope.statement.not_before = 1;
      envelope.statement.expires_at = 2;
      envelope.proof_created_at = 1;
    } else return 64;
    std::vector<uint8_t> changed;
    if (!EncodeQuietProofEnvelope(envelope, &changed)) return 1;
    std::ofstream output(argv[4], std::ios::binary);
    output.write(reinterpret_cast<const char*>(changed.data()), changed.size());
    return output ? 0 : 1;
  }
  if (argc == 2 && std::string(argv[1]) == "fixture") {
    // Public disposable scalar 1; never use this key outside isolated regtest.
    std::array<uint8_t, 32> secret{};
    secret.back() = 1;
    PoKCWitnessV1<PoKCField, PoKCEC> witness;
    if (!witness.compute(p256k1, secret.data(), secret.size())) return 1;
    std::cout << Hex(witness.program()) << '\n';
    return 0;
  }
  if (argc != 9 || std::string(argv[1]) != "lookup") return 64;
  QuietProofNetwork network;
  QuietProofChainRequest request{};
  std::vector<uint8_t> txid;
  if (!QuietProofParseNetwork(argv[2], &network) ||
      !quietproof_internal::DecodeHex(argv[5], &txid) || txid.size() != 32) return 64;
  std::copy(txid.begin(), txid.end(), request.txid.begin());
  request.network = network;
  const std::string vout = argv[6];
  const auto parsed = std::from_chars(vout.data(), vout.data() + vout.size(), request.vout);
  if (parsed.ec != std::errc{} || parsed.ptr != vout.data() + vout.size()) return 64;
  BitcoinCoreRpcConfig config(network);
  config.rpc_url = argv[3];
  config.rpc_cookie = argv[4];
  BitcoinCoreRpc native(config);
  const auto evidence = native.Lookup(request);
  if (std::string(argv[7]) == "parity") {
    BitcoinCoreCurrentTipProvider legacy(argv[8], network);
    const auto other = legacy.Lookup(request);
    if (evidence.status != other.status || evidence.network != other.network ||
        evidence.block != other.block || evidence.height != other.height ||
        evidence.confirmations != other.confirmations ||
        evidence.amount_sats != other.amount_sats ||
        evidence.script_pub_key != other.script_pub_key) return 1;
  }
  std::cout << static_cast<int>(evidence.status) << ':' << Hex(evidence.block)
            << ':' << evidence.height << ':' << evidence.amount_sats << '\n';
  return 0;
}
}  // namespace
int main(int argc, char** argv) {
  try { return Run(argc, argv); }
  catch (...) { std::cerr << "Live-test driver failed\n"; return 1; }
}
