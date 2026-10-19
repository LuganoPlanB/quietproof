// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Live-test helper only. Proof stages use the shipped C++ example unchanged.
#include <array>
#include <charconv>
#include <iostream>
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
