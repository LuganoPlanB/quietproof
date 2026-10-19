// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SRC_BITCOIN_RPC_JSON_H_
#define QUIETPROOF_SRC_BITCOIN_RPC_JSON_H_

#include <cstdint>
#include <map>
#include <string>

#include "cli/json.hpp"
#include "bitcoin_rpc_internal.h"

namespace proofs::bitcoin_rpc_internal {
inline constexpr std::size_t kMaxJsonDepth = 64;
inline constexpr std::size_t kMaxRpcErrorMessageBytes = 1024;
struct ExactMoney {
  std::string token;
  uint64_t sats = 0;
};
struct RpcDecodedResponse {
  // Captured monetary nodes are null placeholders: only money contains their
  // values. No monetary number ever comes from the DOM's floating arithmetic.
  nlohmann::json result;
  std::map<std::string, ExactMoney> money;
};
bool DecodeRpcResponse(const HttpResponse&, const std::string& expected_id,
                       RpcDecodedResponse*, BitcoinRpcError*);
using HttpTransport = bool (*)(const BitcoinCoreRpcConfig&, const std::string&,
                               bool, HttpResponse*, BitcoinRpcError*,
                               const std::optional<std::string>&);
// Implementation-only sequential client. No arbitrary RPC API is installed.
class RpcClient {
 public:
  explicit RpcClient(BitcoinCoreRpcConfig config, HttpTransport transport = PostRpcHttp);
  RpcClient(const RpcClient&) = delete;
  RpcClient& operator=(const RpcClient&) = delete;
  bool Call(const std::string& method, const nlohmann::json& params, bool scan,
            RpcDecodedResponse*, BitcoinRpcError*,
            const std::optional<std::string>& wallet = std::nullopt);
  const BitcoinCoreRpcConfig& config() const { return config_; }
 private:
  BitcoinCoreRpcConfig config_;
  HttpTransport transport_;
  uint64_t next_id_ = 1;
  bool exhausted_ = false;
};
// Shared private operation used by the provider and deterministic transport tests.
QuietProofChainEvidence LookupCurrentTip(RpcClient&, const QuietProofChainRequest&);
bool DiscoverAddress(RpcClient&, const BitcoinUtxoQuery&, BitcoinUtxoDiscovery*,
                     BitcoinRpcError*);
}  // namespace proofs::bitcoin_rpc_internal
#endif
