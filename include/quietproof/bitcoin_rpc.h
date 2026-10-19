// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#ifndef PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_BITCOIN_RPC_H_
#define PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_BITCOIN_RPC_H_

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "quietproof/chain_state.h"

namespace proofs {
enum class BitcoinRpcErrorCode {
  kNone, kConfiguration, kCookie, kAuthentication, kConnection, kTimeout,
  kResponseTooLarge, kHttp, kRpc, kMalformed, kWrongNetwork,
  kInvalidAddress, kUnsupportedScript, kScanBusy, kScanIncomplete,
  kInconclusive
};
struct BitcoinRpcError {
  BitcoinRpcErrorCode code = BitcoinRpcErrorCode::kNone;
  int http_status = 0;
  std::optional<int64_t> rpc_code;
  std::string message;  // Bounded, library-authored diagnostic; no server text.
};
struct BitcoinCoreRpcConfig {
  explicit BitcoinCoreRpcConfig(QuietProofNetwork expected) : network(expected) {}
  QuietProofNetwork network;
  std::string rpc_url;
  std::string rpc_cookie;
  std::string rpc_datadir;
  std::chrono::milliseconds connect_timeout{5000};
  std::chrono::milliseconds rpc_timeout{30000};
  std::chrono::milliseconds scan_timeout{600000};
};
struct BitcoinUtxoQuery {
  std::string address;
  uint64_t min_confirmations = 1;
  std::optional<std::string> wallet;
};
struct BitcoinUtxo {
  QuietProofClaimV1 claim;
  uint64_t confirmations = 0;
};
struct BitcoinUtxoDiscovery {
  QuietProofNetwork network = static_cast<QuietProofNetwork>(0xff);
  std::vector<BitcoinUtxo> outputs;
  std::array<uint8_t, 32> observed_block{};
  uint64_t observed_height = 0;
  std::optional<std::array<uint8_t, 32>> scan_block;
  std::optional<uint64_t> scan_height;
  std::size_t excluded_below_min_confirmations = 0;
  bool current_rechecked = false;
  bool challenge_compatible = false;
  std::string incompatibility;
};
// Instances are sequential/non-thread-safe. Construction performs no network I/O.
// On failure Discover leaves output unchanged and sets a redacted error.
class BitcoinCoreRpc final : public QuietProofChainProvider {
 public:
  explicit BitcoinCoreRpc(BitcoinCoreRpcConfig config);
  ~BitcoinCoreRpc() override;
  BitcoinCoreRpc(const BitcoinCoreRpc&) = delete;
  BitcoinCoreRpc& operator=(const BitcoinCoreRpc&) = delete;
  bool Discover(const BitcoinUtxoQuery&, BitcoinUtxoDiscovery*,
                BitcoinRpcError* = nullptr);
  QuietProofProviderKind kind() const override;
  QuietProofChainEvidence Lookup(const QuietProofChainRequest&) override;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};
}  // namespace proofs
#endif
