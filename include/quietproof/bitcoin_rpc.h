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
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "quietproof/chain_state.h"

namespace proofs {
enum class BitcoinRpcErrorCode {
  kNone, kConfiguration, kCookie, kAuthentication, kConnection, kTimeout,
  kResponseTooLarge, kHttp, kRpc, kMalformed, kWrongNetwork,
  kInvalidAddress, kUnsupportedScript, kScanBusy, kScanIncomplete,
  kInconclusive, kWalletLocked, kWrongPassphrase, kUnsupportedWallet
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
// Nonsecret resolved settings. Performs no RPC or cookie reads; the transport
// reopens the cookie for each call so node restarts/rotation remain supported.
struct BitcoinRpcSettings {
  std::string url;
  std::string cookie_path;
};
bool ResolveBitcoinRpcSettings(const BitcoinCoreRpcConfig&, BitcoinRpcSettings*,
                               BitcoinRpcError* = nullptr);
struct BitcoinRpcKeyMatch {
  std::array<uint8_t, 20> program{};
  std::vector<QuietProofScriptKind> script_kinds;
};
struct BitcoinRpcWalletProbe {
  std::string name;
  std::optional<bool> private_keys_enabled;
  std::optional<bool> descriptor_wallet;
  std::optional<bool> external_signer;
  std::optional<bool> request_matches;
  BitcoinRpcError error;
};
struct BitcoinRpcProbe {
  bool authenticated = false;
  std::optional<uint64_t> version;
  std::optional<std::string> chain;
  std::optional<bool> network_matches;
  std::optional<bool> syncing;
  std::optional<bool> export_address_key;
  bool wallets_listed = false;
  std::vector<BitcoinRpcWalletProbe> wallets;
};
enum class BitcoinRpcWalletState { kUnencrypted, kLocked, kUnlocked };
struct BitcoinUtxoQuery {
  std::string address;
  uint64_t min_confirmations = 1;
  // Explicit loaded wallet name (1..1024 UTF-8 bytes, no controls). Wallet mode
  // reflects tracked outputs and Core's locked/immature-coin exclusions; it is
  // not exhaustive address discovery. Watch-only outputs remain eligible.
  std::optional<std::string> wallet;
};
struct BitcoinUtxo {
  QuietProofClaimV1 claim;
  uint64_t confirmations = 0;
};
struct BitcoinUtxoDiscovery {
  QuietProofNetwork network = static_cast<QuietProofNetwork>(0xff);
  std::vector<BitcoinUtxo> outputs;
  // Current recheck observation when current_rechecked; otherwise scan snapshot
  // or the tip observed before querying the wallet (wallet results are not atomic).
  std::array<uint8_t, 32> observed_block{};
  uint64_t observed_height = 0;
  std::optional<std::array<uint8_t, 32>> scan_block;
  std::optional<uint64_t> scan_height;
  std::size_t excluded_below_min_confirmations = 0;
  bool current_rechecked = false;
  // Empty, excessive, or aggregate-overflow sets are returned without selection
  // and without current rechecks; callers must honor these flags.
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
  // Nonsecret capability probe: never unlocks or invokes key export.
  // Returns partial observations on failure. Total budget is 1..60000 ms;
  // each call is bounded by remaining time and configured transport timeouts.
  // Inspects at most 16 loaded wallets. Instances remain sequential.
  bool Probe(const std::optional<BitcoinRpcKeyMatch>&, BitcoinRpcProbe*,
             BitcoinRpcError* = nullptr,
             std::chrono::milliseconds budget = std::chrono::milliseconds(10000));
  // Native P2WPKH export. Empty address derives it from the request program;
  // empty wallet selects the sole loaded wallet. Checks node network and
  // address program before requesting a secret. Leaves output unchanged on
  // failure. Caller must validate the scalar/key against the request and erase it.
  bool ExportAddressKey(const std::string& wallet, const std::string& address,
                        const std::array<uint8_t, 20>& expected_program,
                        std::array<uint8_t, 32>* secret,
                        BitcoinRpcError* = nullptr);
  // Explicit identity, including the unnamed wallet. Never auto-selects.
  bool ExportSelectedAddressKey(const std::string& wallet,
                        const BitcoinRpcKeyMatch&, std::array<uint8_t, 32>*,
                        BitcoinRpcError* = nullptr,
                        const std::function<bool()>& stop = {});
  bool WalletState(const std::string& wallet, BitcoinRpcWalletState*,
                   BitcoinRpcError* = nullptr);
  // One bounded lease; no retries. A transport failure may mean it succeeded.
  // Passphrase bytes are borrowed only for this call, never RPC cookie auth.
  bool UnlockWallet(const std::string& wallet, std::span<const char> passphrase,
                    std::chrono::seconds lease, BitcoinRpcError* = nullptr);
  bool LockWallet(const std::string& wallet, BitcoinRpcError* = nullptr);
  // Typed export: accepted address kinds must occur in the request. Empty
  // address prefers P2PKH when present, otherwise P2WPKH. The original overload
  // retains its P2WPKH-only contract.
  bool ExportAddressKey(const std::string& wallet, const std::string& address,
                        const std::array<uint8_t, 20>& expected_program,
                        const std::vector<QuietProofScriptKind>& script_kinds,
                        std::array<uint8_t, 32>* secret,
                        BitcoinRpcError* = nullptr);
  QuietProofProviderKind kind() const override;
  QuietProofChainEvidence Lookup(const QuietProofChainRequest&) override;

 private:
  bool ExportAddressKeyImpl(const std::string&, const std::string&,
      const std::array<uint8_t, 20>&, const std::vector<QuietProofScriptKind>&,
      std::array<uint8_t, 32>*, BitcoinRpcError*, bool select_sole,
      const std::function<bool()>& stop = {});
  class Impl;
  std::unique_ptr<Impl> impl_;
};
}  // namespace proofs
#endif
