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
#ifndef PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_CHAIN_STATE_H_
#define PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_CHAIN_STATE_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include "quietproof/statement.h"

namespace proofs {
enum class QuietProofProviderKind : uint8_t { kCurrentTip, kHistoricalSnapshot };
enum class QuietProofChainStatus : uint8_t { kUnspent, kSpent, kInconclusive, kUnavailable, kMalformed, kWrongNetwork, kStale };
struct QuietProofChainRequest {
  // Callers must select a network; an incomplete request fails before I/O.
  QuietProofNetwork network = static_cast<QuietProofNetwork>(0xff);
  std::array<uint8_t, 32> txid{};
  uint32_t vout = 0;
  bool has_snapshot = false;
  std::array<uint8_t, 32> snapshot{};
  uint32_t snapshot_height = 0;
};
struct QuietProofChainEvidence { QuietProofChainStatus status = QuietProofChainStatus::kUnavailable; QuietProofNetwork network = QuietProofNetwork::kMainnet; std::array<uint8_t,32> block{}; uint64_t height = 0; uint64_t confirmations = 0; uint64_t amount_sats = 0; std::vector<uint8_t> script_pub_key; std::string detail; };
class QuietProofChainProvider { public: virtual ~QuietProofChainProvider() = default; virtual QuietProofProviderKind kind() const = 0; virtual QuietProofChainEvidence Lookup(const QuietProofChainRequest&) = 0; };
// Recognize only canonical, bounded templates. Outputs remain unchanged on failure.
// P2PKH reveals a key hash, not whether the hidden public key was compressed.
inline bool QuietProofClassifyScript(
    const std::vector<uint8_t>& script, QuietProofScriptKind* kind,
    std::array<uint8_t, 20>* key_hash) {
  if (kind == nullptr || key_hash == nullptr) return false;
  QuietProofScriptKind matched_kind;
  size_t offset = 0;
  if (script.size() == 22 && script[0] == 0x00 && script[1] == 0x14) {
    matched_kind = QuietProofScriptKind::kP2wpkh;
    offset = 2;
  } else if (script.size() == 25 && script[0] == 0x76 &&
             script[1] == 0xa9 && script[2] == 0x14 &&
             script[23] == 0x88 && script[24] == 0xac) {
    matched_kind = QuietProofScriptKind::kP2pkh;
    offset = 3;
  } else {
    return false;
  }
  std::copy_n(script.begin() + offset, key_hash->size(), key_hash->begin());
  *kind = matched_kind;
  return true;
}

inline bool QuietProofMatchesScript(const QuietProofClaimV1& claim,
                                    const std::vector<uint8_t>& script) {
  QuietProofScriptKind kind;
  std::array<uint8_t, 20> key_hash{};
  return QuietProofClassifyScript(script, &kind, &key_hash) &&
         kind == claim.script_kind && key_hash == claim.program;
}

// Retain the existing P2WPKH-specific API without broadening its semantics.
inline bool QuietProofIsP2wpkh(const QuietProofClaimV1& claim,
                              const std::vector<uint8_t>& script) {
  return claim.script_kind == QuietProofScriptKind::kP2wpkh &&
         QuietProofMatchesScript(claim, script);
}
inline QuietProofChainStatus QuietProofMatchClaim(const QuietProofClaimV1& claim, QuietProofNetwork network, const QuietProofChainEvidence& evidence) {
  if (evidence.status != QuietProofChainStatus::kUnspent) return evidence.status;
  if (evidence.network != network || evidence.amount_sats != claim.amount_sats || !QuietProofMatchesScript(claim, evidence.script_pub_key)) return QuietProofChainStatus::kInconclusive;
  return QuietProofChainStatus::kUnspent;
}
}  // namespace proofs
#endif
