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
#ifndef PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_STATEMENT_H_
#define PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_STATEMENT_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "util/crypto.h"

namespace proofs {

// Values 0..3 were assigned by the original v1 draft. Testnet4 is appended so
// adding it cannot reinterpret an already serialized signet or regtest request.
enum class QuietProofNetwork : uint8_t {
  kMainnet = 0,
  kTestnet3 = 1,
  kTestnet = kTestnet3,
  kSignet = 2,
  kRegtest = 3,
  kTestnet4 = 4,
};

constexpr size_t kQuietProofMaxVerifierBytes = 256;
constexpr size_t kQuietProofMaxPurposeBytes = 64;
constexpr size_t kQuietProofMaxAssetIdBytes = 256;
constexpr size_t kQuietProofMaxClaims = 16;
constexpr size_t kQuietProofMaxKeys = 2;
constexpr size_t kQuietProofMaxStatementBytes = 4096;
constexpr uint64_t kQuietProofMaxMoneySats = 21000000ULL * 100000000ULL;

enum class QuietProofDecodeError : uint8_t { kNone, kMalformed, kUnsupported };

inline bool QuietProofNetworkValid(QuietProofNetwork network) {
  switch (network) {
    case QuietProofNetwork::kMainnet:
    case QuietProofNetwork::kTestnet3:
    case QuietProofNetwork::kSignet:
    case QuietProofNetwork::kRegtest:
    case QuietProofNetwork::kTestnet4:
      return true;
  }
  return false;
}

inline const char* QuietProofNetworkName(QuietProofNetwork network) {
  switch (network) {
    case QuietProofNetwork::kMainnet: return "mainnet";
    case QuietProofNetwork::kTestnet3: return "testnet3";
    case QuietProofNetwork::kSignet: return "signet";
    case QuietProofNetwork::kRegtest: return "regtest";
    case QuietProofNetwork::kTestnet4: return "testnet4";
  }
  return "unsupported";
}

inline const char* QuietProofBitcoinCoreChainName(QuietProofNetwork network) {
  switch (network) {
    case QuietProofNetwork::kMainnet: return "main";
    case QuietProofNetwork::kTestnet3: return "test";
    case QuietProofNetwork::kSignet: return "signet";
    case QuietProofNetwork::kRegtest: return "regtest";
    case QuietProofNetwork::kTestnet4: return "testnet4";
  }
  return "";
}

inline bool QuietProofParseNetwork(const std::string& name,
                                 QuietProofNetwork* network) {
  if (network == nullptr) return false;
  if (name == "mainnet" || name == "main") {
    *network = QuietProofNetwork::kMainnet;
  } else if (name == "testnet" || name == "testnet3" || name == "test") {
    *network = QuietProofNetwork::kTestnet3;
  } else if (name == "testnet4") {
    *network = QuietProofNetwork::kTestnet4;
  } else if (name == "signet") {
    *network = QuietProofNetwork::kSignet;
  } else if (name == "regtest") {
    *network = QuietProofNetwork::kRegtest;
  } else {
    return false;
  }
  return true;
}

template <size_t N>
inline bool QuietProofAllZero(const std::array<uint8_t, N>& value) {
  uint8_t aggregate = 0;
  for (uint8_t byte : value) aggregate |= byte;
  return aggregate == 0;
}

// The public program member remains the compressed-public-key HASH160.
enum class QuietProofScriptKind : uint8_t { kP2wpkh = 0, kP2pkh = 1 };

inline bool QuietProofScriptKindValid(QuietProofScriptKind kind) {
  return kind == QuietProofScriptKind::kP2wpkh ||
         kind == QuietProofScriptKind::kP2pkh;
}

inline const char* QuietProofScriptKindName(QuietProofScriptKind kind) {
  switch (kind) {
    case QuietProofScriptKind::kP2wpkh: return "p2wpkh";
    case QuietProofScriptKind::kP2pkh: return "p2pkh";
  }
  return "unsupported";
}

struct QuietProofClaimV1 {
  std::array<uint8_t, 32> txid{};  // Bitcoin RPC/display byte order.
  uint32_t vout = 0;
  uint64_t amount_sats = 0;
  std::array<uint8_t, 20> program{};
  QuietProofScriptKind script_kind = QuietProofScriptKind::kP2wpkh;

  bool operator<(const QuietProofClaimV1& other) const {
    const int comparison = std::memcmp(txid.data(), other.txid.data(), txid.size());
    return comparison != 0 ? comparison < 0 : vout < other.vout;
  }
  bool operator==(const QuietProofClaimV1& other) const {
    return txid == other.txid && vout == other.vout;
  }
};

struct QuietProofBridgeBindingV1 {
  QuietProofNetwork destination_network = QuietProofNetwork::kMainnet;
  std::array<uint8_t, 32> destination_commitment{};
  std::string asset_id;
  std::array<uint8_t, 32> lock_id{};
};

struct QuietProofStatementV1 {
  QuietProofNetwork network = QuietProofNetwork::kMainnet;
  std::string verifier;
  std::string purpose;
  std::array<uint8_t, 32> nonce{};
  std::array<uint8_t, 32> bip322_message_hash{};
  uint64_t not_before = 0;
  uint64_t expires_at = 0;
  bool has_snapshot = false;
  std::array<uint8_t, 32> snapshot{};
  uint32_t snapshot_height = 0;
  bool has_bridge_binding = false;
  QuietProofBridgeBindingV1 bridge;
  std::vector<QuietProofClaimV1> claims;
  uint8_t statement_version = 1;  // Retained on decode; never silently downgrade.
};

inline bool QuietProofUtf8(const std::string& text) {
  for (size_t index = 0; index < text.size();) {
    const uint8_t lead = static_cast<uint8_t>(text[index++]);
    if (lead < 0x20 || lead == 0x7f) return false;
    if (lead < 0x80) continue;
    const size_t continuation =
        lead >= 0xf0 && lead <= 0xf4 ? 3 :
        lead >= 0xe0 && lead <= 0xef ? 2 :
        lead >= 0xc2 && lead <= 0xdf ? 1 : 99;
    if (continuation == 99 || index + continuation > text.size()) return false;
    uint32_t codepoint = lead & ((1u << (6 - continuation)) - 1);
    for (size_t i = 0; i < continuation; ++i) {
      const uint8_t byte = static_cast<uint8_t>(text[index++]);
      if ((byte & 0xc0) != 0x80) return false;
      codepoint = (codepoint << 6) | (byte & 0x3f);
    }
    if ((continuation == 1 && codepoint < 0x80) ||
        (continuation == 2 && codepoint < 0x800) ||
        (continuation == 3 && (codepoint < 0x10000 || codepoint > 0x10ffff)) ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
      return false;
    }
  }
  return true;
}

inline bool QuietProofPurposeValid(const std::string& purpose) {
  return purpose == "proof-of-control" || purpose == "proof-of-funds" ||
         purpose == "bridge-authorization";
}

inline bool QuietProofProgramLess(const std::array<uint8_t, 20>& left,
                                const std::array<uint8_t, 20>& right) {
  return std::memcmp(left.data(), right.data(), left.size()) < 0;
}

inline bool QuietProofStatementValid(const QuietProofStatementV1& statement) {
  if ((statement.statement_version != 1 && statement.statement_version != 2) ||
      !QuietProofNetworkValid(statement.network) || statement.verifier.empty() ||
      statement.verifier.size() > kQuietProofMaxVerifierBytes ||
      !QuietProofUtf8(statement.verifier) || !QuietProofPurposeValid(statement.purpose) ||
      statement.purpose.size() > kQuietProofMaxPurposeBytes ||
      QuietProofAllZero(statement.nonce) ||
      QuietProofAllZero(statement.bip322_message_hash) ||
      statement.not_before >= statement.expires_at || statement.claims.empty() ||
      statement.claims.size() > kQuietProofMaxClaims) {
    return false;
  }
  if (statement.has_snapshot && QuietProofAllZero(statement.snapshot)) return false;
  if (!statement.has_snapshot &&
      (!QuietProofAllZero(statement.snapshot) || statement.snapshot_height != 0)) {
    return false;
  }
  if (statement.has_bridge_binding) {
    if (statement.purpose != "bridge-authorization" ||
        !QuietProofNetworkValid(statement.bridge.destination_network) ||
        QuietProofAllZero(statement.bridge.destination_commitment) ||
        statement.bridge.asset_id.empty() ||
        statement.bridge.asset_id.size() > kQuietProofMaxAssetIdBytes ||
        !QuietProofUtf8(statement.bridge.asset_id) ||
        QuietProofAllZero(statement.bridge.lock_id)) {
      return false;
    }
  } else if (statement.purpose == "bridge-authorization") {
    return false;
  }

  std::vector<std::array<uint8_t, 20>> programs;
  programs.reserve(statement.claims.size());
  uint64_t total_sats = 0;
  for (size_t index = 0; index < statement.claims.size(); ++index) {
    const auto& claim = statement.claims[index];
    if (!QuietProofScriptKindValid(claim.script_kind) ||
        (statement.statement_version == 1 &&
         claim.script_kind != QuietProofScriptKind::kP2wpkh) ||
        QuietProofAllZero(claim.txid) || claim.amount_sats == 0 ||
        claim.amount_sats > kQuietProofMaxMoneySats ||
        claim.amount_sats > kQuietProofMaxMoneySats - total_sats ||
        (index != 0 && !(statement.claims[index - 1] < claim))) {
      return false;
    }
    total_sats += claim.amount_sats;
    programs.push_back(claim.program);
  }
  std::sort(programs.begin(), programs.end(), QuietProofProgramLess);
  programs.erase(std::unique(programs.begin(), programs.end()), programs.end());
  return !programs.empty() && programs.size() <= kQuietProofMaxKeys;
}

// Compatibility API name: these are distinct compressed-public-key hashes,
// shared by ownership witnesses even when output script kinds differ.
inline bool QuietProofDistinctPrograms(
    const QuietProofStatementV1& statement,
    std::vector<std::array<uint8_t, 20>>* programs) {
  if (programs == nullptr || !QuietProofStatementValid(statement)) return false;
  programs->clear();
  programs->reserve(statement.claims.size());
  for (const auto& claim : statement.claims) programs->push_back(claim.program);
  std::sort(programs->begin(), programs->end(), QuietProofProgramLess);
  programs->erase(std::unique(programs->begin(), programs->end()), programs->end());
  return true;
}

inline void QuietProofAppendU16(std::vector<uint8_t>* output, uint16_t value) {
  output->push_back(static_cast<uint8_t>(value >> 8));
  output->push_back(static_cast<uint8_t>(value));
}
inline void QuietProofAppendU32(std::vector<uint8_t>* output, uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8)
    output->push_back(static_cast<uint8_t>(value >> shift));
}
inline void QuietProofAppendU64(std::vector<uint8_t>* output, uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8)
    output->push_back(static_cast<uint8_t>(value >> shift));
}

inline bool EncodeQuietProofStatement(const QuietProofStatementV1& statement,
                                    std::vector<uint8_t>* output) {
  if (output == nullptr || !QuietProofStatementValid(statement)) return false;
  output->clear();
  output->insert(output->end(), {'Q', 'P', 'S', '1', statement.statement_version,
                                 static_cast<uint8_t>(statement.network)});
  QuietProofAppendU16(output, static_cast<uint16_t>(statement.verifier.size()));
  output->insert(output->end(), statement.verifier.begin(), statement.verifier.end());
  QuietProofAppendU16(output, static_cast<uint16_t>(statement.purpose.size()));
  output->insert(output->end(), statement.purpose.begin(), statement.purpose.end());
  output->insert(output->end(), statement.nonce.begin(), statement.nonce.end());
  output->insert(output->end(), statement.bip322_message_hash.begin(),
                 statement.bip322_message_hash.end());
  QuietProofAppendU64(output, statement.not_before);
  QuietProofAppendU64(output, statement.expires_at);
  output->push_back(statement.has_snapshot ? 1 : 0);
  if (statement.has_snapshot) {
    output->insert(output->end(), statement.snapshot.begin(), statement.snapshot.end());
    QuietProofAppendU32(output, statement.snapshot_height);
  }
  output->push_back(statement.has_bridge_binding ? 1 : 0);
  if (statement.has_bridge_binding) {
    output->push_back(static_cast<uint8_t>(statement.bridge.destination_network));
    output->insert(output->end(), statement.bridge.destination_commitment.begin(),
                   statement.bridge.destination_commitment.end());
    QuietProofAppendU16(output,
                     static_cast<uint16_t>(statement.bridge.asset_id.size()));
    output->insert(output->end(), statement.bridge.asset_id.begin(),
                   statement.bridge.asset_id.end());
    output->insert(output->end(), statement.bridge.lock_id.begin(),
                   statement.bridge.lock_id.end());
  }
  QuietProofAppendU16(output, static_cast<uint16_t>(statement.claims.size()));
  for (const auto& claim : statement.claims) {
    output->insert(output->end(), claim.txid.begin(), claim.txid.end());
    QuietProofAppendU32(output, claim.vout);
    QuietProofAppendU64(output, claim.amount_sats);
    if (statement.statement_version == 2)
      output->push_back(static_cast<uint8_t>(claim.script_kind));
    output->insert(output->end(), claim.program.begin(), claim.program.end());
  }
  return output->size() <= kQuietProofMaxStatementBytes;
}

class QuietProofReader {
 public:
  explicit QuietProofReader(const std::vector<uint8_t>& bytes)
      : pointer_(bytes.data()), remaining_(bytes.size()) {}
  bool bytes(uint8_t* output, size_t size) {
    if (size > remaining_ || (size != 0 && output == nullptr)) return false;
    if (size != 0) std::memcpy(output, pointer_, size);
    pointer_ += size;
    remaining_ -= size;
    return true;
  }
  bool u8(uint8_t* output) { return bytes(output, 1); }
  bool u16(uint16_t* output) {
    uint8_t bytes_value[2];
    if (output == nullptr || !bytes(bytes_value, sizeof(bytes_value))) return false;
    *output = (uint16_t(bytes_value[0]) << 8) | bytes_value[1];
    return true;
  }
  bool u32(uint32_t* output) {
    uint8_t bytes_value[4];
    if (output == nullptr || !bytes(bytes_value, sizeof(bytes_value))) return false;
    *output = (uint32_t(bytes_value[0]) << 24) |
              (uint32_t(bytes_value[1]) << 16) |
              (uint32_t(bytes_value[2]) << 8) | bytes_value[3];
    return true;
  }
  bool u64(uint64_t* output) {
    uint8_t bytes_value[8];
    if (output == nullptr || !bytes(bytes_value, sizeof(bytes_value))) return false;
    *output = 0;
    for (uint8_t byte : bytes_value) *output = (*output << 8) | byte;
    return true;
  }
  bool text(std::string* output, size_t maximum) {
    uint16_t size = 0;
    if (output == nullptr || !u16(&size) || size > maximum || size > remaining_)
      return false;
    output->assign(reinterpret_cast<const char*>(pointer_), size);
    pointer_ += size;
    remaining_ -= size;
    return QuietProofUtf8(*output);
  }
  size_t left() const { return remaining_; }

 private:
  const uint8_t* pointer_;
  size_t remaining_;
};

inline bool DecodeQuietProofStatement(
    const std::vector<uint8_t>& bytes, QuietProofStatementV1* statement,
    QuietProofDecodeError* error = nullptr) {
  if (error != nullptr) *error = QuietProofDecodeError::kMalformed;
  if (statement == nullptr || bytes.size() < 6 ||
      bytes.size() > kQuietProofMaxStatementBytes) {
    return false;
  }
  QuietProofReader reader(bytes);
  uint8_t magic[4] = {}, version = 0, network_byte = 0;
  if (!reader.bytes(magic, sizeof(magic)) || std::memcmp(magic, "QPS1", 4) != 0)
    return false;
  if (!reader.u8(&version) || (version != 1 && version != 2)) {
    if (error != nullptr) *error = QuietProofDecodeError::kUnsupported;
    return false;
  }
  if (!reader.u8(&network_byte)) return false;
  const auto network = static_cast<QuietProofNetwork>(network_byte);
  if (!QuietProofNetworkValid(network)) {
    if (error != nullptr) *error = QuietProofDecodeError::kUnsupported;
    return false;
  }

  QuietProofStatementV1 decoded;
  decoded.network = network;
  decoded.statement_version = version;
  if (!reader.text(&decoded.verifier, kQuietProofMaxVerifierBytes) ||
      !reader.text(&decoded.purpose, kQuietProofMaxPurposeBytes) ||
      !reader.bytes(decoded.nonce.data(), decoded.nonce.size()) ||
      !reader.bytes(decoded.bip322_message_hash.data(),
                    decoded.bip322_message_hash.size()) ||
      !reader.u64(&decoded.not_before) || !reader.u64(&decoded.expires_at)) {
    return false;
  }
  uint8_t present = 0;
  if (!reader.u8(&present) || present > 1) return false;
  decoded.has_snapshot = present == 1;
  if (decoded.has_snapshot &&
      (!reader.bytes(decoded.snapshot.data(), decoded.snapshot.size()) ||
       !reader.u32(&decoded.snapshot_height))) {
    return false;
  }
  if (!reader.u8(&present) || present > 1) return false;
  decoded.has_bridge_binding = present == 1;
  if (decoded.has_bridge_binding) {
    uint8_t destination_network = 0;
    if (!reader.u8(&destination_network)) return false;
    decoded.bridge.destination_network =
        static_cast<QuietProofNetwork>(destination_network);
    if (!QuietProofNetworkValid(decoded.bridge.destination_network)) {
      if (error != nullptr) *error = QuietProofDecodeError::kUnsupported;
      return false;
    }
    if (!reader.bytes(decoded.bridge.destination_commitment.data(),
                      decoded.bridge.destination_commitment.size()) ||
        !reader.text(&decoded.bridge.asset_id, kQuietProofMaxAssetIdBytes) ||
        !reader.bytes(decoded.bridge.lock_id.data(), decoded.bridge.lock_id.size())) {
      return false;
    }
  }
  uint16_t count = 0;
  if (!reader.u16(&count) || count == 0 || count > kQuietProofMaxClaims) return false;
  decoded.claims.resize(count);
  for (auto& claim : decoded.claims) {
    if (!reader.bytes(claim.txid.data(), claim.txid.size()) ||
        !reader.u32(&claim.vout) || !reader.u64(&claim.amount_sats)) {
      return false;
    }
    if (version == 2) {
      uint8_t kind = 0;
      if (!reader.u8(&kind)) return false;
      claim.script_kind = static_cast<QuietProofScriptKind>(kind);
      if (!QuietProofScriptKindValid(claim.script_kind)) {
        if (error != nullptr) *error = QuietProofDecodeError::kUnsupported;
        return false;
      }
    }
    if (!reader.bytes(claim.program.data(), claim.program.size())) return false;
  }
  if (reader.left() != 0 || !QuietProofStatementValid(decoded)) return false;
  *statement = std::move(decoded);
  if (error != nullptr) *error = QuietProofDecodeError::kNone;
  return true;
}

inline std::array<uint8_t, 32> QuietProofTaggedHash(const char* tag,
                                                  const uint8_t* data,
                                                  size_t size) {
  std::array<uint8_t, 32> tag_hash{}, output{};
  SHA256 tag_hasher;
  tag_hasher.Update(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag));
  tag_hasher.DigestData(tag_hash.data());
  SHA256 hasher;
  hasher.Update(tag_hash.data(), tag_hash.size());
  hasher.Update(tag_hash.data(), tag_hash.size());
  if (size != 0) hasher.Update(data, size);
  hasher.DigestData(output.data());
  return output;
}

inline std::array<uint8_t, 32> QuietProofBip322MessageHash(
    const uint8_t* message, size_t size) {
  return QuietProofTaggedHash("BIP0322-signed-message", message, size);
}

inline bool QuietProofStatementDigest(const QuietProofStatementV1& statement,
                                    std::array<uint8_t, 32>* digest) {
  std::vector<uint8_t> bytes;
  if (digest == nullptr || !EncodeQuietProofStatement(statement, &bytes)) return false;
  const char* tag = statement.statement_version == 2 ?
      "QuietProof/statement/v2" : "QuietProof/statement/v1";
  *digest = QuietProofTaggedHash(tag, bytes.data(), bytes.size());
  return true;
}

}  // namespace proofs
#endif
