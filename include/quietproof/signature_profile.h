// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SIGNATURE_PROFILE_H_
#define QUIETPROOF_SIGNATURE_PROFILE_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>
#include "quietproof/statement.h"

namespace proofs {
constexpr size_t kQuietProofSignatureApplicationMessageBytes = 88;
constexpr size_t kQuietProofSignatureMaxToSpendBytes = 119;
constexpr size_t kQuietProofSignatureUnsignedToSignBytes = 61;
constexpr size_t kQuietProofSignatureLegacyPreimageBytes = 90;
constexpr size_t kQuietProofSignatureWitnessPreimageBytes = 182;

// Derived public bytes, not an authorisation result or accepted prover input.
// Signing/proof entry points must always reconstruct these from their retained
// expected request. No function accepts this object or a free z as authority.
struct QuietProofSignatureProfileV1 {
  QuietProofScriptKind signing_kind = QuietProofScriptKind::kP2wpkh;
  std::array<uint8_t, 20> h{};
  std::array<uint8_t, 32> statement_digest{};
  std::array<uint8_t, kQuietProofSignatureApplicationMessageBytes> application_message{};
  std::array<uint8_t, 32> application_message_hash{};
  std::array<uint8_t, 25> script_code{};
  std::vector<uint8_t> selected_script;  // Exactly 22 or 25 bytes.
  std::vector<uint8_t> to_spend;         // Exactly 116 or 119 bytes.
  std::array<uint8_t, 32> to_spend_txid{};  // Raw SHA output order, not display order.
  std::array<uint8_t, 36> synthetic_outpoint{};
  std::array<uint8_t, kQuietProofSignatureUnsignedToSignBytes> unsigned_to_sign{};
};

namespace quietproof_detail {
inline std::array<uint8_t, 32> QuietProofSignatureHash256(const uint8_t* bytes, size_t size) {
  std::array<uint8_t, 32> first{}, output{};
  SHA256 hash;
  if (size != 0) hash.Update(bytes, size);
  hash.DigestData(first.data());
  SHA256 second;
  second.Update(first.data(), first.size());
  second.DigestData(output.data());
  return output;
}

// Fixed profile construction only. The sole input is a validated v3 request;
// transaction fields, message, hash, amount and signing parameters are derived.
// All vector appends have fixed bounds, independent of real claim count/value.
inline bool BuildQuietProofSignatureProfile(
    const QuietProofSignatureStatementV3& expected, QuietProofSignatureProfileV1* output) {
  if (!output || !QuietProofSignatureStatementValid(expected)) return false;
  QuietProofSignatureProfileV1 profile;
  profile.signing_kind = expected.signing_kind;
  profile.h = expected.claims.front().program;
  if (!QuietProofSignatureStatementDigest(expected, &profile.statement_digest)) return false;
  constexpr char prefix[] = "quietproof:signature:v1:";
  constexpr char hex[] = "0123456789abcdef";
  static_assert(sizeof(prefix) - 1 == 24);
  std::copy_n(prefix, sizeof(prefix) - 1, profile.application_message.begin());
  for (size_t i = 0; i < profile.statement_digest.size(); ++i) {
    profile.application_message[24 + 2 * i] = hex[profile.statement_digest[i] >> 4];
    profile.application_message[25 + 2 * i] = hex[profile.statement_digest[i] & 15];
  }
  profile.application_message_hash = QuietProofBip322MessageHash(
      profile.application_message.data(), profile.application_message.size());
  profile.script_code[0] = 0x76; profile.script_code[1] = 0xa9; profile.script_code[2] = 0x14;
  std::copy(profile.h.begin(), profile.h.end(), profile.script_code.begin() + 3);
  profile.script_code[23] = 0x88; profile.script_code[24] = 0xac;
  if (expected.signing_kind == QuietProofScriptKind::kP2wpkh) {
    profile.selected_script = {0x00, 0x14};
    profile.selected_script.insert(profile.selected_script.end(), profile.h.begin(), profile.h.end());
  } else {
    profile.selected_script.assign(profile.script_code.begin(), profile.script_code.end());
  }

  auto& parent = profile.to_spend;
  parent.reserve(kQuietProofSignatureMaxToSpendBytes);
  parent.assign(4, 0);                  // Version zero (little endian).
  parent.push_back(1);                  // One input, minimal CompactSize.
  parent.insert(parent.end(), 32, 0);   // Null outpoint hash.
  parent.insert(parent.end(), 4, 0xff); // Null outpoint index 0xffffffff LE.
  parent.insert(parent.end(), {0x22, 0x00, 0x20}); // 34-byte OP_0 PUSH32 scriptSig.
  parent.insert(parent.end(), profile.application_message_hash.begin(), profile.application_message_hash.end());
  parent.insert(parent.end(), 4, 0);    // Sequence zero.
  parent.push_back(1);                 // One output.
  parent.insert(parent.end(), 8, 0);    // Synthetic amount zero, never a claimed amount.
  parent.push_back(static_cast<uint8_t>(profile.selected_script.size()));
  parent.insert(parent.end(), profile.selected_script.begin(), profile.selected_script.end());
  parent.insert(parent.end(), 4, 0);    // Locktime zero.
  profile.to_spend_txid = QuietProofSignatureHash256(parent.data(), parent.size());
  std::copy(profile.to_spend_txid.begin(), profile.to_spend_txid.end(), profile.synthetic_outpoint.begin());
  // The remaining four outpoint bytes are output index zero, little endian.
  auto& child = profile.unsigned_to_sign;
  child[4] = 1;                       // One input after version zero.
  std::copy(profile.synthetic_outpoint.begin(), profile.synthetic_outpoint.end(), child.begin() + 5);
  // Empty scriptSig, zero sequence, one zero-valued one-byte OP_RETURN output.
  child[46] = 1; child[55] = 1; child[56] = 0x6a;
  // All other bytes, including version and final locktime, remain zero.
  *output = std::move(profile);
  return true;
}
}  // namespace quietproof_detail
}  // namespace proofs
#endif
