// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SIGNATURE_DIGEST_H_
#define QUIETPROOF_SIGNATURE_DIGEST_H_

#include "quietproof/signature_profile.h"

namespace proofs {
struct QuietProofSignatureInputsV1 {
  QuietProofSignatureProfileV1 profile;
  std::array<uint8_t, 32> z{};  // Raw SHA output bytes; ECDSA interprets these big endian.
  std::vector<uint8_t> sighash_preimage; // BIP322 ALL:90/182 bytes; Bitcoin Signed Message:114 bytes.
  std::array<uint8_t, 32> hash_prevouts{}, hash_sequence{}, hash_outputs{}; // BIP-143 only.
};
enum class QuietProofSignatureDigestError {
  kNone, kMalformedStatement, kUnsupported, kSignatureModeDisabled
};
inline const char* QuietProofSignatureDigestErrorName(QuietProofSignatureDigestError error) {
  switch (error) {
    case QuietProofSignatureDigestError::kNone: return "none";
    case QuietProofSignatureDigestError::kMalformedStatement: return "malformed_statement";
    case QuietProofSignatureDigestError::kUnsupported: return "unsupported";
    case QuietProofSignatureDigestError::kSignatureModeDisabled: return "signature_mode_disabled";
  }
  return "malformed_statement";
}

// Explicit signature operation. Only the independently retained canonical
// request is an input: there is no raw-transaction editor, supplied digest,
// alternative sighash, amount or scriptCode. Derived objects are outputs only.
// Keep this capability-dependent entry point TU-local, including in mixed
// base-only/enabled executables. On every failure output remains unchanged.
static inline bool DeriveQuietProofSignatureInputs(
    const std::vector<uint8_t>& expected_request, QuietProofSignatureInputsV1* output,
    QuietProofSignatureDigestError* error = nullptr) {
  const auto fail = [error](QuietProofSignatureDigestError code) {
    if (error) *error = code;
    return false;
  };
  if (!output) return fail(QuietProofSignatureDigestError::kMalformedStatement);
  QuietProofSignatureStatementV4 expected;
  QuietProofDecodeError decode_error;
  if (!DecodeQuietProofSignatureStatement(expected_request, &expected, &decode_error))
    return fail(decode_error == QuietProofDecodeError::kUnsupported ?
        QuietProofSignatureDigestError::kUnsupported : QuietProofSignatureDigestError::kMalformedStatement);
#if !defined(QUIETPROOF_HAS_SIGNATURE_MODE) || !QUIETPROOF_HAS_SIGNATURE_MODE
  return fail(QuietProofSignatureDigestError::kSignatureModeDisabled);
#endif
  if (!QuietProofSigningProfileImplemented(expected.signing_profile))
    return fail(QuietProofSignatureDigestError::kUnsupported);
  QuietProofSignatureInputsV1 inputs;
  if (!quietproof_detail::BuildQuietProofSignatureProfile(expected, &inputs.profile))
    return fail(QuietProofSignatureDigestError::kMalformedStatement);
  const auto& profile = inputs.profile;
  auto& preimage = inputs.sighash_preimage;
  if (expected.signing_profile == QuietProofSigningProfile::kBitcoinMessageEcdsaV1) {
    // Both lengths fit the one-byte canonical CompactSize form. The signed
    // application message is always exactly 88 ASCII bytes, regardless of
    // UTF-8 text lengths inside the canonical request committed by its digest.
    constexpr char domain[] = "Bitcoin Signed Message:\n";
    static_assert(sizeof(domain) - 1 == 24);
    static_assert(kQuietProofSignatureApplicationMessageBytes == 88);
    preimage.push_back(24);
    preimage.insert(preimage.end(), domain, domain + 24);
    preimage.push_back(88);
    preimage.insert(preimage.end(), profile.application_message.begin(), profile.application_message.end());
    inputs.z = quietproof_detail::QuietProofSignatureHash256(preimage.data(), preimage.size());
    *output = std::move(inputs);
    if (error) *error = QuietProofSignatureDigestError::kNone;
    return true;
  }
  preimage.reserve(kQuietProofSignatureWitnessPreimageBytes);
  if (expected.signing_kind == QuietProofScriptKind::kP2pkh) {
    // Legacy ALL input zero: replace only the empty scriptSig with P2PKH C.
    const auto& child = profile.unsigned_to_sign;
    preimage.assign(child.begin(), child.begin() + 41);
    preimage.push_back(0x19); // Minimal CompactSize for 25-byte scriptCode.
    preimage.insert(preimage.end(), profile.script_code.begin(), profile.script_code.end());
    preimage.insert(preimage.end(), child.begin() + 42, child.end());
  } else {
    constexpr std::array<uint8_t, 4> zero_sequence{};
    constexpr std::array<uint8_t, 10> zero_op_return_output{0,0,0,0,0,0,0,0,1,0x6a};
    inputs.hash_prevouts = quietproof_detail::QuietProofSignatureHash256(
        profile.synthetic_outpoint.data(), profile.synthetic_outpoint.size());
    inputs.hash_sequence = quietproof_detail::QuietProofSignatureHash256(
        zero_sequence.data(), zero_sequence.size());
    inputs.hash_outputs = quietproof_detail::QuietProofSignatureHash256(
        zero_op_return_output.data(), zero_op_return_output.size());
    preimage.assign(4, 0); // Version zero, little endian.
    preimage.insert(preimage.end(), inputs.hash_prevouts.begin(), inputs.hash_prevouts.end());
    preimage.insert(preimage.end(), inputs.hash_sequence.begin(), inputs.hash_sequence.end());
    preimage.insert(preimage.end(), profile.synthetic_outpoint.begin(), profile.synthetic_outpoint.end());
    preimage.push_back(0x19);
    preimage.insert(preimage.end(), profile.script_code.begin(), profile.script_code.end());
    preimage.insert(preimage.end(), 8, 0); // Zero synthetic amount, little endian.
    preimage.insert(preimage.end(), 4, 0); // Sequence zero.
    preimage.insert(preimage.end(), inputs.hash_outputs.begin(), inputs.hash_outputs.end());
    preimage.insert(preimage.end(), 4, 0); // Locktime zero.
  }
  preimage.insert(preimage.end(), {0x01,0x00,0x00,0x00}); // SIGHASH_ALL as u32 LE.
  inputs.z = quietproof_detail::QuietProofSignatureHash256(preimage.data(), preimage.size());
  *output = std::move(inputs);
  if (error) *error = QuietProofSignatureDigestError::kNone;
  return true;
}
}  // namespace proofs
#endif
