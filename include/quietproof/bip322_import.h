// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_BIP322_IMPORT_H_
#define QUIETPROOF_BIP322_IMPORT_H_

#include <string>
#include "quietproof/signature_authorisation.h"

namespace proofs {
enum class QuietProofBip322Format { kSimple, kFull };

namespace quietproof_detail {
// Strict RFC4648 alphabet, padding and unused bits. No whitespace, trimming,
// alternate alphabets or length-dependent unbounded allocations are accepted.
inline bool DecodeQuietProofBip322Base64(const std::string& text,
                                       std::vector<uint8_t>* output) {
  if (text.empty() || text.size() > 228 || text.size() % 4) return false;
  const auto digit = [](char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    return c == '+' ? 62 : c == '/' ? 63 : -1;
  };
  std::vector<uint8_t> decoded;
  for (size_t i = 0; i < text.size(); i += 4) {
    const int a = digit(text[i]), b = digit(text[i+1]);
    const bool pad_c = text[i+2] == '=', pad_d = text[i+3] == '=';
    const int c = pad_c ? 0 : digit(text[i+2]), d = pad_d ? 0 : digit(text[i+3]);
    if (a < 0 || b < 0 || c < 0 || d < 0 || (pad_c && !pad_d) ||
        ((pad_c || pad_d) && i + 4 != text.size()) ||
        (pad_c && (b & 15)) || (pad_d && !pad_c && (c & 3))) return false;
    decoded.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
    if (!pad_c) decoded.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
    if (!pad_d) decoded.push_back(static_cast<uint8_t>((c << 6) | d));
  }
  *output = std::move(decoded);
  return true;
}
}  // namespace quietproof_detail

// Local private-witness adapter, never a general script interpreter. Simple is
// P2WPKH only; Full accepts precisely the existing fixed ECDSA profile. Legacy
// compact messages, Schnorr, PSBTs, timelocks and extra inputs are unsupported.
// Prefixless encodings are accepted only under the explicitly selected format
// for pre-final BIP322 interoperability. No supplied digest/message is trusted.
static inline bool ImportQuietProofBip322Signature(
    const std::vector<uint8_t>& expected_request, QuietProofBip322Format format,
    const std::string& signature, std::vector<uint8_t>* receipt,
    QuietProofSignatureAuthorisationError* error = nullptr) {
  const auto fail = [error](QuietProofSignatureAuthorisationError code) {
    if (error) *error = code;
    return false;
  };
  if (!receipt || signature.size() > 231)
    return fail(QuietProofSignatureAuthorisationError::kMalformedReceipt);
  if (format != QuietProofBip322Format::kSimple && format != QuietProofBip322Format::kFull)
    return fail(QuietProofSignatureAuthorisationError::kUnsupported);
  QuietProofSignatureInputsV1 inputs;
  QuietProofSignatureDigestError derive_error;
  if (!DeriveQuietProofSignatureInputs(expected_request, &inputs, &derive_error))
    return fail(derive_error == QuietProofSignatureDigestError::kSignatureModeDisabled ?
        QuietProofSignatureAuthorisationError::kSignatureModeDisabled :
        derive_error == QuietProofSignatureDigestError::kUnsupported ?
        QuietProofSignatureAuthorisationError::kUnsupported :
        QuietProofSignatureAuthorisationError::kMalformedStatement);
  if (format == QuietProofBip322Format::kSimple &&
      inputs.profile.signing_kind != QuietProofScriptKind::kP2wpkh)
    return fail(QuietProofSignatureAuthorisationError::kUnsupported);
  const std::string prefix = format == QuietProofBip322Format::kSimple ? "smp" : "ful";
  std::vector<uint8_t> decoded;
  if (!quietproof_detail::DecodeQuietProofBip322Base64(
          signature.starts_with(prefix) ? signature.substr(3) : signature, &decoded))
    return fail(QuietProofSignatureAuthorisationError::kMalformedReceipt);
  std::vector<uint8_t> transaction;
  if (format == QuietProofBip322Format::kSimple) {
    const auto& child = inputs.profile.unsigned_to_sign;
    transaction.assign(child.begin(), child.begin() + 4);
    transaction.insert(transaction.end(), {0, 1}); // Segwit marker/flag.
    transaction.insert(transaction.end(), child.begin() + 4, child.end() - 4);
    transaction.insert(transaction.end(), decoded.begin(), decoded.end());
    transaction.insert(transaction.end(), child.end() - 4, child.end());
  } else transaction = std::move(decoded);
  // QPA1 framing is transport only; existing receipt validation independently
  // checks the complete synthetic transaction, HASH160, low-S and ECDSA.
  std::vector<uint8_t> candidate{'Q','P','A','1',1,1,0,1};
  candidate.insert(candidate.end(), inputs.profile.statement_digest.begin(), inputs.profile.statement_digest.end());
  const uint32_t size = static_cast<uint32_t>(transaction.size());
  for (int shift : {24,16,8,0}) candidate.push_back(static_cast<uint8_t>(size >> shift));
  candidate.insert(candidate.end(), transaction.begin(), transaction.end());
  QuietProofSignatureAuthorisationV1 checked;
  if (!ImportQuietProofSignatureAuthorisation(expected_request, candidate, &checked, error)) return false;
  *receipt = std::move(candidate);
  return true;
}
}  // namespace proofs
#endif
