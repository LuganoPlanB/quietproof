// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_BIP322_IMPORT_H_
#define QUIETPROOF_BIP322_IMPORT_H_

#include <string>
#include "quietproof/signature_authorisation.h"
#include "quietproof/signature_encoding.h"

namespace proofs {
enum class QuietProofBip322Format { kSimple, kFull };

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
  if (inputs.profile.signing_profile != QuietProofSigningProfile::kBip322EcdsaV1)
    return fail(QuietProofSignatureAuthorisationError::kUnsupported);
  const std::string prefix = format == QuietProofBip322Format::kSimple ? "smp" : "ful";
  std::vector<uint8_t> decoded;
  if (!quietproof_detail::DecodeQuietProofSignatureBase64(
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
  std::vector<uint8_t> candidate{'Q','P','A','1',kQuietProofSignatureStatementVersion,
      kQuietProofSignatureMode,0,static_cast<uint8_t>(QuietProofSigningProfile::kBip322EcdsaV1),
      kQuietProofSigningProfileVersion};
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
