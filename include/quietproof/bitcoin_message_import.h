// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_BITCOIN_MESSAGE_IMPORT_H_
#define QUIETPROOF_BITCOIN_MESSAGE_IMPORT_H_
#include "quietproof/signature_authorisation.h"
#include "quietproof/signature_encoding.h"
namespace proofs {
// Compact Bitcoin Signed Message transport. The retained v4 request alone
// selects the digest/profile/signer; Base64 conveys only a header and r/s.
// No whitespace, line ending, URL alphabet, high-S normalization or fallback.
static inline bool ImportQuietProofBitcoinMessageSignature(
    const std::vector<uint8_t>& expected_request, const std::string& signature,
    std::vector<uint8_t>* receipt, QuietProofSignatureAuthorisationError* error = nullptr) {
  const auto fail = [error](QuietProofSignatureAuthorisationError code) {
    if (error) *error = code;
    return false;
  };
  if (!receipt || signature.size() != 88)
    return fail(QuietProofSignatureAuthorisationError::kMalformedReceipt);
  QuietProofSignatureInputsV1 inputs;
  QuietProofSignatureDigestError derived;
  if (!DeriveQuietProofSignatureInputs(expected_request, &inputs, &derived))
    return fail(derived == QuietProofSignatureDigestError::kSignatureModeDisabled ?
        QuietProofSignatureAuthorisationError::kSignatureModeDisabled :
        derived == QuietProofSignatureDigestError::kUnsupported ?
        QuietProofSignatureAuthorisationError::kUnsupported :
        QuietProofSignatureAuthorisationError::kMalformedStatement);
  if (inputs.profile.signing_profile != QuietProofSigningProfile::kBitcoinMessageEcdsaV1)
    return fail(QuietProofSignatureAuthorisationError::kUnsupported);
  std::vector<uint8_t> compact;
  if (!quietproof_detail::DecodeQuietProofSignatureBase64(signature, &compact) || compact.size() != 65)
    return fail(QuietProofSignatureAuthorisationError::kMalformedReceipt);
  std::vector<uint8_t> candidate{'Q','P','A','1',kQuietProofSignatureStatementVersion,
      kQuietProofSignatureMode,0,2,kQuietProofSigningProfileVersion};
  candidate.insert(candidate.end(), inputs.profile.statement_digest.begin(), inputs.profile.statement_digest.end());
  QuietProofAppendU32(&candidate, 65);
  candidate.insert(candidate.end(), compact.begin(), compact.end());
  QuietProofSignatureAuthorisationV1 checked;
  if (!ImportQuietProofSignatureAuthorisation(expected_request, candidate, &checked, error)) return false;
  *receipt = std::move(candidate);
  return true;
}
}  // namespace proofs
#endif
