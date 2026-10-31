// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_POKSIG_PROVER_H_
#define QUIETPROOF_POKSIG_PROVER_H_

#include <chrono>
#include <functional>
#include "poksig/verifier.h"
#include "quietproof/signature_authorisation.h"
#if defined(QUIETPROOF_HAS_SIGNATURE_MODE) && QUIETPROOF_HAS_SIGNATURE_MODE
#include "circuit/signature_possession_witness.h"
#include "random/secure_random_engine.h"
#include "zk/zk_prover.h"
#endif

namespace proofs {

// Explicit signature-only operation: expected request plus private Q/r/s,
// never a scalar, free digest or caller-selected circuit. Outputs are unchanged
// on failure. The timestamp is the local prover start, not signing time.
static inline bool PoKSigProve(
    const std::vector<uint8_t>& expected_request, const QuietProofSignatureAuthorisationV1& authorization,
    PoKSigProofV1* output, PoKSigOptionsV1 options, PoKSigError* error = nullptr,
    const std::function<void(const char*)>& progress = {}) {
  const auto fail = [error](PoKSigError code) { if (error) *error = code; return false; };
  const auto clock = std::chrono::system_clock::now();
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(clock.time_since_epoch()).count();
  if (!output) return fail(PoKSigError::kMalformedStatement);
  QuietProofSignatureStatementV3 expected;
  QuietProofDecodeError decoded;
  if (!DecodeQuietProofSignatureStatement(expected_request, &expected, &decoded))
    return fail(decoded == QuietProofDecodeError::kUnsupported ?
        PoKSigError::kUnsupported : PoKSigError::kMalformedStatement);
#if !defined(QUIETPROOF_HAS_SIGNATURE_MODE) || !QUIETPROOF_HAS_SIGNATURE_MODE
  return fail(PoKSigError::kSignatureModeDisabled);
#else
  if (!options.allow_signature_possession) return fail(PoKSigError::kSignatureModeNotAllowed);
  if (seconds <= 0 || static_cast<uint64_t>(seconds) < expected.not_before ||
      static_cast<uint64_t>(seconds) >= expected.expires_at) return fail(PoKSigError::kInvalidAuthorization);
  QuietProofSignatureInputsV1 inputs;
  if (!DeriveQuietProofSignatureInputs(expected_request, &inputs)) return fail(PoKSigError::kMalformedStatement);
  if (authorization.statement_digest != inputs.profile.statement_digest ||
      !quietproof_detail::SignatureReceiptEcdsaValid(inputs.z, authorization.public_key, authorization.r, authorization.s))
    return fail(PoKSigError::kInvalidAuthorization);
  std::array<uint8_t, 32> key_hash;
  SHA256 sha; sha.Update(authorization.public_key.data(), authorization.public_key.size()); sha.DigestData(key_hash.data());
  if (Ripemd160::digest(key_hash) != inputs.profile.h) return fail(PoKSigError::kInvalidAuthorization);
  std::array<uint8_t, 32> x_bytes;
  std::copy_n(authorization.public_key.begin() + 1, 32, x_bytes.begin());
  const auto qx = quietproof_detail::SignatureReceiptNat(x_bytes);
  const auto xm = p256k1_base.to_montgomery(qx);
  const auto square = p256k1_base.addf(p256k1_base.mulf(p256k1_base.mulf(xm, xm), xm), p256k1_base.of_scalar(7));
  auto exponent = p256k1_base.m_; exponent.add(Fp256k1Nat(1)); exponent.shiftr(2);
  auto ym = p256k1_base.one();
  for (size_t bit = 256; bit-- > 0;) {
    ym = p256k1_base.mulf(ym, ym);
    if (exponent.bit(bit)) ym = p256k1_base.mulf(ym, square);
  }
  if (p256k1_base.from_montgomery(ym).bit(0) != (authorization.public_key[0] & 1)) ym = p256k1_base.negf(ym);
  SignaturePossessionWitnessV1 witness;
  witness.compute(quietproof_detail::SignatureReceiptNat(inputs.z), qx, p256k1_base.from_montgomery(ym),
      quietproof_detail::SignatureReceiptNat(authorization.r), quietproof_detail::SignatureReceiptNat(authorization.s));
  if (progress) progress("building signature circuit");
  quietproof_detail::PoKSigCircuitState state;
  if (!state.qualified()) return fail(PoKSigError::kUnsupportedResources);
  PoKSigPublicInputsV1 encoded;
  if (!PoKSigEncodePublicInputs(expected_request, &encoded)) return fail(PoKSigError::kMalformedStatement);
  auto private_inputs = std::make_unique<Dense<Fp256k1Base>>(1, state.circuit->ninputs);
  DenseFiller<Fp256k1Base> filler(*private_inputs);
  for (const auto& value : encoded) filler.push_back(value);
  witness.fill_witness(filler);
  if (filler.size() != state.circuit->ninputs) return fail(PoKSigError::kInvalidAuthorization);
  QuietProofSignatureEnvelopeMetadataV3 metadata;
  metadata.request = expected_request;
  metadata.proof_created_at = static_cast<uint64_t>(seconds);
  metadata.circuit_digest = PoKSigExpectedCircuitDigest();
  std::array<uint8_t, 146> binding;
  if (!quietproof_detail::SignatureTranscriptBinding(expected_request, metadata,
      metadata.proof_created_at, &binding)) return fail(PoKSigError::kInvalidAuthorization);
  const auto seed = QuietProofTaggedHash(kPoKSigTranscriptDomain, binding.data(), binding.size());
  quietproof_detail::PoKSigCF cf(p256k1_base);
  quietproof_detail::PoKSigRS rs(cf, p256k1_base);
  ZkProof<Fp256k1Base> proof(*state.circuit, PoKSigParametersV1::kRate, PoKSigParametersV1::kQueries, state.block);
  if (!proof.param.valid()) return fail(PoKSigError::kUnsupportedResources);
  ZkProver<Fp256k1Base, quietproof_detail::PoKSigRS> prover(*state.circuit, p256k1_base, rs);
  SecureRandomEngine random;
  Transcript transcript(seed.data(), seed.size());
  if (progress) progress("committing signature proof");
  prover.commit(proof, *private_inputs, transcript, random);
  if (progress) progress("proving signature possession");
  if (!prover.prove(proof, *private_inputs, transcript)) return fail(PoKSigError::kInvalidAuthorization);
  std::vector<uint8_t> serialized;
  proof.write(serialized, p256k1_base);
  // SDK size() is an estimate. The actual serializer length governs this cap.
  if (serialized.empty() || serialized.size() > kQuietProofSignatureMaxProofBytes)
    return fail(PoKSigError::kUnsupportedResources);
  PoKSigProofV1 result;
  if (!EncodeQuietProofSignatureEnvelope(metadata, serialized, &result.bytes)) return fail(PoKSigError::kInvalidProof);
  *output = std::move(result);
  if (error) *error = PoKSigError::kNone;
  return true;
#endif
}

static inline bool PoKSigProveReceipt(
    const std::vector<uint8_t>& expected_request, const std::vector<uint8_t>& private_receipt,
    PoKSigProofV1* output, PoKSigOptionsV1 options, PoKSigError* error = nullptr,
    const std::function<void(const char*)>& progress = {}) {
  QuietProofSignatureAuthorisationV1 authorization;
  QuietProofSignatureAuthorisationError imported;
  if (!ImportQuietProofSignatureAuthorisation(expected_request, private_receipt, &authorization, &imported)) {
    if (error) {
      switch (imported) {
        case QuietProofSignatureAuthorisationError::kMalformedReceipt: *error = PoKSigError::kMalformedReceipt; break;
        case QuietProofSignatureAuthorisationError::kUnsupported: *error = PoKSigError::kUnsupported; break;
        case QuietProofSignatureAuthorisationError::kSignatureModeDisabled: *error = PoKSigError::kSignatureModeDisabled; break;
        case QuietProofSignatureAuthorisationError::kMalformedStatement: *error = PoKSigError::kMalformedStatement; break;
        default: *error = PoKSigError::kInvalidAuthorization; break;
      }
    }
    return false;
  }
  return PoKSigProve(expected_request, authorization, output, options, error, progress);
}
}  // namespace proofs
#endif
