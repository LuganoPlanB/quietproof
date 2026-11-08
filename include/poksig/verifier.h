// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_POKSIG_VERIFIER_H_
#define QUIETPROOF_POKSIG_VERIFIER_H_

#include "quietproof/signature_envelope.h"
#if defined(QUIETPROOF_HAS_SIGNATURE_MODE) && QUIETPROOF_HAS_SIGNATURE_MODE
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuit/signature_possession.h"
#include "pokc/crt_guard.h"
#include "random/transcript.h"
#include "util/byte_cursor.h"
#include "zk/zk_proof.h"
#include "zk/zk_verifier.h"
#endif

namespace proofs {
namespace quietproof_detail {
inline PoKSigError PoKSigEnvelopeError(QuietProofSignatureEnvelopeError error) {
  switch (error) {
    case QuietProofSignatureEnvelopeError::kNone: return PoKSigError::kNone;
    case QuietProofSignatureEnvelopeError::kUnsupported: return PoKSigError::kUnsupported;
    case QuietProofSignatureEnvelopeError::kSignatureModeDisabled: return PoKSigError::kSignatureModeDisabled;
    case QuietProofSignatureEnvelopeError::kUnapprovedCircuit: return PoKSigError::kUnapprovedCircuit;
    case QuietProofSignatureEnvelopeError::kInvalidProof: return PoKSigError::kInvalidProof;
    case QuietProofSignatureEnvelopeError::kPrivateReceiptInput: return PoKSigError::kPrivateReceiptInput;
    default: return PoKSigError::kMalformedStatement;
  }
}
// Dependent implementation types remain TU-local alongside capability-dependent
// entrypoints, including template instantiations in mixed-capability consumers.
#if defined(QUIETPROOF_HAS_SIGNATURE_MODE) && QUIETPROOF_HAS_SIGNATURE_MODE
namespace {
using PoKSigCF = CrtConvolutionFactory<CRT256<Fp256k1Base>, Fp256k1Base>;
using PoKSigRS = ReedSolomonFactory<Fp256k1Base, PoKSigCF>;
struct PoKSigCircuitState {
  QuadCircuit<Fp256k1Base> quad{p256k1_base};
  std::unique_ptr<Circuit<Fp256k1Base>> circuit = SignaturePossessionBuildCircuit(&quad);
  size_t block = circuit->ninputs - circuit->npub_in + quad.nquad_terms_ + 1;
  bool qualified() const {
    return circuit->npub_in == PoKSigParametersV1::kPublicInputs &&
        PoKCCrtBlockSupported(block) && PoKSigCircuitDigest(*circuit) == PoKSigExpectedCircuitDigest();
  }
};
}  // namespace
#endif
}  // namespace quietproof_detail

// Cryptographic signature-possession verification only. The caller retains the
// independently issued canonical request and supplies its observation time.
// Chain/funds policy and final atomic expiry/nonce acceptance are separate.
// No free h/z/circuit/request-from-proof can be used as expected authority.
static inline bool PoKSigVerifyProof(
    const std::vector<uint8_t>& expected_request, const PoKSigProofV1& proof,
    uint64_t now, PoKSigOptionsV1 options, PoKSigError* error = nullptr) {
  const auto fail = [error](PoKSigError code) { if (error) *error = code; return false; };
  QuietProofSignatureEnvelopeMetadataV4 metadata;
  QuietProofSignatureEnvelopeError transport;
  if (!InspectQuietProofSignatureEnvelope(proof.bytes, &metadata, &transport))
    return fail(quietproof_detail::PoKSigEnvelopeError(transport));
  QuietProofSignatureStatementV4 expected;
  QuietProofDecodeError decoded;
  if (!DecodeQuietProofSignatureStatement(expected_request, &expected, &decoded))
    return fail(decoded == QuietProofDecodeError::kUnsupported ?
        PoKSigError::kUnsupported : PoKSigError::kMalformedStatement);
#if !defined(QUIETPROOF_HAS_SIGNATURE_MODE) || !QUIETPROOF_HAS_SIGNATURE_MODE
  return fail(PoKSigError::kSignatureModeDisabled);
#else
  if (!options.allow_signature_possession) return fail(PoKSigError::kSignatureModeNotAllowed);
  if (!PoKSigCircuitIdentityApproved(metadata.circuit_digest)) return fail(PoKSigError::kUnapprovedCircuit);
  if (metadata.request != expected_request || metadata.proof_created_at > now)
    return fail(PoKSigError::kInvalidProof);
  std::array<uint8_t, 32> seed;
  if (!PoKSigTranscriptSeed(expected_request, proof.bytes, now, &seed, &transport))
    return fail(quietproof_detail::PoKSigEnvelopeError(transport));
  PoKSigPublicInputsV1 encoded;
  if (!PoKSigEncodePublicInputs(expected_request, &encoded)) return fail(PoKSigError::kMalformedStatement);
  // All untrusted framing, IDs, capability, allowance, exact request, local
  // identity and time checks precede circuit/proof allocation and proof.read().
  quietproof_detail::PoKSigCircuitState state;
  if (!state.qualified()) return fail(PoKSigError::kUnsupportedResources);
  ZkProof<Fp256k1Base> decoded_proof(*state.circuit, PoKSigParametersV1::kRate,
                                   PoKSigParametersV1::kQueries, state.block);
  if (!decoded_proof.param.valid()) return fail(PoKSigError::kUnsupportedResources);
  ByteCursor cursor(proof.bytes.data() + metadata.proof_offset, metadata.proof_size);
  if (!decoded_proof.read(cursor, p256k1_base) || cursor.remaining()) return fail(PoKSigError::kInvalidProof);
  Dense<Fp256k1Base> public_inputs(1, encoded.size());
  std::copy(encoded.begin(), encoded.end(), public_inputs.v_.begin());
  quietproof_detail::PoKSigCF cf(p256k1_base);
  quietproof_detail::PoKSigRS rs(cf, p256k1_base);
  Transcript transcript(seed.data(), seed.size());
  ZkVerifier<Fp256k1Base, quietproof_detail::PoKSigRS> verifier(*state.circuit, rs,
      PoKSigParametersV1::kRate, PoKSigParametersV1::kQueries, state.block, p256k1_base);
  verifier.recv_commitment(decoded_proof, transcript);
  if (!verifier.verify(decoded_proof, public_inputs, transcript)) return fail(PoKSigError::kInvalidProof);
  if (error) *error = PoKSigError::kNone;
  return true;
#endif
}
}  // namespace proofs
#endif
