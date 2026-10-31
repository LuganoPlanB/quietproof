// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_POKSIG_PROOF_H_
#define QUIETPROOF_POKSIG_PROOF_H_

#include "circuits/logic/bit_plucker_encoder.h"
#include "ec/p256k1.h"
#include "proto/circuit_writer.h"
#include "quietproof/signature_digest.h"

namespace proofs {
struct PoKSigParametersV1 {
  static constexpr uint16_t kFamily = 1;
  static constexpr uint32_t kCircuitVersion = 1;
  static constexpr uint32_t kRate = 4;
  static constexpr uint32_t kQueries = 128;
  static constexpr size_t kPublicInputs = 53;
  static constexpr size_t kHashOffset = 1;
  static constexpr size_t kDigestOffset = 21;
};
inline constexpr char kPoKSigCircuitDomain[] = "QuietProof/signature/circuit/v1";
inline constexpr char kPoKSigTranscriptDomain[] = "QuietProof/signature/transcript/v1";
using PoKSigPublicInputsV1 = std::array<Fp256k1Base::Elt, PoKSigParametersV1::kPublicInputs>;

// Identity computation is not approval. L5 must qualify the complete composed
// circuit and pin its actual digest; no caller-supplied digest can approve it.
inline std::array<uint8_t, 32> PoKSigCircuitDigest(const Circuit<Fp256k1Base>& circuit) {
  std::vector<uint8_t> circuit_bytes;
  CircuitWriter<Fp256k1Base>(p256k1_base, SECP_ID).to_bytes(circuit, circuit_bytes);
  std::vector<uint8_t> binding;
  QuietProofAppendU16(&binding, PoKSigParametersV1::kFamily);
  QuietProofAppendU32(&binding, PoKSigParametersV1::kCircuitVersion);
  QuietProofAppendU32(&binding, PoKSigParametersV1::kRate);
  QuietProofAppendU32(&binding, PoKSigParametersV1::kQueries);
  QuietProofAppendU64(&binding, static_cast<uint64_t>(circuit_bytes.size()));
  binding.insert(binding.end(), circuit_bytes.begin(), circuit_bytes.end());
  return QuietProofTaggedHash(kPoKSigCircuitDomain, binding.data(), binding.size());
}
inline bool PoKSigCircuitIdentityApproved(const std::array<uint8_t, 32>&) {
  return false; // Intentionally no approved signature circuit before L5.
}

// Explicit signature operation, deriving every public byte from the retained
// canonical expected request. This is input encoding, not proof acceptance.
static inline bool PoKSigEncodePublicInputs(
    const std::vector<uint8_t>& expected_request, PoKSigPublicInputsV1* output,
    QuietProofSignatureDigestError* error = nullptr) {
  if (!output) {
    if (error) *error = QuietProofSignatureDigestError::kMalformedStatement;
    return false;
  }
  QuietProofSignatureInputsV1 inputs;
  if (!DeriveQuietProofSignatureInputs(expected_request, &inputs, error)) return false;
  PoKSigPublicInputsV1 encoded;
  encoded[0] = p256k1_base.one();
  BitPluckerEncoder<Fp256k1Base, 8> encoder(p256k1_base);
  size_t index = PoKSigParametersV1::kHashOffset;
  for (uint8_t byte : inputs.profile.h) encoded[index++] = encoder.encode(byte);
  for (uint8_t byte : inputs.z) encoded[index++] = encoder.encode(byte);
  *output = std::move(encoded);
  return true;
}
}  // namespace proofs
#endif
