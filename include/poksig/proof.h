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
inline constexpr char kPoKSigTranscriptDomain[] = "QuietProof/signature/transcript/v4";
using PoKSigPublicInputsV1 = std::array<Fp256k1Base::Elt, PoKSigParametersV1::kPublicInputs>;

// Dedicated public proof transport: bytes are a complete QPE1/v4 envelope,
// never a receipt or a PoKCProofV1. Every operation requires explicit allowance.
struct PoKSigProofV1 { std::vector<uint8_t> bytes; };
struct PoKSigOptionsV1 { bool allow_signature_possession = false; };
enum class PoKSigError {
  kNone, kMalformedStatement, kMalformedReceipt, kUnsupported,
  kSignatureModeDisabled, kSignatureModeNotAllowed, kUnapprovedCircuit,
  kInvalidAuthorization, kInvalidProof, kUnsupportedResources, kPrivateReceiptInput
};
inline const char* PoKSigErrorName(PoKSigError error) {
  switch (error) {
    case PoKSigError::kNone: return "none";
    case PoKSigError::kMalformedStatement: return "malformed_statement";
    case PoKSigError::kMalformedReceipt: return "malformed_receipt";
    case PoKSigError::kUnsupported: return "unsupported";
    case PoKSigError::kSignatureModeDisabled: return "signature_mode_disabled";
    case PoKSigError::kSignatureModeNotAllowed: return "signature_mode_not_allowed";
    case PoKSigError::kUnapprovedCircuit: return "unapproved_circuit";
    case PoKSigError::kInvalidAuthorization: return "invalid_authorization";
    case PoKSigError::kInvalidProof: return "invalid_proof";
    case PoKSigError::kUnsupportedResources: return "unsupported_resources";
    case PoKSigError::kPrivateReceiptInput: return "private_receipt_input";
  }
  return "invalid_proof";
}

// L5's qualified complete ECDSA/HASH160 serialization, SECP_ID, 53 public
// inputs. 26519998 serialized bytes; SHA256(C) is
// 07d62ac962dd0f484828c4075bc64fde3575396b28946bdef52931c6f4234d51.
// Qualification uses both CircuitWriter and an independent tagged-hash encoder.
inline const std::array<uint8_t, 32>& PoKSigExpectedCircuitDigest() {
  static constexpr std::array<uint8_t, 32> digest = {
    0x85,0xfc,0x96,0x26,0xe7,0x4e,0x19,0x44,0xe7,0x36,0x23,0x7c,0x5f,0x71,0x22,0x0f,
    0x98,0x2b,0x05,0xa3,0xf7,0x86,0xc4,0x91,0xcf,0x35,0xef,0x2e,0x56,0x54,0x7d,0x32};
  return digest;
}

// Identity computation is not approval. Only the exact locally pinned digest
// below is approved; a nonzero caller-supplied digest cannot choose a circuit.
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
inline bool PoKSigCircuitIdentityApproved(const std::array<uint8_t, 32>& digest) {
  return digest == PoKSigExpectedCircuitDigest();
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
