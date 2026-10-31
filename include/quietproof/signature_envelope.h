// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SIGNATURE_ENVELOPE_H_
#define QUIETPROOF_SIGNATURE_ENVELOPE_H_

#include "poksig/proof.h"

namespace proofs {
constexpr size_t kQuietProofSignatureEnvelopeOverheadBytes = 70;
constexpr size_t kQuietProofSignatureMaxProofBytes = size_t{128} * 1024 * 1024;
constexpr size_t kQuietProofSignatureMaxEnvelopeBytes = 134221894;
static_assert(kQuietProofSignatureMaxEnvelopeBytes ==
    kQuietProofSignatureEnvelopeOverheadBytes + kQuietProofMaxStatementBytes +
    kQuietProofSignatureMaxProofBytes);

// Format metadata only: neither an approved identity nor a verified proof.
// No witness, h, z or proof allocation is retained by inspection.
struct QuietProofSignatureEnvelopeMetadataV3 {
  std::vector<uint8_t> request;
  uint64_t proof_created_at = 0; // Local prover start, never signing time.
  uint8_t mode = kQuietProofSignatureMode;
  uint16_t profile = kQuietProofSignatureProfile;
  uint16_t circuit_family = PoKSigParametersV1::kFamily;
  std::array<uint8_t, 32> circuit_digest{};
  uint32_t circuit_version = PoKSigParametersV1::kCircuitVersion;
  uint32_t rate = PoKSigParametersV1::kRate;
  uint32_t queries = PoKSigParametersV1::kQueries;
  uint32_t proof_size = 0;
  size_t proof_offset = 0;
};
enum class QuietProofSignatureEnvelopeError {
  kNone, kMalformedStatement, kUnsupported, kSignatureModeDisabled,
  kUnapprovedCircuit, kInvalidProof, kPrivateReceiptInput
};
inline const char* QuietProofSignatureEnvelopeErrorName(QuietProofSignatureEnvelopeError error) {
  switch (error) {
    case QuietProofSignatureEnvelopeError::kNone: return "none";
    case QuietProofSignatureEnvelopeError::kMalformedStatement: return "malformed_statement";
    case QuietProofSignatureEnvelopeError::kUnsupported: return "unsupported";
    case QuietProofSignatureEnvelopeError::kSignatureModeDisabled: return "signature_mode_disabled";
    case QuietProofSignatureEnvelopeError::kUnapprovedCircuit: return "unapproved_circuit";
    case QuietProofSignatureEnvelopeError::kInvalidProof: return "invalid_proof";
    case QuietProofSignatureEnvelopeError::kPrivateReceiptInput: return "private_receipt_input";
  }
  return "malformed_statement";
}
inline bool QuietProofIsPrivateReceiptInput(const uint8_t* bytes, size_t size) {
  return bytes && size >= 4 && std::memcmp(bytes, "QPA1", 4) == 0;
}

namespace quietproof_detail {
inline uint64_t SignatureEnvelopeNumber(const uint8_t* bytes, size_t size) {
  uint64_t value = 0;
  for (size_t i = 0; i < size; ++i) value = (value << 8) | bytes[i];
  return value;
}
inline bool SignatureEnvelopeTupleKnown(const QuietProofSignatureEnvelopeMetadataV3& m) {
  return m.mode <= 1 && m.profile == kQuietProofSignatureProfile &&
      m.circuit_family == PoKSigParametersV1::kFamily &&
      m.circuit_version == PoKSigParametersV1::kCircuitVersion &&
      m.rate == PoKSigParametersV1::kRate && m.queries == PoKSigParametersV1::kQueries;
}
inline bool SignatureEnvelopeTimeValid(const QuietProofSignatureStatementV3& s, uint64_t created) {
  return created != 0 && created >= s.not_before && created < s.expires_at;
}
} // namespace quietproof_detail

// Bounded format inspection only. Caller supplies a readable byte span; lengths
// are checked by subtraction before any nested allocation. The proof is never
// copied or parsed. Inspection grants neither capability nor mode allowance.
inline bool InspectQuietProofSignatureEnvelope(
    const uint8_t* bytes, size_t size, QuietProofSignatureEnvelopeMetadataV3* output,
    QuietProofSignatureEnvelopeError* error = nullptr) {
  const auto fail = [error](QuietProofSignatureEnvelopeError code) {
    if (error) *error = code;
    return false;
  };
  if (QuietProofIsPrivateReceiptInput(bytes, size))
    return fail(QuietProofSignatureEnvelopeError::kPrivateReceiptInput);
  if (!output || !bytes || size < kQuietProofSignatureEnvelopeOverheadBytes ||
      size > kQuietProofSignatureMaxEnvelopeBytes || std::memcmp(bytes, "QPE1", 4))
    return fail(QuietProofSignatureEnvelopeError::kMalformedStatement);
  const uint8_t version = bytes[4];
  const size_t statement_size = quietproof_detail::SignatureEnvelopeNumber(bytes + 5, 4);
  if (!statement_size || statement_size > kQuietProofMaxStatementBytes ||
      statement_size > size - kQuietProofSignatureEnvelopeOverheadBytes)
    return fail(QuietProofSignatureEnvelopeError::kMalformedStatement);
  const size_t tail = 9 + statement_size; // Safe after the whole-size subtraction.
  QuietProofSignatureEnvelopeMetadataV3 metadata;
  metadata.proof_created_at = quietproof_detail::SignatureEnvelopeNumber(bytes + tail, 8);
  metadata.mode = bytes[tail + 8];
  metadata.profile = quietproof_detail::SignatureEnvelopeNumber(bytes + tail + 9, 2);
  metadata.circuit_family = quietproof_detail::SignatureEnvelopeNumber(bytes + tail + 11, 2);
  std::copy_n(bytes + tail + 13, 32, metadata.circuit_digest.begin());
  metadata.circuit_version = quietproof_detail::SignatureEnvelopeNumber(bytes + tail + 45, 4);
  metadata.rate = quietproof_detail::SignatureEnvelopeNumber(bytes + tail + 49, 4);
  metadata.queries = quietproof_detail::SignatureEnvelopeNumber(bytes + tail + 53, 4);
  metadata.proof_size = quietproof_detail::SignatureEnvelopeNumber(bytes + tail + 57, 4);
  metadata.proof_offset = tail + 61;
  if (!metadata.proof_size || metadata.proof_size > kQuietProofSignatureMaxProofBytes ||
      metadata.proof_size != size - metadata.proof_offset)
    return fail(QuietProofSignatureEnvelopeError::kMalformedStatement);
  // All safe framing precedes ID dispatch, which precedes known incompatibility.
  if ((version != 1 && version != 2 && version != 3) ||
      !quietproof_detail::SignatureEnvelopeTupleKnown(metadata))
    return fail(QuietProofSignatureEnvelopeError::kUnsupported);
  metadata.request.assign(bytes + 9, bytes + tail);
  QuietProofSignatureStatementV3 statement;
  QuietProofDecodeError nested = QuietProofDecodeError::kMalformed;
  if (statement_size >= 5 && metadata.request[4] != 3) {
    QuietProofStatementV1 old;
    DecodeQuietProofStatement(metadata.request, &old, &nested);
    return fail(nested == QuietProofDecodeError::kUnsupported ?
        QuietProofSignatureEnvelopeError::kUnsupported : QuietProofSignatureEnvelopeError::kMalformedStatement);
  }
  if (!DecodeQuietProofSignatureStatement(metadata.request, &statement, &nested))
    return fail(nested == QuietProofDecodeError::kUnsupported ?
        QuietProofSignatureEnvelopeError::kUnsupported : QuietProofSignatureEnvelopeError::kMalformedStatement);
  if (version != 3 || metadata.mode != kQuietProofSignatureMode ||
      metadata.mode != metadata.request[6] || metadata.profile !=
          quietproof_detail::SignatureEnvelopeNumber(metadata.request.data() + 7, 2) ||
      QuietProofAllZero(metadata.circuit_digest) ||
      !quietproof_detail::SignatureEnvelopeTimeValid(statement, metadata.proof_created_at))
    return fail(QuietProofSignatureEnvelopeError::kMalformedStatement);
  *output = std::move(metadata);
  if (error) *error = QuietProofSignatureEnvelopeError::kNone;
  return true;
}
inline bool InspectQuietProofSignatureEnvelope(
    const std::vector<uint8_t>& bytes, QuietProofSignatureEnvelopeMetadataV3* output,
    QuietProofSignatureEnvelopeError* error = nullptr) {
  return InspectQuietProofSignatureEnvelope(bytes.data(), bytes.size(), output, error);
}

// Transport codec only, including for unapproved nonzero identities. This does
// not select a mode or offer support/acceptance. The acceptance gate is below.
inline bool EncodeQuietProofSignatureEnvelope(
    const QuietProofSignatureEnvelopeMetadataV3& metadata, const std::vector<uint8_t>& proof,
    std::vector<uint8_t>* output) {
  if (!output || metadata.request.empty() || metadata.request.size() > kQuietProofMaxStatementBytes ||
      proof.empty() || proof.size() > kQuietProofSignatureMaxProofBytes) return false;
  QuietProofSignatureStatementV3 statement;
  if (!quietproof_detail::SignatureEnvelopeTupleKnown(metadata) ||
      metadata.mode != kQuietProofSignatureMode || QuietProofAllZero(metadata.circuit_digest) ||
      !DecodeQuietProofSignatureStatement(metadata.request, &statement) ||
      !quietproof_detail::SignatureEnvelopeTimeValid(statement, metadata.proof_created_at)) return false;
  std::vector<uint8_t> bytes{'Q','P','E','1',3};
  bytes.reserve(kQuietProofSignatureEnvelopeOverheadBytes + metadata.request.size() + proof.size());
  QuietProofAppendU32(&bytes, static_cast<uint32_t>(metadata.request.size()));
  bytes.insert(bytes.end(), metadata.request.begin(), metadata.request.end());
  QuietProofAppendU64(&bytes, metadata.proof_created_at);
  bytes.push_back(metadata.mode); QuietProofAppendU16(&bytes, metadata.profile);
  QuietProofAppendU16(&bytes, metadata.circuit_family);
  bytes.insert(bytes.end(), metadata.circuit_digest.begin(), metadata.circuit_digest.end());
  QuietProofAppendU32(&bytes, metadata.circuit_version); QuietProofAppendU32(&bytes, metadata.rate);
  QuietProofAppendU32(&bytes, metadata.queries); QuietProofAppendU32(&bytes, static_cast<uint32_t>(proof.size()));
  bytes.insert(bytes.end(), proof.begin(), proof.end());
  *output = std::move(bytes);
  return true;
}

// Capability-dependent operations stay TU-local. Support is metadata-only;
// the dedicated verifier additionally requires allowance and expected request.
static inline bool QuietProofSignatureEnvelopeSupported(
    const std::vector<uint8_t>& bytes, QuietProofSignatureEnvelopeError* error = nullptr) {
  QuietProofSignatureEnvelopeMetadataV3 metadata;
  if (!InspectQuietProofSignatureEnvelope(bytes, &metadata, error)) return false;
#if !defined(QUIETPROOF_HAS_SIGNATURE_MODE) || !QUIETPROOF_HAS_SIGNATURE_MODE
  if (error) *error = QuietProofSignatureEnvelopeError::kSignatureModeDisabled;
  return false;
#endif
  if (!PoKSigCircuitIdentityApproved(metadata.circuit_digest)) {
    if (error) *error = QuietProofSignatureEnvelopeError::kUnapprovedCircuit;
    return false;
  }
  if (error) *error = QuietProofSignatureEnvelopeError::kNone;
  return true;
}

namespace quietproof_detail {
// Internal layout codec, NOT a production transcript/acceptance entry point.
// Test-only synthetic I can exercise its bytes without creating a trust anchor.
// Even here d/h/z are derived from the expected request, never caller inputs.
static inline bool SignatureTranscriptBinding(
    const std::vector<uint8_t>& expected_request,
    const QuietProofSignatureEnvelopeMetadataV3& metadata, uint64_t now,
    std::array<uint8_t, 146>* output, QuietProofSignatureEnvelopeError* error = nullptr) {
  const auto fail = [error](QuietProofSignatureEnvelopeError code) {
    if (error) *error = code;
    return false;
  };
  QuietProofSignatureStatementV3 statement;
  QuietProofDecodeError nested;
  if (!output) return fail(QuietProofSignatureEnvelopeError::kMalformedStatement);
  if (!DecodeQuietProofSignatureStatement(expected_request, &statement, &nested))
    return fail(nested == QuietProofDecodeError::kUnsupported ?
        QuietProofSignatureEnvelopeError::kUnsupported : QuietProofSignatureEnvelopeError::kMalformedStatement);
  if (metadata.request != expected_request || metadata.proof_created_at > now)
    return fail(QuietProofSignatureEnvelopeError::kInvalidProof);
  if (!SignatureEnvelopeTupleKnown(metadata)) return fail(QuietProofSignatureEnvelopeError::kUnsupported);
  if (metadata.mode != kQuietProofSignatureMode || QuietProofAllZero(metadata.circuit_digest) ||
      !SignatureEnvelopeTimeValid(statement, metadata.proof_created_at))
    return fail(QuietProofSignatureEnvelopeError::kMalformedStatement);
  QuietProofSignatureInputsV1 inputs;
  QuietProofSignatureDigestError derived;
  if (!DeriveQuietProofSignatureInputs(expected_request, &inputs, &derived))
    return fail(derived == QuietProofSignatureDigestError::kSignatureModeDisabled ?
        QuietProofSignatureEnvelopeError::kSignatureModeDisabled : QuietProofSignatureEnvelopeError::kMalformedStatement);
  std::vector<uint8_t> binding{'Q','P','E','1',3,metadata.mode};
  binding.reserve(146);
  QuietProofAppendU16(&binding, metadata.profile); QuietProofAppendU16(&binding, metadata.circuit_family);
  binding.insert(binding.end(), inputs.profile.statement_digest.begin(), inputs.profile.statement_digest.end());
  binding.insert(binding.end(), inputs.profile.h.begin(), inputs.profile.h.end());
  binding.insert(binding.end(), inputs.z.begin(), inputs.z.end());
  binding.insert(binding.end(), metadata.circuit_digest.begin(), metadata.circuit_digest.end());
  QuietProofAppendU32(&binding, metadata.circuit_version); QuietProofAppendU32(&binding, metadata.rate);
  QuietProofAppendU32(&binding, metadata.queries); QuietProofAppendU64(&binding, metadata.proof_created_at);
  std::copy(binding.begin(), binding.end(), output->begin());
  if (error) *error = QuietProofSignatureEnvelopeError::kNone;
  return true;
}
} // namespace quietproof_detail

// Explicit signature transcript API. Approval is checked before hashing or
// proof parsing. Caller cannot supply an approved digest or derived h/z.
static inline bool PoKSigTranscriptSeed(
    const std::vector<uint8_t>& expected_request, const std::vector<uint8_t>& bytes,
    uint64_t now, std::array<uint8_t, 32>* output,
    QuietProofSignatureEnvelopeError* error = nullptr) {
  QuietProofSignatureEnvelopeMetadataV3 metadata;
  if (!InspectQuietProofSignatureEnvelope(bytes, &metadata, error)) return false;
  QuietProofSignatureStatementV3 expected;
  QuietProofDecodeError nested;
  if (!DecodeQuietProofSignatureStatement(expected_request, &expected, &nested)) {
    if (error) *error = nested == QuietProofDecodeError::kUnsupported ?
        QuietProofSignatureEnvelopeError::kUnsupported : QuietProofSignatureEnvelopeError::kMalformedStatement;
    return false;
  }
  if (!QuietProofSignatureEnvelopeSupported(bytes, error)) return false;
  std::array<uint8_t, 146> binding;
  if (!output) {
    if (error) *error = QuietProofSignatureEnvelopeError::kMalformedStatement;
    return false;
  }
  if (!quietproof_detail::SignatureTranscriptBinding(expected_request, metadata, now, &binding, error))
    return false;
  *output = QuietProofTaggedHash(kPoKSigTranscriptDomain, binding.data(), binding.size());
  return true;
}
} // namespace proofs
#endif
