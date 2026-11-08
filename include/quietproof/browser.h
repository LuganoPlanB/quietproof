// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_BROWSER_H_
#define QUIETPROOF_BROWSER_H_

#include "quietproof/challenge.h"
#include "quietproof/envelope.h"
#include "quietproof/signature_challenge.h"
#include "quietproof/signature_envelope.h"

namespace proofs {
// This transport is not a new request format. QWC1 carries only user options;
// the result is the existing canonical QPS1 (.qpr) wire format. All integers
// are big endian, strings are u16-length UTF-8, claims are typed v2 records.
constexpr size_t kQuietProofBrowserMaxMessageBytes = 4096;
constexpr size_t kQuietProofBrowserMaxOptionsBytes = 8192;
inline bool DecodeQuietProofBrowserOptions(
    const std::vector<uint8_t>& bytes, QuietProofChallengeOptions* options,
    std::vector<QuietProofClaimV1>* claims) {
  if (!options || !claims || bytes.size() > kQuietProofBrowserMaxOptionsBytes)
    return false;
  QuietProofReader reader(bytes);
  uint8_t magic[4], network;
  QuietProofChallengeOptions out;
  if (!reader.bytes(magic, 4) || std::memcmp(magic, "QWC1", 4) ||
      !reader.u8(&network) || (network != 0 && network != 2) ||
      !reader.u64(&out.lifetime_seconds) ||
      !reader.text(&out.verifier, kQuietProofMaxVerifierBytes) ||
      !reader.text(&out.purpose, kQuietProofMaxPurposeBytes) ||
      !reader.text(&out.message, kQuietProofBrowserMaxMessageBytes)) return false;
  out.network = static_cast<QuietProofNetwork>(network);
  uint16_t count;
  if (!reader.u16(&count) || !count || count > kQuietProofMaxClaims) return false;
  std::vector<QuietProofClaimV1> decoded(count);
  for (auto& claim : decoded) {
    uint8_t kind;
    if (!reader.bytes(claim.txid.data(), claim.txid.size()) ||
        !reader.u32(&claim.vout) || !reader.u64(&claim.amount_sats) ||
        !reader.u8(&kind) ||
        !reader.bytes(claim.program.data(), claim.program.size())) return false;
    claim.script_kind = static_cast<QuietProofScriptKind>(kind);
  }
  if (reader.left()) return false;
  *options = std::move(out);
  *claims = std::move(decoded);
  return true;
}

// QWC3 selects mode, profile ID/version and signing kind explicitly. QWC2
// omitted the procedure and is unsupported; it must not acquire a new default.
inline bool DecodeQuietProofBrowserSignatureOptions(
    const std::vector<uint8_t>& bytes, QuietProofSignatureChallengeOptions* options,
    std::vector<QuietProofClaimV1>* claims) {
  if (!options || bytes.size() < 10 || bytes.size() > kQuietProofBrowserMaxOptionsBytes ||
      std::memcmp(bytes.data(), "QWC3", 4) || bytes[4] != 1 || bytes[8] > 1) return false;
  const auto profile = static_cast<QuietProofSigningProfile>((uint16_t(bytes[5]) << 8) | bytes[6]);
  const auto kind = static_cast<QuietProofScriptKind>(bytes[8]);
  if (!QuietProofSigningProfileCompatible(profile, bytes[7], kind)) return false;
  std::vector<uint8_t> common{'Q','W','C','1'};
  common.insert(common.end(), bytes.begin()+9, bytes.end());
  QuietProofSignatureChallengeOptions out;
  if (!DecodeQuietProofBrowserOptions(common, &out.request, claims)) return false;
  out.signing_kind = kind;
  out.signing_profile = profile;
  *options = std::move(out);
  return true;
}

// Public presentation/selection data, derived solely from the closed library
// table. Recognized formats remain inspectable in disabled builds; the separate
// enabled capability is required for request creation and verification.
inline void QuietProofBrowserProfileCapabilities(std::vector<uint8_t>* output) {
  output->assign({'Q','S','C','1',uint8_t(kQuietProofSigningProfiles.size())});
  const auto text = [output](const char* value) {
    const size_t size = std::strlen(value);
    QuietProofAppendU16(output, size);
    output->insert(output->end(), value, value + size);
  };
  for (const auto& descriptor : kQuietProofSigningProfiles) {
    QuietProofAppendU16(output, static_cast<uint16_t>(descriptor.id));
    output->push_back(descriptor.version);
    uint8_t compatible = 0, defaults = 0;
    for (uint8_t id = 0; id < 2; ++id) {
      const auto kind = static_cast<QuietProofScriptKind>(id);
      if (QuietProofSigningProfileCompatible(descriptor.id, descriptor.version, kind)) compatible |= 1u << id;
      QuietProofSigningProfile selected;
      if (QuietProofDefaultSigningProfile(kind, &selected) && selected == descriptor.id) defaults |= 1u << id;
    }
    output->push_back(compatible); output->push_back(defaults);
    text(descriptor.name); text(descriptor.label);
    for (uint8_t id = 0; id < 2; ++id) {
      const auto kind = static_cast<QuietProofScriptKind>(id);
      text(QuietProofSigningProfileCompatible(descriptor.id, descriptor.version, kind) ?
          QuietProofSigningInstructions(descriptor.id, kind) : "");
    }
  }
}

// QWI1: envelope version u8 (0 for request), proof-created-at u64 (0 if
// absent), circuit digest[32], circuit-version/rate/queries/proof-size u32,
// followed by the canonical QPS1 request. Inspection never verifies a proof.
inline bool QuietProofBrowserMetadata(const QuietProofEnvelopeV1& envelope,
                                     bool proof, std::vector<uint8_t>* output) {
  if (!output) return false;
  std::vector<uint8_t> statement;
  if (!EncodeQuietProofStatement(envelope.statement, &statement)) return false;
  output->assign({'Q', 'W', 'I', '1', uint8_t(proof ? envelope.envelope_version : 0)});
  QuietProofAppendU64(output, proof ? envelope.proof_created_at : 0);
  if (proof) output->insert(output->end(), envelope.proof.circuit_digest.begin(),
                           envelope.proof.circuit_digest.end());
  else output->insert(output->end(), 32, 0);
  QuietProofAppendU32(output, proof ? envelope.proof.circuit_version : 0);
  QuietProofAppendU32(output, proof ? envelope.proof.rate : 0);
  QuietProofAppendU32(output, proof ? envelope.proof.queries : 0);
  QuietProofAppendU32(output, proof ? envelope.proof.bytes.size() : 0);
  output->insert(output->end(), statement.begin(), statement.end());
  return true;
}
inline bool QuietProofBrowserInspect(const std::vector<uint8_t>& bytes,
                                    bool proof, std::vector<uint8_t>* output) {
  if (!output) return false;
  if (bytes.size() >= 5 && bytes[4] == kQuietProofSignatureStatementVersion) {
    QuietProofSignatureEnvelopeMetadataV4 metadata;
    if (proof) {
      if (!InspectQuietProofSignatureEnvelope(bytes, &metadata)) return false;
    } else {
      QuietProofSignatureStatementV4 statement;
      if (!DecodeQuietProofSignatureStatement(bytes, &statement)) return false;
      metadata.request = bytes;
    }
    // QWI1 retains its existing header; the canonical v4 request carries the
    // explicit mode/profile/signing kind. Inspection grants no capability.
    output->assign({'Q','W','I','1',uint8_t(proof ? kQuietProofSignatureStatementVersion : 0)});
    QuietProofAppendU64(output, proof ? metadata.proof_created_at : 0);
    if (proof) output->insert(output->end(), metadata.circuit_digest.begin(), metadata.circuit_digest.end());
    else output->insert(output->end(), 32, 0);
    QuietProofAppendU32(output, proof ? metadata.circuit_version : 0);
    QuietProofAppendU32(output, proof ? metadata.rate : 0);
    QuietProofAppendU32(output, proof ? metadata.queries : 0);
    QuietProofAppendU32(output, proof ? metadata.proof_size : 0);
    output->insert(output->end(), metadata.request.begin(), metadata.request.end());
    return true;
  }
  QuietProofEnvelopeV1 envelope;
  if (proof) {
    if (!DecodeQuietProofEnvelope(bytes, &envelope)) return false;
  } else if (!DecodeQuietProofStatement(bytes, &envelope.statement)) {
    return false;
  }
  return QuietProofBrowserMetadata(envelope, proof, output);
}
}  // namespace proofs
#endif
