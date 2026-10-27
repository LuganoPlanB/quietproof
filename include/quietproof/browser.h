// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_BROWSER_H_
#define QUIETPROOF_BROWSER_H_

#include "quietproof/challenge.h"
#include "quietproof/envelope.h"

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
