// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#ifndef PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_ENVELOPE_H_
#define PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_ENVELOPE_H_

#include <functional>
#include <limits>
#include <sstream>
#include "pokc/proof.h"
#include "quietproof/statement.h"

namespace proofs {
// The maximum supported two-key relation measures about 88 MiB. Keep a fixed
// 128 MiB parsing ceiling: it admits the bounded v1 circuit family with
// headroom while retaining a finite allocation limit at the wire boundary.
constexpr size_t kQuietProofMaxProofBytes = size_t{128} * 1024 * 1024;
constexpr size_t kQuietProofEnvelopeOverheadBytes = 5 + 4 + 32 + 4 + 4 + 4 + 4;
constexpr size_t kQuietProofMaxEnvelopeBytes =
    kQuietProofEnvelopeOverheadBytes + 8 + kQuietProofMaxStatementBytes +
    kQuietProofMaxProofBytes;
// The type retains its public API name; envelope_version selects the wire format.
struct QuietProofEnvelopeV1 {
  QuietProofStatementV1 statement;
  PoKCProofV1 proof;
  uint8_t envelope_version = 1;
  uint64_t proof_created_at = 0;  // Unix seconds; absent in legacy envelopes.
};

inline bool QuietProofEnvelopeTimeValid(const QuietProofEnvelopeV1& envelope) {
  if (envelope.envelope_version == 1)
    return envelope.proof_created_at == 0 && envelope.statement.statement_version == 1;
  return envelope.envelope_version == 2 && envelope.proof_created_at != 0 &&
         envelope.proof_created_at >= envelope.statement.not_before &&
         envelope.proof_created_at < envelope.statement.expires_at;
}

inline bool EncodeQuietProofEnvelope(const QuietProofEnvelopeV1& envelope, std::vector<uint8_t>* out) {
  std::vector<uint8_t> statement; if (!out || !QuietProofEnvelopeTimeValid(envelope) || !EncodeQuietProofStatement(envelope.statement, &statement) || statement.size() > std::numeric_limits<uint32_t>::max() || envelope.proof.bytes.empty() || envelope.proof.bytes.size() > kQuietProofMaxProofBytes || QuietProofAllZero(envelope.proof.circuit_digest) || envelope.proof.circuit_version != PoKCParametersV1::kCircuitVersion || envelope.proof.rate != PoKCParametersV1::kRate || envelope.proof.queries != PoKCParametersV1::kQueries) return false;
  out->clear(); out->insert(out->end(), {'Q','P','E','1',envelope.envelope_version}); QuietProofAppendU32(out, static_cast<uint32_t>(statement.size())); out->insert(out->end(), statement.begin(), statement.end()); if (envelope.envelope_version == 2) QuietProofAppendU64(out, envelope.proof_created_at); out->insert(out->end(), envelope.proof.circuit_digest.begin(), envelope.proof.circuit_digest.end()); QuietProofAppendU32(out, envelope.proof.circuit_version); QuietProofAppendU32(out, static_cast<uint32_t>(envelope.proof.rate)); QuietProofAppendU32(out, static_cast<uint32_t>(envelope.proof.queries)); QuietProofAppendU32(out, static_cast<uint32_t>(envelope.proof.bytes.size())); out->insert(out->end(), envelope.proof.bytes.begin(), envelope.proof.bytes.end()); return true;
}
inline bool DecodeQuietProofEnvelope(
    const std::vector<uint8_t>& bytes, QuietProofEnvelopeV1* envelope,
    QuietProofDecodeError* error = nullptr) {
  if (error != nullptr) *error = QuietProofDecodeError::kMalformed;
  if (!envelope || bytes.size() < kQuietProofEnvelopeOverheadBytes ||
      bytes.size() > kQuietProofMaxEnvelopeBytes) return false;
  QuietProofReader r(bytes);
  uint8_t magic[4], version;
  uint32_t n;
  if (!r.bytes(magic, 4) || std::memcmp(magic, "QPE1", 4) != 0) return false;
  if (!r.u8(&version) || (version != 1 && version != 2)) {
    if (error != nullptr) *error = QuietProofDecodeError::kUnsupported;
    return false;
  }
  if (!r.u32(&n) || n == 0 || n > kQuietProofMaxStatementBytes || n > r.left())
    return false;
  std::vector<uint8_t> statement(n);
  if (!r.bytes(statement.data(), n)) return false;
  QuietProofEnvelopeV1 out;
  QuietProofDecodeError statement_error = QuietProofDecodeError::kMalformed;
  if (!DecodeQuietProofStatement(statement, &out.statement, &statement_error)) {
    if (error != nullptr) *error = statement_error;
    return false;
  }
  out.envelope_version = version;
  if (version == 2 && !r.u64(&out.proof_created_at)) return false;
  if (!QuietProofEnvelopeTimeValid(out)) return false;
  if (!r.bytes(out.proof.circuit_digest.data(), 32) ||
      !r.u32(&out.proof.circuit_version)) return false;
  if (QuietProofAllZero(out.proof.circuit_digest)) return false;
  uint32_t rate, queries, proof_size; if (!r.u32(&rate) || !r.u32(&queries) || !r.u32(&proof_size) ||
      proof_size == 0 || proof_size > kQuietProofMaxProofBytes || proof_size != r.left()) return false;
  if (out.proof.circuit_version != PoKCParametersV1::kCircuitVersion ||
      rate != PoKCParametersV1::kRate ||
      queries != PoKCParametersV1::kQueries) {
    if (error != nullptr) *error = QuietProofDecodeError::kUnsupported;
    return false;
  }
  out.proof.rate = rate;
  out.proof.queries = queries;
  out.proof.bytes.resize(proof_size);
  if (!r.bytes(out.proof.bytes.data(), proof_size)) return false;
  *envelope = std::move(out);
  if (error != nullptr) *error = QuietProofDecodeError::kNone;
  return true;
}

// Inspection is deliberately a presentation format. Verification always uses
// EncodeQuietProofStatement/EncodeQuietProofEnvelope, never this JSON.
inline std::string QuietProofInspectJson(const QuietProofEnvelopeV1& envelope) {
  std::vector<uint8_t> statement; if (!EncodeQuietProofStatement(envelope.statement, &statement)) return "";
  static const char hex[] = "0123456789abcdef";
  auto hexify = [&](const uint8_t* p, size_t n) { std::string out; out.reserve(n * 2); for (size_t i = 0; i < n; ++i) { out.push_back(hex[p[i] >> 4]); out.push_back(hex[p[i] & 15]); } return out; };
  auto json = [](const std::string& value) { std::string out; for (unsigned char c : value) { if (c == '"' || c == '\\') out.push_back('\\'); if (c >= 0x20) out.push_back(static_cast<char>(c)); } return out; };
  std::ostringstream out; out << "{\"format\":\"quietproof-proof-v" << unsigned(envelope.envelope_version) << "\",\"network\":\"" << QuietProofNetworkName(envelope.statement.network) << "\""
      << ",\"statement_version\":" << unsigned(envelope.statement.statement_version)
      << ",\"request_created_at\":" << envelope.statement.not_before
      << ",\"not_before\":" << envelope.statement.not_before
      << ",\"expires_at\":" << envelope.statement.expires_at
      << ",\"proof_created_at\":" << (envelope.envelope_version == 2 ? std::to_string(envelope.proof_created_at) : "null")
      << ",\"verifier\":\"" << json(envelope.statement.verifier) << "\",\"purpose\":\"" << json(envelope.statement.purpose)
      << "\",\"statement_bytes\":" << statement.size() << ",\"circuit_digest\":\"" << hexify(envelope.proof.circuit_digest.data(), 32)
      << "\",\"proof_bytes\":" << envelope.proof.bytes.size() << ",\"claims\":" << envelope.statement.claims.size()
      << ",\"script_kinds\":[";
  for (size_t i = 0; i < envelope.statement.claims.size(); ++i) {
    if (i != 0) out << ',';
    out << '\"' << QuietProofScriptKindName(envelope.statement.claims[i].script_kind) << '\"';
  }
  out << "]}";
  return out.str();
}

inline std::array<uint8_t, 32> PoKCTranscriptSeed(const QuietProofStatementV1& statement, const PoKCProofV1& proof) {
  std::array<uint8_t, 32> digest{}; if (!QuietProofStatementDigest(statement, &digest)) return {}; std::vector<uint8_t> binding(digest.begin(), digest.end()); binding.insert(binding.end(), proof.circuit_digest.begin(), proof.circuit_digest.end()); QuietProofAppendU32(&binding, proof.circuit_version); QuietProofAppendU32(&binding, static_cast<uint32_t>(proof.rate)); QuietProofAppendU32(&binding, static_cast<uint32_t>(proof.queries)); return QuietProofTaggedHash("PoKC/transcript/v1", binding.data(), binding.size());
}

// Keep the v1 transcript byte-for-byte stable for existing proofs.
inline std::array<uint8_t, 32> PoKCTranscriptSeed(const QuietProofEnvelopeV1& envelope) {
  if (!QuietProofEnvelopeTimeValid(envelope)) return {};
  const auto legacy = PoKCTranscriptSeed(envelope.statement, envelope.proof);
  if (envelope.envelope_version == 1) return legacy;
  std::vector<uint8_t> binding(legacy.begin(), legacy.end());
  QuietProofAppendU64(&binding, envelope.proof_created_at);
  return QuietProofTaggedHash("PoKC/transcript/v2", binding.data(), binding.size());
}

enum class QuietProofAuthorization : uint8_t { kInvalid, kPendingReplayCheck, kReplayRejected, kPolicyRejected, kAuthorized };
struct QuietProofReplayPolicy { uint64_t now = 0; uint64_t max_lifetime = 0; std::string verifier; std::string purpose; std::function<bool(const std::array<uint8_t, 32>&)> nonce_seen; std::function<bool(const std::array<uint8_t, 32>&)> consume_nonce; };
inline QuietProofAuthorization QuietProofCheckPolicy(const QuietProofStatementV1& statement, const QuietProofReplayPolicy& policy, bool proof_valid) {
  if (!proof_valid || !QuietProofStatementValid(statement) || statement.verifier != policy.verifier || statement.purpose != policy.purpose || policy.now < statement.not_before || policy.now >= statement.expires_at || (policy.max_lifetime && statement.expires_at - statement.not_before > policy.max_lifetime)) return QuietProofAuthorization::kPolicyRejected;
  if (policy.nonce_seen && policy.nonce_seen(statement.nonce)) return QuietProofAuthorization::kReplayRejected;
  return QuietProofAuthorization::kPendingReplayCheck;
}
inline QuietProofAuthorization QuietProofConsumeNonce(const QuietProofStatementV1& statement, const QuietProofReplayPolicy& policy) { return policy.consume_nonce && policy.consume_nonce(statement.nonce) ? QuietProofAuthorization::kAuthorized : QuietProofAuthorization::kReplayRejected; }
}  // namespace proofs
#endif
