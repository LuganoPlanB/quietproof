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

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "quietproof/envelope.h"
#include "quietproof/chain_state.h"

namespace proofs {
namespace {

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

QuietProofStatementV1 Statement() {
  QuietProofStatementV1 statement;
  statement.network = QuietProofNetwork::kSignet;
  statement.verifier = "merchant.example";
  statement.purpose = "proof-of-funds";
  statement.not_before = 100;
  statement.expires_at = 200;
  for (size_t index = 0; index < 32; ++index) {
    statement.nonce[index] = static_cast<uint8_t>(index + 1);
    statement.bip322_message_hash[index] = static_cast<uint8_t>(32 - index);
  }
  QuietProofClaimV1 first;
  first.txid[0] = 1;
  first.vout = 2;
  first.amount_sats = 42;
  first.program[0] = 9;
  QuietProofClaimV1 second;
  second.txid[0] = 2;
  second.vout = 1;
  second.amount_sats = 99;
  second.program = first.program;
  statement.claims = {first, second};
  return statement;
}

void TestNetworks() {
  const std::pair<const char*, QuietProofNetwork> networks[] = {
      {"mainnet", QuietProofNetwork::kMainnet},
      {"testnet", QuietProofNetwork::kTestnet3},
      {"testnet3", QuietProofNetwork::kTestnet3},
      {"testnet4", QuietProofNetwork::kTestnet4},
      {"signet", QuietProofNetwork::kSignet},
      {"regtest", QuietProofNetwork::kRegtest},
  };
  for (const auto& entry : networks) {
    QuietProofNetwork parsed = QuietProofNetwork::kMainnet;
    Require(QuietProofParseNetwork(entry.first, &parsed) && parsed == entry.second,
            "network name rejected");
    auto statement = Statement();
    statement.network = entry.second;
    std::vector<uint8_t> encoded;
    QuietProofStatementV1 decoded;
    Require(EncodeQuietProofStatement(statement, &encoded) &&
                DecodeQuietProofStatement(encoded, &decoded) &&
                decoded.network == entry.second,
            "network wire round trip failed");
  }
  QuietProofNetwork ignored = QuietProofNetwork::kMainnet;
  Require(!QuietProofParseNetwork("testnet5", &ignored),
          "unknown future network accepted");
}

void TestStatementRoundTrip() {
  const auto statement = Statement();
  std::vector<uint8_t> encoded;
  Require(EncodeQuietProofStatement(statement, &encoded), "encode statement");
  Require(encoded.size() <= kQuietProofMaxStatementBytes, "statement exceeds cap");
  QuietProofStatementV1 decoded;
  Require(DecodeQuietProofStatement(encoded, &decoded), "decode statement");
  std::vector<uint8_t> again;
  Require(EncodeQuietProofStatement(decoded, &again) && encoded == again,
          "statement is not canonical");
  const std::array<uint8_t, 32> expected_digest = {
      0x76, 0x46, 0xf5, 0xcf, 0x56, 0xdc, 0x57, 0xa8,
      0x33, 0x69, 0xc4, 0xc8, 0xdf, 0x3f, 0xc4, 0x93,
      0x65, 0x17, 0x39, 0xb5, 0x0c, 0xad, 0x19, 0x44,
      0xdd, 0x0c, 0x9e, 0xc3, 0xcd, 0x7d, 0xa5, 0x76};
  std::array<uint8_t, 32> digest{};
  Require(QuietProofStatementDigest(statement, &digest) &&
              digest == expected_digest,
          "statement digest differs from independent vector");
  for (size_t size = 0; size < encoded.size(); ++size) {
    const auto end = encoded.begin() +
                     static_cast<std::vector<uint8_t>::difference_type>(size);
    const std::vector<uint8_t> truncated(encoded.begin(), end);
    Require(!DecodeQuietProofStatement(truncated, &decoded),
            "truncated statement accepted");
  }
  auto trailing = encoded;
  trailing.push_back(0);
  Require(!DecodeQuietProofStatement(trailing, &decoded),
          "trailing statement byte accepted");

  // A formerly supported second key is rejected on both sides of the codec.
  auto second_key = statement;
  second_key.claims[1].program[0] ^= 1;
  Require(!QuietProofStatementValid(second_key) &&
              !EncodeQuietProofStatement(second_key, &again),
          "second key hash accepted by encoder");
  auto old_two_key_wire = encoded;
  old_two_key_wire[old_two_key_wire.size() - 20] ^= 1;
  Require(!DecodeQuietProofStatement(old_two_key_wire, &decoded),
          "second key hash accepted by decoder");

  auto snapshot = statement;
  snapshot.has_snapshot = true;
  snapshot.snapshot[0] = 7;
  snapshot.snapshot_height = 123;
  Require(EncodeQuietProofStatement(snapshot, &encoded) &&
              DecodeQuietProofStatement(encoded, &decoded) &&
              decoded.snapshot_height == 123,
          "snapshot hash/height round trip failed");
}

std::string Hex(const uint8_t* bytes, size_t size) {
  static const char alphabet[] = "0123456789abcdef";
  std::string result;
  for (size_t i = 0; i < size; ++i) {
    result += alphabet[bytes[i] >> 4];
    result += alphabet[bytes[i] & 15];
  }
  return result;
}

void TestScriptClassification() {
  auto claim = Statement().claims[0];
  std::vector<uint8_t> p2wpkh{0x00, 0x14}, p2pkh{0x76, 0xa9, 0x14};
  for (auto* script : {&p2wpkh, &p2pkh})
    script->insert(script->end(), claim.program.begin(), claim.program.end());
  p2pkh.insert(p2pkh.end(), {0x88, 0xac});
  for (const auto& script : {p2wpkh, p2pkh}) {
    const auto expected = script.size() == 22 ? QuietProofScriptKind::kP2wpkh :
                                              QuietProofScriptKind::kP2pkh;
    QuietProofScriptKind kind = static_cast<QuietProofScriptKind>(255);
    std::array<uint8_t, 20> hash{};
    Require(QuietProofClassifyScript(script, &kind, &hash) &&
                kind == expected && hash == claim.program,
            "canonical script classification failed");
    claim.script_kind = expected;
    Require(QuietProofMatchesScript(claim, script), "canonical script not matched");
    auto reject = [&](const std::vector<uint8_t>& invalid) {
      kind = static_cast<QuietProofScriptKind>(255);
      hash.fill(0xaa);
      const auto sentinel = hash;
      Require(!QuietProofClassifyScript(invalid, &kind, &hash) &&
                  kind == static_cast<QuietProofScriptKind>(255) && hash == sentinel &&
                  !QuietProofMatchesScript(claim, invalid),
              "noncanonical script classified, matched, or changed outputs");
    };
    for (size_t length = 0; length < script.size(); ++length)
      reject(std::vector<uint8_t>(script.begin(), script.begin() + length));
    auto invalid = script;
    invalid.push_back(0);
    reject(invalid);
    for (size_t i = 0; i < script.size(); ++i) {
      if (i >= (expected == QuietProofScriptKind::kP2wpkh ? 2 : 3) &&
          i < (expected == QuietProofScriptKind::kP2wpkh ? 22 : 23)) continue;
      invalid = script;
      invalid[i] ^= 1;
      reject(invalid);
    }
    // PUSHDATA1 cannot substitute for the direct 20-byte push.
    invalid = script;
    invalid.insert(invalid.begin() + (expected == QuietProofScriptKind::kP2wpkh ? 1 : 2), 0x4c);
    reject(invalid);
    Require(!QuietProofClassifyScript(script, nullptr, &hash) &&
                !QuietProofClassifyScript(script, &kind, nullptr),
            "null classifier output accepted");
  }
  std::vector<std::vector<uint8_t>> unsupported;
  std::vector<uint8_t> p2sh{0xa9, 0x14};
  p2sh.insert(p2sh.end(), claim.program.begin(), claim.program.end());
  p2sh.push_back(0x87);
  unsupported.push_back(p2sh);
  for (uint8_t version : {uint8_t{0}, uint8_t{0x51}}) {
    std::vector<uint8_t> script{version, 0x20};
    script.resize(34, 1);  // P2WSH or P2TR.
    unsupported.push_back(script);
  }
  for (const auto& script : unsupported) {
    QuietProofScriptKind kind;
    std::array<uint8_t, 20> hash{};
    Require(!QuietProofClassifyScript(script, &kind, &hash), "unsupported script accepted");
  }
  claim.script_kind = static_cast<QuietProofScriptKind>(255);
  Require(!QuietProofMatchesScript(claim, p2wpkh) &&
              !QuietProofMatchesScript(claim, p2pkh), "unknown claim kind matched");
  claim.script_kind = QuietProofScriptKind::kP2pkh;
  Require(!QuietProofIsP2wpkh(claim, p2pkh) &&
              !QuietProofIsP2wpkh(claim, p2wpkh), "P2WPKH helper broadened");
}

void TestTypedStatements() {
  auto statement = Statement();
  statement.statement_version = 2;
  statement.claims[1].script_kind = QuietProofScriptKind::kP2pkh;
  // Independent Python struct.pack big-endian encoding and hashlib tagged hash.
  const std::string expected_wire =
      "51505331020200106d65726368616e742e6578616d706c65000e70726f6f662d6f66"
      "2d66756e64730102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
      "1d1e1f20201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403"
      "0201000000000000006400000000000000c800000002010000000000000000000000"
      "000000000000000000000000000000000000000000000002000000000000002a0009"
      "00000000000000000000000000000000000000020000000000000000000000000000"
      "00000000000000000000000000000000000000000100000000000000630109000000"
      "00000000000000000000000000000000";
  std::vector<uint8_t> bytes, again;
  std::array<uint8_t, 32> digest{};
  Require(EncodeQuietProofStatement(statement, &bytes) &&
              Hex(bytes.data(), bytes.size()) == expected_wire,
          "typed independent wire vector changed");
  Require(QuietProofStatementDigest(statement, &digest) &&
              Hex(digest.data(), digest.size()) ==
                  "7efeed7e864ed7f55d7ea7f07544bf67ef8c7d10f791740908917981f4b45ef0",
          "typed independent digest vector changed");
  QuietProofStatementV1 decoded;
  Require(DecodeQuietProofStatement(bytes, &decoded) &&
              decoded.statement_version == 2 &&
              decoded.claims[1].script_kind == QuietProofScriptKind::kP2pkh &&
              EncodeQuietProofStatement(decoded, &again) && again == bytes,
          "mixed typed round trip failed");
  auto invalid = statement;
  invalid.statement_version = 1;
  Require(!EncodeQuietProofStatement(invalid, &again), "typed claim downgraded");
  invalid = statement;
  invalid.claims[1] = invalid.claims[0];
  invalid.claims[1].script_kind = QuietProofScriptKind::kP2pkh;
  Require(!EncodeQuietProofStatement(invalid, &again), "cross-kind duplicate accepted");
  invalid = statement;
  invalid.claims[0].script_kind = static_cast<QuietProofScriptKind>(2);
  Require(!EncodeQuietProofStatement(invalid, &again), "unknown in-memory kind accepted");
  auto malformed = bytes;
  malformed[4] = 3;
  QuietProofDecodeError error;
  Require(!DecodeQuietProofStatement(malformed, &decoded, &error) &&
              error == QuietProofDecodeError::kUnsupported, "unknown version category");
  malformed = bytes;
  // First kind follows the first 44-byte outpoint/amount tuple.
  const size_t first_kind = bytes.size() - 2 * 65 + 44;
  malformed[first_kind] = 2;
  Require(!DecodeQuietProofStatement(malformed, &decoded, &error) &&
              error == QuietProofDecodeError::kUnsupported, "unknown kind category");
  for (size_t size = 0; size < bytes.size(); ++size) {
    malformed.assign(bytes.begin(), bytes.begin() + size);
    Require(!DecodeQuietProofStatement(malformed, &decoded, &error) &&
                error == QuietProofDecodeError::kMalformed, "typed truncation category");
  }
  malformed = bytes;
  malformed.push_back(0);
  Require(!DecodeQuietProofStatement(malformed, &decoded, &error) &&
              error == QuietProofDecodeError::kMalformed, "typed suffix category");
  statement.claims[1].script_kind = QuietProofScriptKind::kP2wpkh;
  Require(EncodeQuietProofStatement(statement, &bytes) &&
              DecodeQuietProofStatement(bytes, &decoded) &&
              decoded.statement_version == 2 &&
              EncodeQuietProofStatement(decoded, &again) && again == bytes,
          "explicit v2 P2WPKH normalized to v1");

  auto bounded = statement;
  bounded.claims.clear();
  for (size_t i = 0; i < kQuietProofMaxClaims; ++i) {
    auto claim = statement.claims[i % 2];
    claim.txid[0] = static_cast<uint8_t>(i + 1);
    claim.script_kind = i % 2 ? QuietProofScriptKind::kP2pkh :
                               QuietProofScriptKind::kP2wpkh;
    bounded.claims.push_back(claim);
  }
  Require(EncodeQuietProofStatement(bounded, &again), "16 typed claims rejected");
  auto extra = bounded.claims.back();
  ++extra.txid[0];
  bounded.claims.push_back(extra);
  Require(!EncodeQuietProofStatement(bounded, &again), "17 typed claims accepted");
  bounded.claims.pop_back();
  bounded.claims.back().program[0] = 42;
  Require(!EncodeQuietProofStatement(bounded, &again), "second typed key accepted");

  statement.claims[1].script_kind = QuietProofScriptKind::kP2pkh;
  QuietProofEnvelopeV1 envelope;
  envelope.statement = statement;
  envelope.proof.bytes = {1};
  envelope.proof.circuit_digest[0] = 1;
  Require(!EncodeQuietProofEnvelope(envelope, &again), "typed legacy envelope accepted");
  envelope.envelope_version = 2;
  envelope.proof_created_at = 150;
  Require(EncodeQuietProofEnvelope(envelope, &bytes), "typed timestamp envelope rejected");
  QuietProofEnvelopeV1 decoded_envelope;
  Require(DecodeQuietProofEnvelope(bytes, &decoded_envelope) &&
              decoded_envelope.statement.statement_version == 2,
          "typed timestamp envelope round trip failed");
  // Strip the timestamp to construct an otherwise well-formed legacy envelope.
  bytes[4] = 1;
  Require(EncodeQuietProofStatement(statement, &again), "typed statement encode");
  bytes.erase(bytes.begin() + 9 + again.size(), bytes.begin() + 17 + again.size());
  Require(!DecodeQuietProofEnvelope(bytes, &decoded_envelope, &error) &&
              error == QuietProofDecodeError::kMalformed, "typed legacy wire accepted");
  const auto json = QuietProofInspectJson(envelope);
  Require(json.find("\"statement_version\":2") != std::string::npos &&
              json.find("\"script_kinds\":[\"p2wpkh\",\"p2pkh\"]") != std::string::npos,
          "inspection omits typed statement metadata");
}

void TestMalformedStatementCorpus() {
  std::vector<uint8_t> output;
  auto invalid = Statement();
  invalid.nonce.fill(0);
  Require(!EncodeQuietProofStatement(invalid, &output), "zero nonce accepted");
  invalid = Statement();
  invalid.bip322_message_hash.fill(0);
  Require(!EncodeQuietProofStatement(invalid, &output), "zero message hash accepted");
  invalid = Statement();
  invalid.not_before = invalid.expires_at;
  Require(!EncodeQuietProofStatement(invalid, &output), "empty lifetime accepted");
  invalid = Statement();
  invalid.purpose = "anything-goes";
  Require(!EncodeQuietProofStatement(invalid, &output), "unknown purpose accepted");
  invalid = Statement();
  invalid.claims[0].txid.fill(0);
  Require(!EncodeQuietProofStatement(invalid, &output), "zero txid accepted");
  invalid = Statement();
  invalid.claims[0].amount_sats = 0;
  Require(!EncodeQuietProofStatement(invalid, &output), "zero amount accepted");
  invalid = Statement();
  invalid.claims[0].amount_sats = kQuietProofMaxMoneySats + 1;
  Require(!EncodeQuietProofStatement(invalid, &output), "excess amount accepted");
  invalid = Statement();
  invalid.claims[0].amount_sats = kQuietProofMaxMoneySats;
  Require(!EncodeQuietProofStatement(invalid, &output),
          "aggregate amount above maximum accepted");
  invalid = Statement();
  std::swap(invalid.claims[0], invalid.claims[1]);
  Require(!EncodeQuietProofStatement(invalid, &output), "unsorted claims accepted");
  invalid = Statement();
  invalid.claims[1] = invalid.claims[0];
  Require(!EncodeQuietProofStatement(invalid, &output), "duplicate outpoint accepted");
  invalid = Statement();
  QuietProofClaimV1 third = invalid.claims.back();
  third.txid[0] = 3;
  third.program[2] = 7;
  invalid.claims.push_back(third);
  Require(!EncodeQuietProofStatement(invalid, &output),
          "third ownership relation accepted");
  invalid = Statement();
  invalid.has_snapshot = true;
  Require(!EncodeQuietProofStatement(invalid, &output), "zero snapshot hash accepted");
  invalid = Statement();
  invalid.snapshot_height = 1;
  Require(!EncodeQuietProofStatement(invalid, &output),
          "snapshot height without snapshot accepted");
  invalid = Statement();
  invalid.has_bridge_binding = true;
  Require(!EncodeQuietProofStatement(invalid, &output),
          "incomplete bridge binding accepted");
  invalid = Statement();
  invalid.verifier = "\xc0\x80";
  Require(!EncodeQuietProofStatement(invalid, &output), "invalid UTF-8 accepted");
  invalid = Statement();
  invalid.verifier = "line\nbreak";
  Require(!EncodeQuietProofStatement(invalid, &output),
          "control character accepted in verifier ID");
  invalid = Statement();
  invalid.verifier = std::string("bad") + "\xed\xa0\x80";
  Require(!EncodeQuietProofStatement(invalid, &output),
          "UTF-8 surrogate accepted");
  invalid = Statement();
  invalid.verifier = "v\xc3\xa9rificateur";
  Require(EncodeQuietProofStatement(invalid, &output), "valid UTF-8 rejected");
}

void TestEnvelopeAndTranscript() {
  QuietProofEnvelopeV1 envelope;
  envelope.statement = Statement();
  for (size_t index = 0; index < envelope.proof.circuit_digest.size(); ++index) {
    envelope.proof.circuit_digest[index] = static_cast<uint8_t>(index + 1);
  }
  envelope.proof.bytes = {1, 2, 3, 4};
  const auto seed = PoKCTranscriptSeed(envelope.statement, envelope.proof);
  const std::array<uint8_t, 32> sage_seed = {
      0x17, 0x3d, 0x6e, 0x1d, 0xb9, 0xa4, 0x7f, 0x6d,
      0xd9, 0x84, 0xd2, 0x00, 0x52, 0x3f, 0x4c, 0x80,
      0x3f, 0x0a, 0x63, 0x14, 0x6b, 0x4b, 0xb6, 0xba,
      0x09, 0xcc, 0x74, 0xe2, 0x54, 0x4a, 0xf3, 0x46};
  Require(seed == sage_seed, "transcript seed differs from Sage vector");
  envelope.statement.nonce[0] ^= 1;
  Require(seed != PoKCTranscriptSeed(envelope.statement, envelope.proof),
          "nonce not transcript-bound");
  envelope.statement.nonce[0] ^= 1;

  std::vector<uint8_t> wire;
  Require(EncodeQuietProofEnvelope(envelope, &wire), "encode envelope");
  QuietProofEnvelopeV1 decoded;
  Require(DecodeQuietProofEnvelope(wire, &decoded), "decode envelope");
  std::vector<uint8_t> again;
  Require(EncodeQuietProofEnvelope(decoded, &again) && wire == again,
          "envelope is not canonical");
  Require(decoded.envelope_version == 1 && decoded.proof_created_at == 0,
          "legacy envelope acquired a fabricated timestamp");
  Require(PoKCTranscriptSeed(decoded) == seed, "legacy transcript changed");
  auto timestamped = envelope;
  timestamped.envelope_version = 2;
  timestamped.proof_created_at = 150;
  const auto timestamp_seed = PoKCTranscriptSeed(timestamped);
  Require(timestamp_seed != seed, "timestamp envelope lacks domain separation");
  std::vector<uint8_t> timestamp_wire;
  Require(EncodeQuietProofEnvelope(timestamped, &timestamp_wire) &&
              DecodeQuietProofEnvelope(timestamp_wire, &decoded) &&
              decoded.proof_created_at == 150 && decoded.envelope_version == 2 &&
              decoded.statement.not_before == 100,
          "timestamp envelope round trip failed");
  Require(EncodeQuietProofEnvelope(decoded, &again) && again == timestamp_wire,
          "timestamp envelope not canonical");
  ++timestamped.proof_created_at;
  Require(PoKCTranscriptSeed(timestamped) != timestamp_seed,
          "proof timestamp not transcript-bound");
  for (uint64_t invalid_time : {uint64_t{0}, uint64_t{99}, uint64_t{200}}) {
    timestamped.proof_created_at = invalid_time;
    Require(!EncodeQuietProofEnvelope(timestamped, &again), "invalid timestamp encoded");
  }
  for (size_t size = 0; size < timestamp_wire.size(); ++size) {
    Require(!DecodeQuietProofEnvelope(std::vector<uint8_t>(timestamp_wire.begin(),
                timestamp_wire.begin() + size), &decoded), "truncated v2 accepted");
  }
  std::vector<uint8_t> statement_wire;
  Require(EncodeQuietProofStatement(envelope.statement, &statement_wire), "statement");
  auto zero_time = timestamp_wire;
  std::fill_n(zero_time.begin() + 9 + statement_wire.size(), 8, 0);
  Require(!DecodeQuietProofEnvelope(zero_time, &decoded), "zero timestamp decoded");
  Require(QuietProofInspectJson(envelope).find("\"proof_created_at\":null") != std::string::npos,
          "legacy inspection hides missing time");
  timestamped.proof_created_at = 150;
  Require(QuietProofInspectJson(timestamped).find("\"proof_created_at\":150") != std::string::npos &&
              QuietProofInspectJson(timestamped).find("\"request_created_at\":100") != std::string::npos,
          "inspection omits creation times");
  auto invalid_envelope = envelope;
  invalid_envelope.proof.bytes.clear();
  Require(!EncodeQuietProofEnvelope(invalid_envelope, &again),
          "empty proof encoded");
  invalid_envelope = envelope;
  invalid_envelope.proof.circuit_digest.fill(0);
  Require(!EncodeQuietProofEnvelope(invalid_envelope, &again),
          "zero circuit digest encoded");
  invalid_envelope = envelope;
  ++invalid_envelope.proof.circuit_version;
  Require(!EncodeQuietProofEnvelope(invalid_envelope, &again),
          "unsupported proof parameters encoded");
  for (size_t size = 0; size < wire.size(); ++size) {
    const auto end = wire.begin() +
                     static_cast<std::vector<uint8_t>::difference_type>(size);
    const std::vector<uint8_t> truncated(wire.begin(), end);
    Require(!DecodeQuietProofEnvelope(truncated, &decoded),
            "truncated envelope accepted");
  }

  auto unsupported = wire;
  unsupported[4] = 3;
  QuietProofDecodeError error = QuietProofDecodeError::kNone;
  Require(!DecodeQuietProofEnvelope(unsupported, &decoded, &error) &&
              error == QuietProofDecodeError::kUnsupported,
          "unsupported envelope version misclassified");

  std::vector<uint8_t> oversized = {'Q', 'P', 'E', '1', 1};
  QuietProofAppendU32(&oversized,
                    static_cast<uint32_t>(kQuietProofMaxStatementBytes + 1));
  oversized.resize(oversized.size() + kQuietProofMaxStatementBytes + 1);
  Require(!DecodeQuietProofEnvelope(oversized, &decoded),
          "oversized statement allocation accepted");

  const std::string inspection = QuietProofInspectJson(envelope);
  Require(inspection.find("\"network\":\"signet\"") != std::string::npos &&
              inspection.find("nonce") == std::string::npos,
          "inspection output is incorrect or leaks nonce material");
}

void TestReplayPolicy() {
  const auto statement = Statement();
  QuietProofReplayPolicy policy;
  policy.now = 150;
  policy.max_lifetime = 200;
  policy.verifier = statement.verifier;
  policy.purpose = statement.purpose;
  bool consumed = false;
  policy.nonce_seen = [&](const std::array<uint8_t, 32>&) { return consumed; };
  policy.consume_nonce = [&](const std::array<uint8_t, 32>&) {
    if (consumed) return false;
    consumed = true;
    return true;
  };
  Require(QuietProofCheckPolicy(statement, policy, true) ==
              QuietProofAuthorization::kPendingReplayCheck,
          "fresh nonce rejected");
  Require(QuietProofConsumeNonce(statement, policy) ==
              QuietProofAuthorization::kAuthorized,
          "fresh nonce not consumed");
  Require(QuietProofCheckPolicy(statement, policy, true) ==
              QuietProofAuthorization::kReplayRejected,
          "replay accepted");
  policy.now = statement.expires_at;
  Require(QuietProofCheckPolicy(statement, policy, true) ==
              QuietProofAuthorization::kPolicyRejected,
          "expiry boundary accepted");
}

}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::TestNetworks();
    proofs::TestStatementRoundTrip();
    proofs::TestScriptClassification();
    proofs::TestTypedStatements();
    proofs::TestMalformedStatementCorpus();
    proofs::TestEnvelopeAndTranscript();
    proofs::TestReplayPolicy();
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "QuietProof protocol tests passed\n";
  return 0;
}
