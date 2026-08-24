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
  second.program[1] = 8;
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
      0x5e, 0x0b, 0x62, 0xe6, 0x0d, 0x8a, 0x87, 0x7c,
      0x72, 0xf8, 0x0c, 0xdb, 0x56, 0x57, 0x43, 0x00,
      0x5b, 0xc1, 0xcd, 0xc3, 0x67, 0x4c, 0xc1, 0xd9,
      0xc5, 0x3e, 0xd3, 0x5c, 0xf0, 0x4b, 0xfc, 0xaa};
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

  auto snapshot = statement;
  snapshot.has_snapshot = true;
  snapshot.snapshot[0] = 7;
  snapshot.snapshot_height = 123;
  Require(EncodeQuietProofStatement(snapshot, &encoded) &&
              DecodeQuietProofStatement(encoded, &decoded) &&
              decoded.snapshot_height == 123,
          "snapshot hash/height round trip failed");
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
      0xa4, 0x12, 0xb1, 0x70, 0xb0, 0x67, 0x06, 0xf6,
      0x00, 0x50, 0x19, 0x1e, 0x6d, 0xf8, 0xc2, 0x39,
      0x74, 0x66, 0x48, 0x55, 0xce, 0x4e, 0xef, 0xc3,
      0x5d, 0x7a, 0xc0, 0x38, 0x15, 0x06, 0xd6, 0x02};
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
  unsupported[4] = 2;
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
