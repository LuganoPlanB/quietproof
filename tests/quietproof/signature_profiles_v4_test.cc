// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <fstream>
#include <iostream>
#include <stdexcept>
#include "cli/json.hpp"
#include "quietproof/bip322_import.h"
#include "quietproof/signature_envelope.h"

namespace {
using namespace proofs;
size_t checks = 0;
void Check(bool condition, const char* message) {
  ++checks;
  if (!condition) throw std::runtime_error(message);
}
std::vector<uint8_t> Unhex(const std::string& text) {
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < text.size(); i += 2)
    bytes.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
  return bytes;
}
void Fixture(const nlohmann::json& vector, QuietProofSigningProfile profile) {
  const auto wire = Unhex(vector.at("request_hex"));
  QuietProofSignatureStatementV4 statement;
  Check(DecodeQuietProofSignatureStatement(wire, &statement), "v4 fixture decode");
  Check(statement.statement_version == 4 && statement.signing_profile == profile &&
        statement.profile_version == 1, "wrong profile tuple");
  std::vector<uint8_t> encoded;
  Check(EncodeQuietProofSignatureStatement(statement, &encoded) && encoded == wire,
        "independent v4 canonical encoding differs");
  std::array<uint8_t, 32> digest;
  const auto expected = Unhex(vector.at("d"));
  Check(QuietProofSignatureStatementDigest(statement, &digest) &&
        std::equal(digest.begin(), digest.end(), expected.begin()), "independent v4 digest differs");
  QuietProofSignatureInputsV1 inputs;
  QuietProofSignatureDigestError error;
  const bool derived = DeriveQuietProofSignatureInputs(wire, &inputs, &error);
#if defined(QUIETPROOF_HAS_SIGNATURE_MODE) && QUIETPROOF_HAS_SIGNATURE_MODE
  if (profile == QuietProofSigningProfile::kBip322EcdsaV1) {
    Check(derived, "BIP322 v4 derivation failed");
    const auto z = Unhex(vector.at("z"));
    Check(std::equal(inputs.z.begin(), inputs.z.end(), z.begin()), "independent BIP322 z differs");
    const std::string message(inputs.profile.application_message.begin(), inputs.profile.application_message.end());
    Check(message == vector.at("application_message_ascii").get<std::string>() && message.size() == 88,
          "exact canonical application message differs");
  } else {
    Check(derived, "legacy v4 derivation failed");
    const auto z = Unhex(vector.at("legacy_z"));
    Check(std::equal(inputs.z.begin(), inputs.z.end(), z.begin()), "independent legacy z differs");
    Check(inputs.sighash_preimage == Unhex(vector.at("legacy_preimage_hex")), "legacy CompactSize/message bytes differ");
    Check(inputs.profile.to_spend.empty() && inputs.profile.selected_script.size() == 25,
          "legacy transaction/address script construction differs");
  }
#else
  Check(!derived && error == QuietProofSignatureDigestError::kSignatureModeDisabled,
        "disabled build derived signing inputs");
#endif
  for (size_t offset : {size_t{7}, size_t{8}, size_t{9}, size_t{10}}) {
    auto bad = wire; bad[offset] = 0xff;
    auto sentinel = statement;
    QuietProofDecodeError decoded;
    Check(!DecodeQuietProofSignatureStatement(bad, &sentinel, &decoded) &&
          decoded == QuietProofDecodeError::kUnsupported, "unknown tuple accepted");
    Check(sentinel.signing_profile == statement.signing_profile, "failed decode changed output");
  }
  auto old = wire; old[4] = 3; old.erase(old.begin() + 9);
  QuietProofDecodeError decoded;
  Check(!DecodeQuietProofSignatureStatement(old, &statement, &decoded) &&
        decoded == QuietProofDecodeError::kUnsupported, "superseded v3 request accepted");
  QuietProofSignatureAuthorisationV1 authorization;
  QuietProofSignatureAuthorisationError receipt_error;
  for (uint8_t version : {uint8_t{1}, uint8_t{3}}) {
    std::vector<uint8_t> receipt(150, 0);
    std::copy_n("QPA1", 4, receipt.begin()); receipt[4] = version;
    Check(!ImportQuietProofSignatureAuthorisation(wire, receipt, &authorization, &receipt_error) &&
          receipt_error == QuietProofSignatureAuthorisationError::kUnsupported,
          "superseded receipt accepted");
  }
}
}  // namespace
int main(int argc, char** argv) {
  try {
    Check(argc == 2, "fixture argument required");
    std::ifstream input(argv[1]); nlohmann::json fixture; input >> fixture;
    for (const auto& vector : fixture.at("vectors"))
      Fixture(vector, QuietProofSigningProfile::kBip322EcdsaV1);
    const auto& legacy = fixture.at("legacy_vectors").at(0);
    Fixture(legacy, QuietProofSigningProfile::kBitcoinMessageEcdsaV1);
    auto bip_wire = Unhex(fixture.at("vectors").at(0).at("request_hex"));
    const auto legacy_wire = Unhex(legacy.at("request_hex"));
    Check(bip_wire != legacy_wire && fixture.at("vectors").at(0).at("d") != legacy.at("d"),
          "same-address profiles share canonical request/digest");
    Check(!QuietProofSigningProfileCompatible(QuietProofSigningProfile::kBitcoinMessageEcdsaV1,
          1, QuietProofScriptKind::kP2wpkh), "legacy SegWit tuple supported");
    QuietProofSignatureEnvelopeMetadataV4 metadata;
    metadata.request = bip_wire; metadata.proof_created_at = 1800000100;
    metadata.circuit_digest = PoKSigExpectedCircuitDigest();
    std::vector<uint8_t> envelope;
    Check(EncodeQuietProofSignatureEnvelope(metadata, {1}, &envelope), "v4 envelope encode");
    auto old = envelope; old[4] = 3;
    QuietProofSignatureEnvelopeError error;
    Check(!InspectQuietProofSignatureEnvelope(old, &metadata, &error) &&
          error == QuietProofSignatureEnvelopeError::kUnsupported, "old proof envelope accepted");
    QuietProofSignatureEnvelopeMetadataV4 parsed;
    Check(InspectQuietProofSignatureEnvelope(envelope, &parsed), "v4 envelope inspection");
    parsed.profile = 2;
    Check(!EncodeQuietProofSignatureEnvelope(parsed, {1}, &old), "cross-profile envelope encoded");
    auto substituted = envelope; substituted[9 + bip_wire.size() + 10] = 2;
    Check(!InspectQuietProofSignatureEnvelope(substituted, &parsed), "profile substitution accepted");
    std::array<uint8_t, 32> seed; seed.fill(17); const auto before = seed;
    Check(!PoKSigTranscriptSeed(legacy_wire, envelope, 1800000100, &seed, &error) &&
          seed == before, "same-address cross-profile proof request reused");
#if defined(QUIETPROOF_HAS_SIGNATURE_MODE) && QUIETPROOF_HAS_SIGNATURE_MODE
    Check(error == QuietProofSignatureEnvelopeError::kInvalidProof,
          "cross-profile substitution did not fail at expected-request binding");
#else
    Check(error == QuietProofSignatureEnvelopeError::kSignatureModeDisabled,
          "disabled build bypassed profile-proof capability");
#endif
    static_assert(PoKSigParametersV1::kPublicInputs == 53 && PoKSigParametersV1::kFamily == 1 &&
                  PoKSigParametersV1::kCircuitVersion == 1 && PoKSigParametersV1::kRate == 4 &&
                  PoKSigParametersV1::kQueries == 128);
    std::cout << checks << " v4 profile contract checks passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "not ok: " << error.what() << '\n'; return 1;
  }
}
