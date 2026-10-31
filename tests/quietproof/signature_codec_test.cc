// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include "cli/json.hpp"
#include "quietproof/signature_challenge.h"
#include "quietproof/signature_digest.h"

namespace {
using namespace proofs;
size_t checks = 0;
void Require(bool value, const char* message) {
  ++checks;
  if (!value) throw std::runtime_error(message);
}
template <typename Bytes>
std::string Hex(const Bytes& bytes) {
  constexpr char hex[] = "0123456789abcdef";
  std::string result;
  for (uint8_t byte : bytes) { result += hex[byte >> 4]; result += hex[byte & 15]; }
  return result;
}
std::vector<uint8_t> Unhex(const std::string& text) {
  Require(text.size() % 2 == 0 && text.size() <= 2 * kQuietProofMaxStatementBytes, "invalid test hex size");
  const auto nibble = [](char c) -> int {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
  };
  std::vector<uint8_t> out;
  for (size_t i = 0; i < text.size(); i += 2) {
    Require(nibble(text[i]) >= 0 && nibble(text[i+1]) >= 0, "invalid test hex");
    out.push_back(static_cast<uint8_t>(16 * nibble(text[i]) + nibble(text[i+1])));
  }
  return out;
}
nlohmann::json Json(const QuietProofSignatureInputsV1& input) {
  const auto& p = input.profile;
  auto display = p.to_spend_txid;
  std::reverse(display.begin(), display.end());
  nlohmann::json out = {{"h",Hex(p.h)}, {"d",Hex(p.statement_digest)},
      {"application_message_ascii",std::string(p.application_message.begin(),p.application_message.end())},
      {"application_message_hex",Hex(p.application_message)},
      {"application_message_hash",Hex(p.application_message_hash)},
      {"selected_script_pubkey",Hex(p.selected_script)}, {"script_code",Hex(p.script_code)},
      {"to_spend_hex",Hex(p.to_spend)}, {"to_spend_txid_raw",Hex(p.to_spend_txid)},
      {"to_spend_txid_display",Hex(display)}, {"to_sign_input_outpoint_wire",Hex(p.synthetic_outpoint)},
      {"to_sign_unsigned_hex",Hex(p.unsigned_to_sign)}, {"sighash_preimage_hex",Hex(input.sighash_preimage)},
      {"z",Hex(input.z)}, {"bip143_components",nullptr}};
  if (p.signing_kind == QuietProofScriptKind::kP2wpkh)
    out["bip143_components"] = {{"hash_prevouts",Hex(input.hash_prevouts)},
        {"hash_sequence",Hex(input.hash_sequence)}, {"hash_outputs",Hex(input.hash_outputs)}};
  return out;
}
void Reject(const std::vector<uint8_t>& request, QuietProofSignatureDigestError expected) {
  QuietProofSignatureInputsV1 out;
  out.z.fill(0xaa); out.profile.h.fill(0xbb);
  out.profile.to_spend = {0xcc}; out.sighash_preimage = {0xdd};
  const auto before = Json(out);
  auto error = QuietProofSignatureDigestError::kNone;
  Require(!DeriveQuietProofSignatureInputs(request, &out, &error) && error == expected && Json(out) == before,
      "failed derivation accepted, changed output, or misclassified error");
}
void TestFixture(const nlohmann::json& vector) {
  const auto request = Unhex(vector.at("request_hex"));
  const auto before = request;
  QuietProofSignatureInputsV1 inputs;
  auto error = QuietProofSignatureDigestError::kMalformedStatement;
  if (kQuietProofSignatureModeEnabled) {
    Require(DeriveQuietProofSignatureInputs(request, &inputs, &error) &&
        error == QuietProofSignatureDigestError::kNone && request == before, "valid expected request failed");
    const auto derived = Json(inputs);
    for (const auto& name : {"d", "application_message_ascii", "application_message_hex",
         "application_message_hash", "selected_script_pubkey", "script_code", "to_spend_hex",
         "to_spend_txid_raw", "to_spend_txid_display", "to_sign_input_outpoint_wire",
         "to_sign_unsigned_hex", "sighash_preimage_hex", "z", "bip143_components"})
      Require(derived.at(name) == vector.at(name), "production bytes differ from frozen independent fixture");
    Require(derived.at("h") == vector.at("request").at("claims")[0].at("program"), "wrong public h");
    const bool witness = inputs.profile.signing_kind == QuietProofScriptKind::kP2wpkh;
    Require(inputs.profile.to_spend.size() == (witness ? 116 : 119) &&
        inputs.profile.selected_script.size() == (witness ? 22 : 25) &&
        inputs.sighash_preimage.size() == (witness ? kQuietProofSignatureWitnessPreimageBytes :
                                                 kQuietProofSignatureLegacyPreimageBytes), "profile bounds differ");
    Require(inputs.profile.application_message_hash != inputs.profile.statement_digest,
        "application message hash confused with statement digest");
    QuietProofSignatureStatementV3 statement;
    Require(DecodeQuietProofSignatureStatement(request, &statement) &&
        statement.bip322_message_hash != inputs.profile.application_message_hash,
        "user commitment confused with application message hash");
    inputs.z.fill(0); inputs.profile.h.fill(0); inputs.profile.synthetic_outpoint.fill(0xff);
    Require(DeriveQuietProofSignatureInputs(request, &inputs) && Json(inputs) == derived,
        "stored/caller-modified derived values affected reconstruction");
    for (const auto& mutation : vector.at("field_mutations")) {
      auto changed = request;
      changed[mutation.at("offset").get<size_t>()] ^= 1;
      QuietProofSignatureInputsV1 modified;
      if (DeriveQuietProofSignatureInputs(changed, &modified, &error)) {
        const auto& expected = mutation.at("field") == "signing_kind" ?
            vector.at("valid_selected_kind_change") : mutation;
        Require(Hex(modified.profile.statement_digest) == expected.at("d").get<std::string>() &&
            Hex(modified.z) == expected.at("z").get<std::string>(),
            "request field mutation differs from independent digest vector");
        Require(modified.z != inputs.z, "changed request reused digest");
      } else {
        Require(error == QuietProofSignatureDigestError::kMalformedStatement ||
            error == QuietProofSignatureDigestError::kUnsupported, "malformed mutation selected another path");
      }
    }
  } else {
    Reject(request, QuietProofSignatureDigestError::kSignatureModeDisabled);
  }
  for (size_t n = 0; n < request.size(); ++n)
    Reject({request.begin(),request.begin()+n}, QuietProofSignatureDigestError::kMalformedStatement);
  auto changed = request; changed.push_back(0);
  Reject(changed, QuietProofSignatureDigestError::kMalformedStatement);
  Reject(std::vector<uint8_t>(4097,0), QuietProofSignatureDigestError::kMalformedStatement);
  for (size_t offset : {size_t{4},size_t{5},size_t{6},size_t{7},size_t{8},size_t{9}}) {
    changed = request; changed[offset] = 0xff;
    Reject(changed, QuietProofSignatureDigestError::kUnsupported);
  }
  changed = request; changed[6] = 0;
  Reject(changed, QuietProofSignatureDigestError::kMalformedStatement);
  // A known old typed request cannot select this signature derivation API.
  changed = request; changed.erase(changed.begin()+6,changed.begin()+10); changed[4] = 2;
  Reject(changed, QuietProofSignatureDigestError::kMalformedStatement);
  Require(!DeriveQuietProofSignatureInputs(request,nullptr), "null output accepted");
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 3 && std::string(argv[1]) == "--derive") {
      // Test-only public-request driver for the independent L2 reference. No
      // signatures/receipts, arbitrary transaction inputs or supplied z accepted.
      QuietProofSignatureInputsV1 inputs;
      QuietProofSignatureDigestError error;
      if (!DeriveQuietProofSignatureInputs(Unhex(argv[2]), &inputs, &error)) {
        std::cout << nlohmann::json{{"error",QuietProofSignatureDigestErrorName(error)}}.dump() << '\n';
        return error == QuietProofSignatureDigestError::kMalformedStatement ? 65 : 66;
      }
      std::cout << Json(inputs).dump() << '\n';
      return 0;
    }
    Require(argc == 2, "expected frozen profile fixture path");
    std::ifstream input(argv[1]); nlohmann::json fixture; input >> fixture;
    for (const auto& vector : fixture.at("vectors")) TestFixture(vector);
    std::cout << checks << " signature codec checks passed; capability=" << kQuietProofSignatureModeEnabled << '\n';
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "not ok: " << e.what() << '\n'; return 1;
  }
}
