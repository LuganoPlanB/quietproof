// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <new>
#include <stdexcept>
#include "cli/json.hpp"
#include "poksig/prover.h"
#include "quietproof/verifier.h"

namespace { bool tracking = false; size_t largest_allocation = 0; }
void* operator new(std::size_t size) {
  if (tracking) largest_allocation = std::max(largest_allocation, size);
  if (void* memory = std::malloc(size ? size : 1)) return memory;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

namespace {
using namespace proofs;
size_t checks = 0;
void Check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
std::vector<uint8_t> Unhex(const std::string& text) {
  Check(text.size() % 2 == 0 && text.size() <= 8192, "bounded fixture input");
  std::vector<uint8_t> bytes;
  for (size_t i=0; i<text.size(); i+=2) bytes.push_back(std::stoul(text.substr(i,2), nullptr, 16));
  return bytes;
}
void Put(std::vector<uint8_t>& bytes, size_t offset, uint64_t value, size_t size) {
  for (size_t i=0; i<size; ++i) bytes[offset+size-1-i] = static_cast<uint8_t>(value >> (8*i));
}
uint64_t Now() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
void Write(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
  Check(!std::filesystem::exists(path), "artifact must be new");
  std::ofstream file(path, std::ios::binary);
  file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  Check(static_cast<bool>(file), "public artifact write failed");
}
void Reject(const std::vector<uint8_t>& expected, const PoKSigProofV1& proof,
            PoKSigError wanted, bool early = true, PoKSigOptionsV1 options = {true}) {
  PoKSigError error = PoKSigError::kNone;
  largest_allocation = 0; tracking = early;
  const bool result = PoKSigVerifyProof(expected, proof, Now(), options, &error);
  tracking = false;
  Check(!result && error == wanted, "proof rejection classification");
  if (early) Check(largest_allocation <= 4096, "proof allocated before acceptance guards");
}
void Run(const nlohmann::json& fixture, const std::filesystem::path& directory, bool disabled) {
  size_t real_proofs = 0;
  for (const auto& test : fixture.at("cases")) {
    const auto request = Unhex(test.at("request"));
    const auto receipt = Unhex(test.at("receipt"));
    PoKSigError error;
    PoKSigProofV1 proof{{17}}, sentinel = proof;
    QuietProofSignatureAuthorisationV1 authorization;
    if (disabled) {
      Check(!PoKSigProve(request, authorization, &proof, {true}, &error) &&
            error == PoKSigError::kSignatureModeDisabled && proof.bytes == sentinel.bytes, "disabled direct prover");
      Check(!PoKSigProveReceipt(request, receipt, &proof, {true}, &error) &&
            error == PoKSigError::kSignatureModeDisabled && proof.bytes == sentinel.bytes, "disabled receipt prover");
      QuietProofSignatureEnvelopeMetadataV4 metadata;
      metadata.request = request; metadata.proof_created_at = Now(); metadata.circuit_digest = PoKSigExpectedCircuitDigest();
      metadata.profile = (uint16_t(request[7]) << 8) | request[8];
      Check(EncodeQuietProofSignatureEnvelope(metadata, {1}, &proof.bytes), "disabled metadata transport");
      Reject(request, proof, PoKSigError::kSignatureModeDisabled);
      continue;
    }
    Check(ImportQuietProofSignatureAuthorisation(request, receipt, &authorization), "private authorisation import");
    QuietProofSignatureInputsV1 inputs;
    Check(DeriveQuietProofSignatureInputs(request, &inputs), "derive public inputs");
    Check(std::equal(inputs.z.begin(), inputs.z.end(), Unhex(test.at("z")).begin()) &&
          std::equal(inputs.profile.h.begin(), inputs.profile.h.end(), Unhex(test.at("h")).begin()), "independent public-byte agreement");
    Check(!PoKSigProve(request, authorization, &proof, {}, &error) &&
          error == PoKSigError::kSignatureModeNotAllowed && proof.bytes == sentinel.bytes, "prover allowance/output");
    for (size_t i=0; i<4; ++i) {
      auto bad = authorization;
      if (i==0) bad.public_key[1] ^= 1;
      if (i==1) bad.r[0] ^= 1;
      if (i==2) bad.s[0] ^= 1;
      if (i==3) bad.statement_digest[0] ^= 1;
      Check(!PoKSigProve(request, bad, &proof, {true}, &error) && error == PoKSigError::kInvalidAuthorization &&
            proof.bytes == sentinel.bytes, "wrong authorisation/output");
    }
    const auto progress = [](const char* stage) { std::cout << "phase " << stage << std::endl; };
    std::cout << "start " << test.at("name").get<std::string>() << std::endl;
    const bool proved = real_proofs == 0 ? PoKSigProve(request, authorization, &proof, {true}, &error, progress) :
        PoKSigProveReceipt(request, receipt, &proof, {true}, &error, progress);
    if (!proved) std::cerr << "prover result " << PoKSigErrorName(error) << std::endl;
    Check(proved && error == PoKSigError::kNone, "real composed proof generation");
    const auto name = test.at("name").get<std::string>();
    Write(directory/(name+".qpf"), proof.bytes);
    Write(directory/(name+".qpr"), request);
    QuietProofSignatureEnvelopeMetadataV4 metadata;
    Check(InspectQuietProofSignatureEnvelope(proof.bytes, &metadata) &&
          metadata.proof_size <= kQuietProofSignatureMaxProofBytes && metadata.circuit_digest == PoKSigExpectedCircuitDigest(), "actual serialized size/identity");
    Check(PoKSigVerifyProof(request, proof, Now(), {true}, &error) && error == PoKSigError::kNone, "real composed verification");
    ++real_proofs;
    Reject(request, proof, PoKSigError::kSignatureModeNotAllowed, true, {});
    Reject({}, proof, PoKSigError::kMalformedStatement);
    QuietProofSignatureStatementV4 statement;
    Check(DecodeQuietProofSignatureStatement(request, &statement), "request decode");
    auto changed = statement; changed.nonce[0] ^= 1;
    std::vector<uint8_t> changed_request;
    Check(EncodeQuietProofSignatureStatement(changed, &changed_request), "changed request encode");
    Reject(changed_request, proof, PoKSigError::kInvalidProof);
    // Rebind embedded bytes as well: public z derives from changed expected
    // request. Reusing the actual proof must fail cryptographic verification.
    const std::vector<uint8_t> body(proof.bytes.begin()+metadata.proof_offset, proof.bytes.end());
    auto rebound_metadata = metadata; rebound_metadata.request = changed_request;
    PoKSigProofV1 rebound;
    Check(EncodeQuietProofSignatureEnvelope(rebound_metadata, body, &rebound.bytes), "rebound transport");
    Reject(changed_request, rebound, PoKSigError::kInvalidProof, false);
    changed = statement;
    for (auto& claim : changed.claims) claim.program[0] ^= 1;
    Check(EncodeQuietProofSignatureStatement(changed, &changed_request), "changed hash request encode");
    rebound_metadata.request = changed_request;
    Check(EncodeQuietProofSignatureEnvelope(rebound_metadata, body, &rebound.bytes), "rebound hash transport");
    Reject(changed_request, rebound, PoKSigError::kInvalidProof, false);
    const size_t tail = 9 + request.size();
    if (statement.signing_kind == QuietProofScriptKind::kP2pkh) {
      changed = statement;
      changed.signing_profile = statement.signing_profile == QuietProofSigningProfile::kBip322EcdsaV1 ?
          QuietProofSigningProfile::kBitcoinMessageEcdsaV1 : QuietProofSigningProfile::kBip322EcdsaV1;
      Check(EncodeQuietProofSignatureStatement(changed, &changed_request), "cross-profile request encode");
      Reject(changed_request, proof, PoKSigError::kInvalidProof);
      rebound_metadata.request = changed_request;
      rebound_metadata.profile = static_cast<uint16_t>(changed.signing_profile);
      Check(EncodeQuietProofSignatureEnvelope(rebound_metadata, body, &rebound.bytes), "cross-profile rebound encode");
      Reject(changed_request, rebound, PoKSigError::kInvalidProof, false);
    }
    for (size_t offset : {tail+14, tail+46, tail+50, tail+54}) {
      auto bad = proof; bad.bytes[offset] ^= 1;
      Reject(request, bad, offset == tail+14 ? PoKSigError::kUnapprovedCircuit : PoKSigError::kUnsupported);
    }
    auto bad = proof; bad.bytes[metadata.proof_offset] ^= 1;
    Reject(request, bad, PoKSigError::kInvalidProof, false);
    bad = proof; bad.bytes.push_back(0); Reject(request, bad, PoKSigError::kMalformedStatement);
    Put(bad.bytes, tail+58, metadata.proof_size+1, 4); Reject(request, bad, PoKSigError::kInvalidProof, false);
    bad.bytes.resize(metadata.proof_offset + kQuietProofSignatureMaxProofBytes + 1);
    Put(bad.bytes, tail+58, kQuietProofSignatureMaxProofBytes+1, 4);
    Reject(request, bad, PoKSigError::kMalformedStatement);
    bad.bytes.resize(kQuietProofSignatureMaxEnvelopeBytes+1); Reject(request, bad, PoKSigError::kMalformedStatement);
    bad.bytes = receipt; Reject(request, bad, PoKSigError::kPrivateReceiptInput);
    unsigned callbacks = 0;
    QuietProofVerifierConfig old; old.supports=[&](const auto&){++callbacks;return true;};
    old.verify_proof=[&](const auto&){++callbacks;return true;};
    Check(VerifyQuietProof(proof.bytes, old).result == QuietProofVerifyResult::kUnsupported && callbacks == 0, "old verifier default changed");
    std::cout << "proof " << name << " verified=1 proof_bytes=" << metadata.proof_size
              << " envelope_bytes=" << proof.bytes.size() << std::endl;
  }
  Check(real_proofs == (disabled ? 0u : fixture.at("cases").size()), "required proof count");
  std::cout << "{\"checks\":" << checks << ",\"realProofs\":" << real_proofs
            << ",\"failed\":0,\"skipped\":0,\"disabled\":" << (disabled ? "true" : "false") << "}" << std::endl;
}
}
int main(int argc, char** argv) {
  try {
    Check(argc==3 || argc==4, "private fixture/public artifact paths required");
    std::ifstream file(argv[1]); nlohmann::json fixture; file >> fixture;
    Run(fixture, argv[2], argc==4);
    return 0;
  } catch (const nlohmann::json::exception&) {
    // Parser exceptions can contain excerpts of the private fixture file.
    std::cerr << "signature proof test: private fixture parse failure\n";
    return 1;
  } catch (const std::exception& error) { std::cerr << "signature proof test: " << error.what() << '\n'; return 1; }
}
