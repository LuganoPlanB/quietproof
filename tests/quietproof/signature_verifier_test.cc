// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <new>
#include <stdexcept>
#include "cli/json.hpp"
#include "quietproof/signature_challenge.h"
#include "quietproof/signature_verifier.h"
#include "quietproof/detail/bitcoin_core_parse.h"

namespace { bool tracking = false; size_t largest = 0; }
void* operator new(std::size_t size) {
  if (tracking) largest = std::max(largest, size);
  if (void* memory = std::malloc(size ? size : 1)) return memory;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

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
std::vector<uint8_t> Encode(const QuietProofSignatureStatementV4& statement) {
  std::vector<uint8_t> bytes;
  Check(EncodeQuietProofSignatureStatement(statement, &bytes), "encode test request");
  return bytes;
}
void Reject(const std::vector<uint8_t>& expected, const std::vector<uint8_t>& proof,
            const QuietProofSignatureVerifierConfig& config,
            QuietProofVerifyResult wanted, const char* detail) {
  const char* reason = nullptr;
  largest = 0;
  tracking = true;
  auto local = config;
  local.clock = [now = config.policy.now](uint64_t* time) { *time = now; return true; };
  const auto result = VerifyQuietProofSignatureWithReason(expected, proof, local, &reason);
  tracking = false;
  Check(result.result == wanted && reason && std::string(reason) == detail,
        "expected-request rejection classification");
  Check(result.claims.empty() && result.total_sats == 0, "rejection asserted funds");
  Check(largest <= kQuietProofMaxStatementBytes, "proof work before request guard");
}
void Run(const nlohmann::json& fixture) {
  for (const auto& vector : fixture.at("vectors")) {
    const auto expected = Unhex(vector.at("request_hex"));
    QuietProofSignatureStatementV4 statement;
    Check(DecodeQuietProofSignatureStatement(expected, &statement), "decode fixture");
    QuietProofSignatureEnvelopeMetadataV4 metadata;
    metadata.request = expected;
    metadata.proof_created_at = statement.not_before + 1;
    metadata.circuit_digest = PoKSigExpectedCircuitDigest();
    std::vector<uint8_t> proof;
    Check(EncodeQuietProofSignatureEnvelope(metadata, {1}, &proof), "framed invalid proof fixture");
    QuietProofSignatureVerifierConfig config;
    config.policy.now = metadata.proof_created_at;
    config.policy.verifier = statement.verifier;
    config.policy.purpose = statement.purpose;
    unsigned nonce_calls = 0;
    config.policy.nonce_seen = [&](const auto&) { ++nonce_calls; return false; };
    config.policy.consume_nonce = [&](const auto&) { ++nonce_calls; return true; };
    Reject({}, proof, config, QuietProofVerifyResult::kInvalidProof, "missing_expected_request");
    Reject(expected, proof, config, QuietProofVerifyResult::kUnsupported, "signature_mode_not_allowed");
    config.modes.allow_signature_possession = true;
    for (size_t field = 0; field < 9; ++field) {
      auto changed = statement;
      if (field == 0) changed.nonce[0] ^= 1;
      if (field == 1) changed.verifier += ".invented";
      if (field == 2) changed.network = statement.network == QuietProofNetwork::kRegtest ?
          QuietProofNetwork::kSignet : QuietProofNetwork::kRegtest;
      if (field == 3) changed.signing_kind = statement.signing_kind == QuietProofScriptKind::kP2pkh ?
          QuietProofScriptKind::kP2wpkh : QuietProofScriptKind::kP2pkh;
      if (field == 4) ++changed.claims[0].amount_sats;
      if (field == 5) { for (auto& claim : changed.claims) claim.program[0] ^= 1; }
      if (field == 6) changed.bip322_message_hash[0] ^= 1;
      if (field == 7) ++changed.expires_at;
      if (field == 8) changed.purpose = statement.purpose == "proof-of-funds" ?
          "proof-of-control" : "proof-of-funds";
      const auto altered = Encode(changed);
      Reject(altered, proof, config, QuietProofVerifyResult::kInvalidProof, "expected_request_mismatch");
      auto invented = metadata;
      invented.request = altered;
      std::vector<uint8_t> invented_proof;
      Check(EncodeQuietProofSignatureEnvelope(invented, {1}, &invented_proof), "altered embedded request");
      Reject(expected, invented_proof, config, QuietProofVerifyResult::kInvalidProof, "expected_request_mismatch");
    }
    auto profile = expected;
    profile[8] = 2;
    Reject(profile, proof, config,
        statement.signing_kind == QuietProofScriptKind::kP2pkh ?
            QuietProofVerifyResult::kInvalidProof : QuietProofVerifyResult::kUnsupported,
        statement.signing_kind == QuietProofScriptKind::kP2pkh ?
            "expected_request_mismatch" : "invalid_expected_request");
    profile[8] = 3;
    Reject(profile, proof, config, QuietProofVerifyResult::kUnsupported, "invalid_expected_request");
    auto bridge_policy = config;
    bridge_policy.policy.purpose = "bridge-authorization";
    Reject(expected, proof, bridge_policy, QuietProofVerifyResult::kBridgeRejected, "signature_bridge_rejected");
    // Construct a valid scalar bridge request then advertise it as v4. The
    // signature codec must reject the bridge fields before any proof work.
    auto bridge = static_cast<const QuietProofStatementV1&>(statement);
    bridge.statement_version = 2;
    bridge.purpose = "bridge-authorization";
    bridge.has_bridge_binding = true;
    bridge.bridge.destination_commitment.fill(1);
    bridge.bridge.lock_id.fill(2);
    bridge.bridge.asset_id = "BTC";
    std::vector<uint8_t> bridge_bytes;
    Check(EncodeQuietProofStatement(bridge, &bridge_bytes), "scalar bridge fixture");
    bridge_bytes[4] = 4;
    bridge_bytes.insert(bridge_bytes.begin()+6, {1, 0, 1, 1, static_cast<uint8_t>(statement.signing_kind)});
    Reject(bridge_bytes, proof, config, QuietProofVerifyResult::kMalformedStatement, "invalid_expected_request");
    Check(nonce_calls == 0, "request rejection touched nonce store");
    Reject(expected, {'Q','P','A','1'}, config, QuietProofVerifyResult::kMalformedStatement, "private_receipt_input");
    if (!kQuietProofSignatureModeEnabled) {
      Reject(expected, proof, config, QuietProofVerifyResult::kUnsupported, "signature_mode_disabled");
    } else {
      for (size_t policy = 0; policy < 5; ++policy) {
        auto bad = config;
        if (policy == 0) bad.policy.verifier += ".other";
        if (policy == 1) bad.policy.purpose = "proof-of-control";
        if (policy == 2) bad.policy.now = statement.not_before - 1;
        if (policy == 3) bad.policy.now = statement.expires_at;
        if (policy == 4) bad.policy.max_lifetime = 1;
        Reject(expected, proof, bad, QuietProofVerifyResult::kInvalidProof, "signature_request_policy_rejected");
      }
    }
    QuietProofVerifierConfig scalar;
    unsigned scalar_calls = 0;
    scalar.verify_proof = [&](const auto&) { ++scalar_calls; return true; };
    Check(VerifyQuietProof(proof, scalar).result == QuietProofVerifyResult::kUnsupported && scalar_calls == 0,
          "untrusted metadata activated scalar API signature mode");
  }
}

class StateProvider final : public QuietProofChainProvider {
 public:
  QuietProofSignatureStatementV4 expected;
  std::vector<QuietProofChainEvidence> evidence;
  QuietProofNodeState before, after;
  bool historical = false;
  size_t lookups = 0, observations = 0;
  QuietProofProviderKind kind() const override {
    return historical ? QuietProofProviderKind::kHistoricalSnapshot : QuietProofProviderKind::kCurrentTip;
  }
  QuietProofNodeState ObserveNodeState() override { return ++observations == 1 ? before : after; }
  QuietProofChainEvidence Lookup(const QuietProofChainRequest& request) override {
    Check(lookups < expected.claims.size(), "extra/synthetic output lookup");
    const auto& claim = expected.claims[lookups];
    Check(request.network == expected.network && request.txid == claim.txid && request.vout == claim.vout &&
          request.has_snapshot == expected.has_snapshot && request.snapshot == expected.snapshot &&
          request.snapshot_height == expected.snapshot_height, "outpoint/network/snapshot lookup changed");
    return evidence.at(lookups++);
  }
};
StateProvider Provider(const QuietProofSignatureStatementV4& expected, uint64_t now) {
  StateProvider provider;
  provider.expected = expected;
  provider.before.status = QuietProofNodeStateStatus::kObserved;
  provider.before.network = expected.network;
  provider.before.block.fill(0x12);
  provider.before.height = 200;
  provider.before.tip_time = now;
  provider.before.initial_block_download = false;
  provider.before.active_chainstate_validated = true;
  provider.after = provider.before;
  for (const auto& claim : expected.claims) {
    QuietProofChainEvidence evidence;
    evidence.status = QuietProofChainStatus::kUnspent;
    evidence.network = expected.network;
    evidence.block = provider.before.block;
    evidence.height = provider.before.height;
    evidence.confirmations = 10;
    evidence.amount_sats = claim.amount_sats;
    evidence.coinbase_known = true;
    evidence.script_pub_key = claim.script_kind == QuietProofScriptKind::kP2pkh ?
        std::vector<uint8_t>{0x76, 0xa9, 0x14} : std::vector<uint8_t>{0, 20};
    evidence.script_pub_key.insert(evidence.script_pub_key.end(), claim.program.begin(), claim.program.end());
    if (claim.script_kind == QuietProofScriptKind::kP2pkh) evidence.script_pub_key.insert(evidence.script_pub_key.end(), {0x88, 0xac});
    provider.evidence.push_back(evidence);
  }
  return provider;
}
void StateChecks(const nlohmann::json& fixture) {
  QuietProofSignatureStatementV4 expected;
  Check(DecodeQuietProofSignatureStatement(Unhex(fixture.at("vectors")[0].at("request_hex")), &expected), "state fixture");
  expected.has_snapshot = false;
  expected.snapshot.fill(0);
  expected.snapshot_height = 0;
  const uint64_t now = expected.not_before + 1;
  QuietProofSignatureVerifierConfig config;
  config.policy.now = now;
  config.clock = [now](uint64_t* time) { *time = now; return true; };
  unsigned consumed = 0;
  config.policy.consume_nonce = [&](const auto&) { ++consumed; return true; };
  uint64_t total = 0;
  for (const auto& claim : expected.claims) total += claim.amount_sats;
  auto run = [&](StateProvider& provider, QuietProofSignatureVerifierConfig policy,
                 bool ready, QuietProofVerifyResult wanted, const char* detail) {
    policy.provider = &provider;
    const char* reason = nullptr;
    const auto out = quietproof_detail::CheckSignatureFunds(provider.expected, policy, &reason);
    Check(out.ready_for_acceptance == ready && out.verification.result == wanted && reason &&
          std::string(reason) == detail, "state policy result/reason");
    Check(consumed == 0 && out.verification.result != QuietProofVerifyResult::kValidCurrent &&
          out.verification.result != QuietProofVerifyResult::kValidHistorical, "observation accepted or consumed nonce");
    return out.verification;
  };
  using Result = QuietProofVerifyResult;
  auto provider = Provider(expected, now);
  const auto valid = run(provider, config, true, Result::kStateInconclusive, "signature_final_acceptance_pending");
  Check(valid.total_sats == total && valid.claims.size() == expected.claims.size() &&
        provider.observations == 2 && provider.lookups == expected.claims.size(), "checked real sum/observations");
  for (size_t field = 0; field < 10; ++field) {
    provider = Provider(expected, now);
    auto& evidence = provider.evidence[0];
    if (field == 0) ++evidence.amount_sats;
    if (field == 1) evidence.amount_sats = 0;
    if (field == 2) evidence.amount_sats = std::numeric_limits<uint64_t>::max();
    if (field == 3) evidence.amount_sats = kQuietProofMaxMoneySats + 1;
    if (field == 4) evidence.network = QuietProofNetwork::kMainnet;
    if (field == 5) evidence.script_pub_key[0] ^= 1;
    if (field == 6) evidence.script_pub_key[4] ^= 1;
    if (field == 7) evidence.script_pub_key.push_back(0);
    if (field == 8) evidence.status = QuietProofChainStatus::kInconclusive;
    if (field == 9) evidence.status = QuietProofChainStatus::kUnavailable;
    Check(run(provider, config, false, Result::kStateInconclusive, "signature_output_inconclusive").total_sats == 0,
          "unverified/forged amount entered sum");
  }
  provider = Provider(expected, now); provider.evidence[0].status = QuietProofChainStatus::kSpent;
  run(provider, config, false, Result::kSpentAtSnapshot, "signature_output_spent");
  provider = Provider(expected, now); provider.evidence[0].confirmations = 0;
  run(provider, config, false, Result::kStaleSnapshot, "signature_output_confirmations");
  provider = Provider(expected, now);
  auto minimum = config; minimum.minimum_total_sats = total + 1;
  Check(run(provider, minimum, false, Result::kStateInconclusive, "signature_minimum_total").total_sats == total,
        "minimum policy changed checked sum");
  for (size_t field = 0; field < 4; ++field) {
    provider = Provider(expected, now);
    if (field == 0) provider.expected.claims.push_back(provider.expected.claims.back());
    if (field == 1) provider.expected.claims[0].amount_sats = std::numeric_limits<uint64_t>::max();
    if (field == 2) for (auto& claim : provider.expected.claims) claim.amount_sats = kQuietProofMaxMoneySats;
    if (field == 3) std::swap(provider.expected.claims.front(), provider.expected.claims.back());
    run(provider, config, false, Result::kMalformedStatement, "invalid_expected_request");
    Check(provider.lookups == 0 && provider.observations == 0, "malformed claims reached provider");
  }
  for (size_t field = 0; field < 7; ++field) {
    provider = Provider(expected, now);
    if (field == 0) provider.evidence.back().block[0] ^= 1;
    if (field == 1) ++provider.evidence.back().height;
    if (field == 2) provider.before.block[0] ^= 1;
    if (field == 3) ++provider.before.height;
    if (field == 4) provider.after.block[0] ^= 1;
    if (field == 5) ++provider.after.height;
    if (field == 6) provider.evidence[0].block.fill(0);
    run(provider, config, false, Result::kStateInconclusive,
        field == 6 ? "signature_chain_tip_unknown" : "signature_chain_tip_changed");
  }
  for (size_t field = 0; field < 8; ++field) {
    provider = Provider(expected, now);
    auto& node = provider.before;
    if (field == 0) node.status = QuietProofNodeStateStatus::kUnavailable;
    if (field == 1) node.status = QuietProofNodeStateStatus::kMalformed;
    if (field == 2) node.status = QuietProofNodeStateStatus::kChanged;
    if (field == 3) node.network = QuietProofNetwork::kMainnet;
    if (field == 4) node.block.fill(0);
    if (field == 5) node.initial_block_download = true;
    if (field == 6) node.active_chainstate_validated = false;
    if (field == 7) node.tip_time = 0;
    run(provider, config, false, Result::kStateInconclusive,
        field == 5 ? "signature_node_initial_block_download" : field == 6 ? "signature_active_chainstate_unvalidated" :
        field == 7 ? "signature_node_tip_stale" : "signature_node_state_unknown");
  }
  provider = Provider(expected, now); provider.after.initial_block_download = true;
  run(provider, config, false, Result::kStateInconclusive, "signature_node_initial_block_download");
  for (unsigned network = 0; network < 5; ++network) {
    auto request = expected; request.network = static_cast<QuietProofNetwork>(network);
    const auto age = QuietProofSignatureMaxTipAge(request.network);
    Check(age == (network == 0 ? 7200u : network == 3 ? 3600u : 86400u), "explicit network age defaults");
    for (bool stale : {false, true}) {
      provider = Provider(request, now); provider.before.tip_time = provider.after.tip_time = now - age - stale;
      run(provider, config, !stale, Result::kStateInconclusive,
          stale ? "signature_node_tip_stale" : "signature_final_acceptance_pending");
    }
  }
  provider = Provider(expected, now); provider.after.tip_time = now + 7201;
  run(provider, config, false, Result::kStateInconclusive, "signature_node_tip_stale");
  provider = Provider(expected, now); provider.before.tip_time = now - 61;
  auto strict_age = config; strict_age.max_tip_age_seconds = 60;
  run(provider, strict_age, false, Result::kStateInconclusive, "signature_node_tip_stale");
  auto qualified = config; qualified.state_policy = QuietProofSignatureStatePolicy::kQualifiedCurrentProvider;
  provider = Provider(expected, now); provider.before = provider.after = {};
  Check(run(provider, qualified, false, Result::kStateInconclusive, "signature_provider_qualified_quantity").total_sats == total &&
        provider.observations == 0, "qualified provider impersonated validated node");
  auto snapshot = expected; snapshot.has_snapshot = true; snapshot.snapshot.fill(0x34); snapshot.snapshot_height = 10;
  provider = Provider(snapshot, now); provider.historical = true;
  run(provider, config, false, Result::kStateInconclusive, "signature_state_policy_mismatch");
  auto recorded = config; recorded.state_policy = QuietProofSignatureStatePolicy::kRecordedHistoricalSnapshot;
  provider = Provider(snapshot, now); provider.historical = true; provider.before = provider.after = {};
  for (auto& evidence : provider.evidence) { evidence.block = snapshot.snapshot; evidence.height = snapshot.snapshot_height; }
  Check(run(provider, recorded, true, Result::kStateInconclusive, "signature_final_acceptance_pending").total_sats == total &&
        provider.observations == 0, "historical snapshot used current readiness/freshness");
  provider = Provider(snapshot, now); provider.historical = true;
  run(provider, recorded, false, Result::kStateInconclusive, "signature_snapshot_mismatch");
  provider = Provider(expected, now);
  run(provider, recorded, false, Result::kStateInconclusive, "signature_state_policy_mismatch");
  provider = Provider(expected, now); provider.evidence[0].coinbase = true; provider.evidence[0].confirmations = 99;
  auto immature = run(provider, config, true, Result::kStateInconclusive, "signature_final_acceptance_pending");
  Check(immature.total_sats == total && std::string(QuietProofQuantityMaturityLabel(immature.claims)) == "includes_immature_coinbase",
        "immature coinbase was discarded or labelled spendable");
  provider = Provider(expected, now); provider.evidence[0].coinbase = true; provider.evidence[0].confirmations = 100;
  Check(std::string(QuietProofQuantityMaturityLabel(provider.evidence)) == "no_immature_coinbase_observed", "coinbase maturity boundary");
  provider.evidence[0].coinbase_known = false;
  Check(std::string(QuietProofQuantityMaturityLabel(provider.evidence)) == "unknown", "unknown coinbase metadata asserted maturity");
}
}  // namespace
int main(int argc, char** argv) {
  try {
    Check(argc == 2, "fixture path required");
    std::ifstream file(argv[1]);
    nlohmann::json fixture;
    file >> fixture;
    Run(fixture);
    StateChecks(fixture);
    std::cout << "expected-request checks=" << checks << " failed=0 skipped=0\n";
    return 0;
  } catch (const std::exception& error) {
    tracking = false;
    std::cerr << "signature verifier test: " << error.what() << '\n';
    return 1;
  }
}
