// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Cryptographic-only test oracle for CLI public output; no funds acceptance.
#include <fstream>
#include <iostream>
#include <filesystem>
#include <stdexcept>
#include <unistd.h>
#include "quietproof/nonce_store.h"
#include "poksig/verifier.h"
#include "quietproof/envelope.h"
#include "quietproof/signature_verifier.h"
namespace {
using namespace proofs;
unsigned checks = 0;
void Check(bool condition, const char* message) {
  ++checks;
  if (!condition) throw std::runtime_error(message);
}
bool Read(const char* path, size_t maximum, std::vector<uint8_t>* bytes) {
  std::ifstream input(path, std::ios::binary);
  std::array<char,4096> buffer{};
  while (input) {
    input.read(buffer.data(), buffer.size());
    const auto size = input.gcount();
    if (size < 0 || static_cast<size_t>(size) > maximum - bytes->size()) return false;
    bytes->insert(bytes->end(), buffer.data(), buffer.data()+size);
  }
  return input.eof();
}

// Test-only fabricated chain observations exercise acceptance ordering with a
// real cryptographic proof. Production Core wallet-to-funds coverage is separate.
class AcceptanceProvider final : public QuietProofChainProvider {
 public:
  QuietProofSignatureStatementV4 statement;
  uint64_t* now = nullptr;
  uint64_t tip_time = 0;
  bool bad_amount = false, expire_on_lookup = false, stale_on_lookup = false;
  unsigned lookups = 0;
  QuietProofProviderKind kind() const override { return QuietProofProviderKind::kCurrentTip; }
  QuietProofNodeState ObserveNodeState() override {
    QuietProofNodeState state;
    state.status = QuietProofNodeStateStatus::kObserved; state.network = statement.network;
    state.block.fill(1); state.height = 1000; state.tip_time = tip_time;
    state.initial_block_download = false; state.active_chainstate_validated = true;
    return state;
  }
  QuietProofChainEvidence Lookup(const QuietProofChainRequest& request) override {
    ++lookups;
    const auto it = std::find_if(statement.claims.begin(), statement.claims.end(), [&](const auto& claim) {
      return claim.txid == request.txid && claim.vout == request.vout;
    });
    Check(it != statement.claims.end() && request.network == statement.network && !request.has_snapshot,
          "acceptance requested wrong real outpoint");
    if (expire_on_lookup) *now = statement.expires_at;
    if (stale_on_lookup) *now = tip_time + 2;
    QuietProofChainEvidence out;
    out.status = QuietProofChainStatus::kUnspent; out.network = statement.network;
    out.block.fill(1); out.height = 1000; out.confirmations = 100;
    out.amount_sats = it->amount_sats + bad_amount; out.coinbase_known = true;
    out.script_pub_key = it->script_kind == QuietProofScriptKind::kP2pkh ?
        std::vector<uint8_t>{0x76,0xa9,0x14} : std::vector<uint8_t>{0,20};
    out.script_pub_key.insert(out.script_pub_key.end(), it->program.begin(), it->program.end());
    if (it->script_kind == QuietProofScriptKind::kP2pkh) out.script_pub_key.insert(out.script_pub_key.end(), {0x88,0xac});
    return out;
  }
};
void AcceptanceChecks(const std::vector<uint8_t>& request, const PoKSigProofV1& proof,
                      const QuietProofSignatureStatementV4& statement, uint64_t start) {
  Check(!statement.has_snapshot && start + 10 < statement.expires_at, "current long-lived test request required");
  char pattern[] = "/tmp/quietproof-signature-acceptance.XXXXXX";
  const char* created = mkdtemp(pattern);
  Check(created != nullptr, "acceptance directory");
  const std::filesystem::path directory(created);
  struct Cleanup { std::filesystem::path path; ~Cleanup() { std::error_code error; std::filesystem::remove_all(path,error); } } cleanup{directory};
  const auto path = directory/"nonces";
  uint64_t now = start;
  AcceptanceProvider provider; provider.statement = statement; provider.now = &now; provider.tip_time = start;
  QuietProofSignatureVerifierConfig config;
  config.modes.allow_signature_possession = true; config.policy.verifier = statement.verifier;
  config.policy.purpose = statement.purpose; config.policy.now = start;
  config.clock = [&](uint64_t* time) { *time = now; return true; };
  config.provider = &provider;
  unsigned old_consume = 0;
  config.policy.consume_nonce = [&](const auto&) { ++old_consume; return true; };
  QuietProofNonceFileAcceptanceStore store(path.string());
  QuietProofSignatureVerificationTimes times;
  const auto verify = [&](QuietProofVerifyResult result, const char* wanted) {
    const char* reason = nullptr;
    const auto out = VerifyQuietProofSignatureDetailed(request, proof.bytes, config, &times, &reason);
    Check(out.result == result && (wanted ? reason && std::string(reason) == wanted : reason == nullptr), "actual proof acceptance result");
    Check(old_consume == 0, "old consume callback authorized signature request");
    return out;
  };
  verify(QuietProofVerifyResult::kStateInconclusive, "signature_final_acceptance_unavailable");
  Check(!std::filesystem::exists(path) && !times.accepted_at, "missing atomic capability consumed nonce");
  config.final_acceptance_store = &store;
  unsigned clock_calls = 0;
  config.clock = [&](uint64_t* time) { *time = ++clock_calls == 1 ? start : statement.expires_at; return true; };
  provider.lookups = 0;
  verify(QuietProofVerifyResult::kInvalidProof, "signature_request_expired");
  Check(clock_calls == 2 && provider.lookups == 0 && !std::filesystem::exists(path) &&
        times.proof_checked_at == statement.expires_at && !times.chain_observed_at && !times.accepted_at,
        "expiry during actual proof work reached chain/store");
  config.clock = [&](uint64_t* time) { *time = now; return true; };
  provider.expire_on_lookup = true;
  verify(QuietProofVerifyResult::kInvalidProof, "signature_request_expired");
  Check(!std::filesystem::exists(path) && times.chain_observed_at == statement.expires_at && !times.accepted_at,
        "expiry during RPC consumed nonce");
  now = start; provider.expire_on_lookup = false; provider.stale_on_lookup = true;
  config.max_tip_age_seconds = 1;
  verify(QuietProofVerifyResult::kStateInconclusive, "signature_node_tip_stale");
  Check(times.chain_observed_at == start + 2 && !std::filesystem::exists(path), "tip age reused pre-proof time");
  now = start; provider.stale_on_lookup = false; config.max_tip_age_seconds = 0;
  provider.bad_amount = true;
  verify(QuietProofVerifyResult::kStateInconclusive, "signature_output_inconclusive");
  Check(!std::filesystem::exists(path), "failed state consumed nonce");
  provider.bad_amount = false;
  now = start + 5;
  const auto accepted = verify(QuietProofVerifyResult::kValidCurrent, nullptr);
  uint64_t total = 0; for (const auto& claim : statement.claims) total += claim.amount_sats;
  Check(accepted.total_sats == total && times.chain_observed_at == start + 5 && times.accepted_at == start + 5 &&
        std::filesystem::file_size(path) == 65, "checked real quantity/final time/persistence");
  verify(QuietProofVerifyResult::kInvalidProof, "signature_request_replayed");
  Check(!times.accepted_at && !QuietProofConsumeNonceFile(path.string(), statement.nonce), "cross-mode replay namespace changed");
  std::cout << "actual-proof acceptance checks=" << checks << " failed=0 skipped=0\n";
}
}
int main(int argc, char** argv) {
  using namespace proofs;
  try {
    if (argc != 3) return 1;
    std::vector<uint8_t> request;
    PoKSigProofV1 proof;
    if (!Read(argv[1], kQuietProofMaxStatementBytes, &request) ||
        !Read(argv[2], kQuietProofMaxEnvelopeBytes, &proof.bytes)) return 1;
    QuietProofSignatureStatementV4 statement;
    if (!DecodeQuietProofSignatureStatement(request, &statement)) return 1;
    QuietProofSignatureVerifierConfig config;
    config.modes.allow_signature_possession = true;
    config.policy.verifier = statement.verifier;
    config.policy.purpose = statement.purpose;
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if (now < 0) return 1;
    config.policy.now = static_cast<uint64_t>(now);
    const char* reason = nullptr;
    const auto result = VerifyQuietProofSignatureWithReason(request, proof.bytes, config, &reason);
    if (result.result != QuietProofVerifyResult::kStateInconclusive || !reason ||
        std::string(reason) != "signature_funds_checks_pending" || result.total_sats || !result.claims.empty()) return 1;
    AcceptanceChecks(request, proof, statement, static_cast<uint64_t>(now));
    std::cout << "signature proof cryptography verified; funds acceptance separate\n";
    return 0;
  } catch (...) { return 1; }
}
