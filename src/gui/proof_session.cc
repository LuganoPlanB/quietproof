#include "proof_session.h"
#include "private_input.h"
#include "pokc/prover.h"

#include <string_view>

namespace quietproof::gui {
const char* ProofStageName(ProofStage stage) {
  switch (stage) {
    case ProofStage::Preflight: return "Rechecking request and wallet";
    case ProofStage::Unlock: return "Unlocking selected wallet";
    case ProofStage::Validation: return "Validating request-matching key";
    case ProofStage::Prove: return "Generating proof";
    case ProofStage::Completion: return "Proof cryptographically verified";
    case ProofStage::Verify: return "Verifying exact reviewed request and proof";
  }
  return "Proof work";
}
const char* ProofPhaseName(ProofPhase phase) {
  switch (phase) {
    case ProofPhase::None: return "";
    case ProofPhase::Circuit: return "building circuit";
    case ProofPhase::Inputs: return "preparing proof inputs";
    case ProofPhase::Commitment: return "computing commitment";
    case ProofPhase::Generation: return "generating proof";
    case ProofPhase::Serialization: return "serializing proof";
  }
  return "";
}
WalletSessionResult RunProofSession(const ProofJob& job, std::span<const char> password,
    const std::function<bool()>& canceled, const std::function<int64_t()>& clock,
    const std::function<void()>& password_used, const ProofProgress& progress,
    const ProofGenerator& generator, const ProofVerifier& test_verifier) {
  const auto started = std::chrono::steady_clock::now();
  auto emit = [&](ProofStage stage, ProofPhase phase = ProofPhase::None) {
    if (progress) progress({job.session.revision,stage,phase,
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started)});
  };
  auto result = RunWalletSession(job.session,password,canceled,clock,password_used,
      [&](ProofStage stage) { emit(stage); });
  if (result.status != WalletSessionStatus::Acquired || !result.key) return result;
  auto current = [&] {
    if (canceled()) {
      result.status = WalletSessionStatus::Canceled;
      return false;
    }
    if (RequestWindowAt(job.session.request->statement,clock()) != RequestWindow::Valid) {
      result.status = WalletSessionStatus::Failed;
      result.error = {proofs::BitcoinRpcErrorCode::kConfiguration,0,{},"Request expired during proof work. Start with a valid request"};
      return false;
    }
    return true;
  };
  try {
    if (current()) {
      emit(ProofStage::Prove);
      if (!current()) { result.key.reset(); return result; }
      // PoKCProve has no cancellation primitive. Its progress callback only
      // observes stages: never throw from it or terminate a secret-owning thread.
      // A cancel finishes this entire native call, then discards its output.
      auto proof = std::make_unique<proofs::QuietProofEnvelopeV1>();
      const auto phase = [&](ProofPhase value) { emit(ProofStage::Prove,value); };
      bool proved;
      if (generator) proved = generator(result.key->Bytes(),job.session.request->statement,proof.get(),phase);
      else proved = proofs::PoKCProve(result.key->Bytes(),job.session.request->statement,proof.get(),[&](const char* name) {
        for (auto value : {ProofPhase::Circuit,ProofPhase::Inputs,ProofPhase::Commitment,
                           ProofPhase::Generation,ProofPhase::Serialization})
          if (std::string_view(name) == ProofPhaseName(value)) { phase(value); break; }
      });
      result.key.reset();
      if (current()) {
        if (proved) {
          emit(ProofStage::Verify);
          auto validated = ProofValidation::Run(job.session.request,*proof,canceled,test_verifier);
          if (current()) {
            if (validated.proof) {
              result.status = WalletSessionStatus::Proved;
              result.verified = std::move(validated.proof);
              result.proof = std::move(proof);
              emit(ProofStage::Completion);
            } else {
              result.status = WalletSessionStatus::Failed;
              result.error = {proofs::BitcoinRpcErrorCode::kConfiguration,0,{},std::move(validated.error)};
            }
          }
        } else {
          result.status = WalletSessionStatus::Failed;
          result.error = {proofs::BitcoinRpcErrorCode::kConfiguration,0,{},"Proof generation failed. Start a new attempt explicitly"};
        }
      }
    }
  } catch (...) {
    result.status = canceled() ? WalletSessionStatus::Canceled : WalletSessionStatus::Failed;
    result.error = {proofs::BitcoinRpcErrorCode::kConfiguration,0,{},"Proof generation failed; private diagnostics suppressed"};
  }
  result.key.reset();
  return result;
}
bool NodeProbeWorker::StartProof(ProofJob job, std::unique_ptr<PrivateInput> password) {
  if (running_.load() || !password) return false;
  if (thread_.joinable()) thread_.join();
  { std::lock_guard lock(mutex_); result_.reset(); wallet_result_.reset(); save_result_.reset(); progress_.reset(); }
  canceled_.store(false);
  running_.store(true);
  try {
    thread_ = std::thread([this,job=std::move(job),password=std::move(password)] {
      auto result = std::make_unique<WalletSessionResult>();
      try {
        *result = RunProofSession(job,password->Bytes(),[this] { return canceled_.load(); },[] {
          return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        },[&] { password->Clear(); },[this](const ProofEvent& value) {
          std::lock_guard lock(mutex_); progress_ = value;
        });
      } catch (...) {
        result->revision = job.session.revision; result->wallet = job.session.wallet;
        result->error = {proofs::BitcoinRpcErrorCode::kConfiguration,0,{},"Proof worker failed; private diagnostics suppressed"};
      }
      password->Clear(); result->key.reset(); result->proof.reset();
      { std::lock_guard lock(mutex_); wallet_result_ = std::move(result); }
      running_.store(false);
    });
  } catch (...) { running_.store(false); return false; }
  return true;
}
std::optional<ProofEvent> NodeProbeWorker::PollProgress() {
  std::lock_guard lock(mutex_);
  auto value = progress_; progress_.reset(); return value;
}
}  // namespace quietproof::gui
