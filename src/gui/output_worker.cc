#include "node_probe.h"
#include "wallet_session.h"

#include <fstream>

namespace quietproof::gui {
bool NodeProbeWorker::StartSave(SaveJob job, SaveHooks hooks) {
  if (running_.load()) return false;
  if (thread_.joinable()) thread_.join();
  { std::lock_guard lock(mutex_); result_.reset(); wallet_result_.reset(); save_result_.reset(); progress_.reset(); }
  canceled_.store(false); running_.store(true);
  try {
    auto allocated = std::make_unique<SaveResult>();
    thread_ = std::thread([this,job=std::move(job),hooks=std::move(hooks),result=std::move(allocated)]() mutable {
      try { *result = RunSave(job,[this] { return canceled_.load(); },hooks); }
      catch (...) { result->revision = job.revision; result->attempt = job.attempt; result->status = SaveStatus::Failed; }
      { std::lock_guard lock(mutex_); save_result_ = std::move(result); }
      running_.store(false);
    });
  } catch (...) { running_.store(false); return false; }
  return true;
}
std::unique_ptr<SaveResult> NodeProbeWorker::PollSave() {
  std::lock_guard lock(mutex_); return std::move(save_result_);
}
bool NodeProbeWorker::StartValidation(ValidationJob job, ProofVerifier test_verifier) {
  if (running_.load()) return false;
  if (thread_.joinable()) thread_.join();
  { std::lock_guard lock(mutex_); result_.reset(); wallet_result_.reset(); save_result_.reset(); progress_.reset(); }
  canceled_.store(false); running_.store(true);
  try {
    auto allocated = std::make_unique<WalletSessionResult>();
    thread_ = std::thread([this,job=std::move(job),test_verifier=std::move(test_verifier),result=std::move(allocated)]() mutable {
      result->revision = job.revision;
      try {
        { std::lock_guard lock(mutex_); progress_ = ProofEvent{job.revision,ProofStage::Verify}; }
        std::ifstream input(job.proof_path,std::ios::binary);
        std::vector<uint8_t> wire; std::array<char,65536> block{};
        while (input && !canceled_.load()) {
          input.read(block.data(),block.size()); const auto n = input.gcount();
          if (n < 0 || static_cast<size_t>(n)>proofs::kQuietProofMaxEnvelopeBytes-wire.size()) break;
          wire.insert(wire.end(),block.data(),block.data()+n);
        }
        proofs::QuietProofEnvelopeV1 envelope;
        if (!canceled_.load() && input.eof() && proofs::DecodeQuietProofEnvelope(wire,&envelope)) {
          auto validated = ProofValidation::Run(job.request,envelope,[this] { return canceled_.load(); },test_verifier);
          result->verified = std::move(validated.proof);
          result->error.message = std::move(validated.error);
        } else result->error.message = "Public proof fixture could not be read or decoded";
        result->status = canceled_.load() ? WalletSessionStatus::Canceled : result->verified ? WalletSessionStatus::Proved : WalletSessionStatus::Failed;
      } catch (...) { result->error.message = "Public proof validation failed"; }
      { std::lock_guard lock(mutex_); wallet_result_ = std::move(result); }
      running_.store(false);
    });
  } catch (...) { running_.store(false); return false; }
  return true;
}
}  // namespace quietproof::gui
