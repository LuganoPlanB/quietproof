#pragma once

#include "node_settings.h"
#include "request.h"
#include "proof_output.h"

#include <atomic>
#include <mutex>
#include <thread>

namespace quietproof::gui {
struct WalletSessionJob;
struct WalletSessionResult;
struct ProofJob;
class PrivateInput;
enum class ProofStage { Preflight, Unlock, Validation, Prove, Completion, Verify };
enum class ProofPhase { None, Circuit, Inputs, Commitment, Generation, Serialization };
struct ProofEvent {
  uint64_t revision = 0;
  ProofStage stage = ProofStage::Preflight;
  ProofPhase phase = ProofPhase::None;
  std::chrono::milliseconds elapsed{};
};
const char* ProofStageName(ProofStage);
const char* ProofPhaseName(ProofPhase);
struct NodeProbeJob {
  uint64_t revision;
  NodeConfiguration configuration;
  std::optional<proofs::BitcoinRpcKeyMatch> match;
  bool has_request = false;
  std::optional<std::string> selected_wallet;
  std::chrono::milliseconds budget{10000};
};
struct NodeProbeResult {
  uint64_t revision = 0;
  proofs::BitcoinRpcProbe probe;
  proofs::BitcoinRpcError error;
  std::optional<std::string> selected_wallet;
  bool has_request = false;
  bool supported_request = false;
  bool complete = false;
  bool Eligible(const proofs::BitcoinRpcWalletProbe&) const;
  std::string Message() const;
};
std::optional<proofs::BitcoinRpcKeyMatch> MatchRequest(const LoadedRequest&);
NodeProbeResult RunNodeProbe(const NodeProbeJob&);
// UI-thread state. Every settings/request/selection change invalidates results.
struct NodeProbeState {
  uint64_t revision = 1;
  std::optional<NodeProbeResult> result;
  void Invalidate();
  bool Accept(NodeProbeResult);
};
// One RPC job maximum, shared by capability probes and wallet sessions. Worker
// owns RPC/password/key; result metadata only crosses to the UI. Destruction
// cancels the wallet session and joins; no detached work or SDL/Nuklear access.
// Probe budget is ten seconds. Wallet shutdown settles its bounded call, then
// attempts captured-wallet cleanup; see wallet_session.h.
class NodeProbeWorker {
 public:
  NodeProbeWorker();
  ~NodeProbeWorker();
  bool Start(NodeProbeJob);
  bool StartWallet(WalletSessionJob, std::unique_ptr<PrivateInput>);
  bool StartProof(ProofJob, std::unique_ptr<PrivateInput>);
  bool StartValidation(ValidationJob, ProofVerifier test_verifier = {});
  bool StartSave(SaveJob, SaveHooks hooks = {});
  std::unique_ptr<SaveResult> PollSave();
  void CancelWallet() { canceled_.store(true); }
  std::unique_ptr<WalletSessionResult> PollWallet();
  std::optional<ProofEvent> PollProgress();
  bool Running() const { return running_.load(); }
  std::optional<NodeProbeResult> Poll();
 private:
  std::atomic<bool> running_{false};
  std::thread thread_;
  std::mutex mutex_;
  std::optional<NodeProbeResult> result_;
  std::unique_ptr<WalletSessionResult> wallet_result_;
  std::unique_ptr<SaveResult> save_result_;
  // Coalesce progress: one fixed-size event maximum, never a growing queue.
  std::optional<ProofEvent> progress_;
  std::atomic<bool> canceled_{false};
};
}  // namespace quietproof::gui
