#pragma once

#include "node_settings.h"
#include "request.h"

#include <atomic>
#include <mutex>
#include <thread>

namespace quietproof::gui {
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
// One job and one result maximum. Worker constructs/owns its sequential RPC.
// Destruction joins; no detached work or SDL/Nuklear access. Total RPC budget
// bounds shutdown (default ten seconds), including every enumerated wallet.
class NodeProbeWorker {
 public:
  ~NodeProbeWorker();
  bool Start(NodeProbeJob);
  bool Running() const { return running_.load(); }
  std::optional<NodeProbeResult> Poll();
 private:
  std::atomic<bool> running_{false};
  std::thread thread_;
  std::mutex mutex_;
  std::optional<NodeProbeResult> result_;
};
}  // namespace quietproof::gui
