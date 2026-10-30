#include "node_probe.h"

#include <algorithm>

namespace quietproof::gui {
std::optional<proofs::BitcoinRpcKeyMatch> MatchRequest(const LoadedRequest& request) {
  if (request.statement.claims.empty()) return {};
  proofs::BitcoinRpcKeyMatch match;
  match.program = request.statement.claims[0].program;
  for (const auto& claim : request.statement.claims) {
    if (claim.program != match.program ||
        (claim.script_kind != proofs::QuietProofScriptKind::kP2pkh &&
         claim.script_kind != proofs::QuietProofScriptKind::kP2wpkh)) return {};
    if (std::find(match.script_kinds.begin(),match.script_kinds.end(),claim.script_kind) == match.script_kinds.end())
      match.script_kinds.push_back(claim.script_kind);
  }
  return match;
}
bool NodeProbeResult::Eligible(const proofs::BitcoinRpcWalletProbe& wallet) const {
  return complete && probe.network_matches == true && probe.export_address_key == true &&
      wallet.private_keys_enabled == true && wallet.descriptor_wallet == true && wallet.external_signer == false &&
      wallet.error.code == proofs::BitcoinRpcErrorCode::kNone &&
      (!has_request || (supported_request && wallet.request_matches == true));
}
std::string NodeProbeResult::Message() const {
  if (error.code != proofs::BitcoinRpcErrorCode::kNone) {
    using Code = proofs::BitcoinRpcErrorCode;
    switch (error.code) {
      case Code::kConnection: return "Connection failed. Start the local node with server=1 and check its host and RPC port.";
      case Code::kTimeout: return "Connection test timed out. Check node responsiveness or adjust the advanced timeouts. Total test budget is 10 seconds.";
      case Code::kAuthentication: return "Authentication rejected. Check that the cookie path belongs to this running node and network; cookies rotate on restart.";
      case Code::kCookie: return "Cookie unavailable. Check the data directory or cookie override and owner-only file permissions.";
      case Code::kMalformed: return "Malformed node response. Check that this endpoint runs a compatible Bitcoin Core or Roots JSON-RPC server.";
      case Code::kRpc: return "Node status RPC failed. Check loaded wallets and node compatibility, then test again.";
      default: return error.message;
    }
  }
  if (probe.network_matches != true) return "Wrong node network. Select a node matching the request.";
  if (probe.syncing == true) return "Node is syncing. Wait for initial block download to finish, then test again.";
  if (probe.export_address_key != true)
    return "Proving unsupported: exportaddresskey is absent. Use compatible Roots. Full Core proving is deferred.";
  if (has_request && !supported_request) return "Request needs unsupported or multiple distinct keys. Proving is unavailable.";
  if (!selected_wallet) {
    const auto eligible = std::count_if(probe.wallets.begin(),probe.wallets.end(),[&](const auto& wallet) { return Eligible(wallet); });
    if (eligible > 1) return "Multiple eligible wallets. Select one below; the selection will be checked again.";
    if (probe.wallets.empty()) return "No loaded wallets. Load a wallet in your node, then test again.";
    if (eligible == 0) return "No eligible wallet: key missing, watch-only or unsupported. See wallet details below.";
    return "Selected wallet unavailable or ineligible. Choose an eligible wallet below.";
  }
  if (!has_request) return "Wallet selected. Load a request to check address, script and network.";
  return "Wallet matches the request. Proving still needs explicit approval and later checks.";
}
NodeProbeResult RunNodeProbe(const NodeProbeJob& job) {
  NodeProbeResult result;
  result.revision = job.revision;
  result.has_request = job.has_request;
  result.supported_request = job.match.has_value();
  proofs::BitcoinCoreRpc rpc(job.configuration.rpc);
  result.complete = rpc.Probe(job.match,&result.probe,&result.error,job.budget);
  std::vector<std::string> eligible;
  for (const auto& wallet : result.probe.wallets)
    if (result.Eligible(wallet)) eligible.push_back(wallet.name);
  auto selection = job.selected_wallet;
  if (!selection && !job.configuration.wallet.empty()) selection = job.configuration.wallet;
  if (selection) {
    if (std::find(eligible.begin(),eligible.end(),*selection) != eligible.end()) result.selected_wallet = selection;
  } else if (eligible.size() == 1) result.selected_wallet = eligible[0];
  return result;
}
void NodeProbeState::Invalidate() { ++revision; result.reset(); }
bool NodeProbeState::Accept(NodeProbeResult value) {
  if (value.revision != revision) return false;
  result = std::move(value);
  return true;
}
NodeProbeWorker::~NodeProbeWorker() { if (thread_.joinable()) thread_.join(); }
bool NodeProbeWorker::Start(NodeProbeJob job) {
  if (running_.load()) return false;
  if (thread_.joinable()) thread_.join();
  { std::lock_guard lock(mutex_); result_.reset(); }
  running_.store(true);
  try {
    thread_ = std::thread([this,job=std::move(job)] {
      NodeProbeResult value;
      try { value = RunNodeProbe(job); }
      catch (...) {
        value.revision = job.revision;
        value.error = {proofs::BitcoinRpcErrorCode::kConnection,0,{},"Connection test failed; private diagnostics suppressed"};
      }
      { std::lock_guard lock(mutex_); result_ = std::move(value); }
      running_.store(false);
    });
  } catch (...) { running_.store(false); return false; }
  return true;
}
std::optional<NodeProbeResult> NodeProbeWorker::Poll() {
  std::lock_guard lock(mutex_);
  auto result = std::move(result_);
  result_.reset();
  return result;
}
}  // namespace quietproof::gui
