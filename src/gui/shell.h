#pragma once

#include "preferences.h"
#include "theme.h"
#include "request.h"
#include "request_review.h"
#include "node_settings.h"
#include "node_probe.h"
#include "wallet_session.h"
#include "proof_session.h"
#include "private_input.h"

#include <array>
#include <string>

namespace quietproof::gui {
enum class View { Request, Node, Result, Settings };
struct ShellState {
  DisplayPreferences preferences;
  View view = View::Request;
  int focus = 2;
  int activate = 0;
  bool details = false;
  bool save_preferences = false;
  bool reveal_focus = false;
  bool editing_path = false;
  bool claims_expanded = false;
  bool node_advanced = false;
  bool save_node_settings = false;
  NodeSettings node_settings;
  proofs::QuietProofNetwork node_network = proofs::QuietProofNetwork::kMainnet;
  std::string node_settings_status;
  NodeProbeState node_probe;
  bool node_busy = false;
  bool test_node = false;
  bool prove_wallet = false;
  bool submit_wallet = false;
  bool cancel_wallet = false;
  bool wallet_busy = false;
  bool wallet_cancel_pending = false;
  std::optional<ProofEvent> proof_progress;
  std::chrono::steady_clock::time_point proof_started{};
  std::shared_ptr<const VerifiedProof> completed_proof;
  std::optional<ValidationJob> validation_job;
  bool save_dialog = false, save_busy = false, save_file = false, cancel_save = false;
  uint64_t save_attempt = 1;
  std::array<char,4096> save_path{};
  std::optional<OutputIdentity> save_confirm;
  std::string save_status, save_notice;
  void InvalidateSaveDestination() {
    ++save_attempt; save_confirm.reset(); save_status.clear();
    if (save_busy) cancel_wallet = true;
  }
  void AcceptSaveResult(const SaveResult& result) {
    save_busy = false;
    const bool current = completed_proof && result.revision == node_probe.revision && result.attempt == save_attempt;
    const auto path = RequestDisplayText(result.destination.string());
    if (current) {
      save_status = result.message+" Destination: "+path;
      scroll = {}; editing_path = false; focus = 307;
      save_confirm = result.status == SaveStatus::NeedsOverwrite ? result.existing : std::nullopt;
      if (save_confirm) focus = 308;
      if (result.committed) save_dialog = false;
    } else if (result.committed) save_notice = "Previous request's verified proof was saved before cancellation to "+path;
    if (result.cleanup_failed) save_notice = "Temporary output cleanup needs attention in "+RequestDisplayText(result.destination.parent_path().string());
  }
  bool wallet_prompt = false;
  bool private_input_guard = false;
  int wallet_focus = 0;
  nk_scroll wallet_scroll{};
  std::unique_ptr<PrivateInput> wallet_input = std::make_unique<PrivateInput>();
  std::optional<WalletSessionJob> wallet_job;
  std::string wallet_status;
  std::string wallet_warning;
  // Validation/proving is emitted only after password consumption and relock.
  // Keep guarding input until the UI has drained that final private frame.
  bool WalletPrivatePhase() const {
    return wallet_busy && (!proof_progress || proof_progress->stage < ProofStage::Validation);
  }
  void CancelWalletInput() {
    private_input_guard = private_input_guard || wallet_prompt || wallet_busy || wallet_input->Size() != 0;
    wallet_input->Clear(); wallet_prompt = false; submit_wallet = false;
    cancel_wallet = true; wallet_job.reset();
    completed_proof.reset();
    validation_job.reset(); InvalidateSaveDestination(); save_dialog = false; save_path.fill(0);
    wallet_cancel_pending = wallet_busy;
    if (!wallet_busy) proof_progress.reset();
    wallet_status.clear();
  }
  std::optional<std::string> node_selection;
  void InvalidateNodeProbe() { node_probe.Invalidate(); node_selection.reset(); CancelWalletInput(); }
  int64_t now = 0;
  RequestState request;
  RequestChooser chooser;
  std::array<char, 4096> request_path{};
  void OpenRequest(const std::filesystem::path& path);
  std::string preference_status;
  nk_scroll scroll{};
  std::array<struct nk_rect, 310> controls{};
};
void HandleShellKey(ShellState& state, const SDL_KeyboardEvent& key);
void DrawShell(nk_context* context, ShellState& state, int width, int height,
               nk_user_font* body, nk_user_font* heading);
const char* ViewName(View view);
}  // namespace quietproof::gui
