#pragma once

#include "preferences.h"
#include "theme.h"
#include "request.h"
#include "request_review.h"
#include "node_settings.h"
#include "node_probe.h"
#include "wallet_session.h"
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
  bool wallet_prompt = false;
  bool private_input_guard = false;
  int wallet_focus = 0;
  nk_scroll wallet_scroll{};
  std::unique_ptr<PrivateInput> wallet_input = std::make_unique<PrivateInput>();
  std::optional<WalletSessionJob> wallet_job;
  std::string wallet_status;
  std::string wallet_warning;
  void CancelWalletInput() {
    private_input_guard = private_input_guard || wallet_prompt || wallet_busy || wallet_input->Size() != 0;
    wallet_input->Clear(); wallet_prompt = false; submit_wallet = false;
    cancel_wallet = true; wallet_job.reset();
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
  std::array<struct nk_rect, 306> controls{};
};
void HandleShellKey(ShellState& state, const SDL_KeyboardEvent& key);
void DrawShell(nk_context* context, ShellState& state, int width, int height,
               nk_user_font* body, nk_user_font* heading);
const char* ViewName(View view);
}  // namespace quietproof::gui
