#pragma once

#include "preferences.h"
#include "theme.h"
#include "request.h"
#include "request_review.h"
#include "node_settings.h"
#include "node_probe.h"

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
  std::optional<std::string> node_selection;
  void InvalidateNodeProbe() { node_probe.Invalidate(); node_selection.reset(); }
  int64_t now = 0;
  RequestState request;
  RequestChooser chooser;
  std::array<char, 4096> request_path{};
  void OpenRequest(const std::filesystem::path& path);
  std::string preference_status;
  nk_scroll scroll{};
  std::array<struct nk_rect, 301> controls{};
};
void HandleShellKey(ShellState& state, const SDL_KeyboardEvent& key);
void DrawShell(nk_context* context, ShellState& state, int width, int height,
               nk_user_font* body, nk_user_font* heading);
const char* ViewName(View view);
}  // namespace quietproof::gui
