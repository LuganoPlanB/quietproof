#pragma once

#include "preferences.h"
#include "theme.h"

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
  std::string preference_status;
  nk_scroll scroll{};
  std::array<struct nk_rect, 12> controls{};
};
void HandleShellKey(ShellState& state, const SDL_KeyboardEvent& key);
void DrawShell(nk_context* context, ShellState& state, int width, int height,
               nk_user_font* body, nk_user_font* heading);
const char* ViewName(View view);
}  // namespace quietproof::gui
