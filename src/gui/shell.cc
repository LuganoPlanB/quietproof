#include "shell.h"

#include <algorithm>
#include <cmath>
#include <string_view>
#include <vector>

namespace quietproof::gui {
namespace {
void ChangeView(ShellState& state, View view) {
  state.view = view;
  state.scroll = {};
}
bool Button(nk_context* context, ShellState& state, int id, const char* label, bool selected = false) {
  const auto saved = context->style.button;
  const auto p = BrandPalette(state.preferences.dark);
  const auto fill = selected ? (state.preferences.dark ? p.highlight : p.strong) : p.panel_strong;
  const auto ink = selected ? (state.preferences.dark ? p.canvas : nk_rgb(255,255,255)) : p.text;
  context->style.button.normal = nk_style_item_color(fill);
  context->style.button.hover = nk_style_item_color(selected ? fill : p.panel);
  context->style.button.active = nk_style_item_color(fill);
  context->style.button.text_normal = ink;
  context->style.button.text_hover = ink;
  context->style.button.text_active = ink;
  context->style.button.border = state.focus == id ? 2 : 1;
  context->style.button.border_color = state.focus == id ? p.focus : p.accent;
  state.controls[id] = nk_widget_bounds(context);
  const bool clicked = nk_button_label(context, label);
  context->style.button = saved;
  if (clicked) state.focus = id;
  return clicked || state.activate == id;
}
void Paragraph(nk_context* context, const char* text, float width) {
  const auto* font = context->style.font;
  // Reserve rows from measured word wrapping, including oversized words.
  const float line_width = std::max(40.0f, width - 16);
  float used = 0;
  int lines = 1;
  std::string_view remaining(text);
  while (!remaining.empty()) {
    const auto end = remaining.find(' ');
    const auto word = remaining.substr(0, end == std::string_view::npos ? remaining.size() : end + 1);
    const float measured = font->width(font->userdata, font->height, word.data(), static_cast<int>(word.size()));
    if (used > 0 && used + measured > line_width) { ++lines; used = 0; }
    lines += static_cast<int>(measured / line_width);
    used += std::fmod(measured, line_width);
    remaining.remove_prefix(word.size());
  }
  nk_layout_row_dynamic(context, lines * (font->height + 4) + 8, 1);
  nk_label_wrap(context, text);
}
void Heading(nk_context* context, const char* text, nk_user_font* font, nk_user_font* body) {
  nk_style_set_font(context, font);
  nk_layout_row_dynamic(context, font->height + 12, 1);
  nk_label(context, text, NK_TEXT_LEFT);
  nk_style_set_font(context, body);
}
}  // namespace

const char* ViewName(View view) {
  switch (view) {
    case View::Request: return "request";
    case View::Node: return "node";
    case View::Result: return "result";
    case View::Settings: return "settings";
  }
  return "request";
}

void HandleShellKey(ShellState& state, const SDL_KeyboardEvent& key) {
  if (key.type != SDL_KEYDOWN || key.repeat) return;
  if (key.keysym.sym == SDLK_ESCAPE && state.view == View::Settings) {
    ChangeView(state, View::Request);
    state.focus = 2;
  }
  if (key.keysym.sym == SDLK_TAB) {
    const std::vector<int> order = state.view == View::Settings ?
      std::vector<int>{1,2,3,4,5,6,7,8,9,11} : std::vector<int>{1,2,3,4,10};
    auto iterator = std::find(order.begin(), order.end(), state.focus);
    int index = iterator == order.end() ? ((key.keysym.mod & KMOD_SHIFT) ? 0 : -1) :
      static_cast<int>(iterator - order.begin());
    const int count = static_cast<int>(order.size());
    index = (index + ((key.keysym.mod & KMOD_SHIFT) ? count - 1 : 1)) % count;
    state.focus = order[index];
    state.reveal_focus = true;
  } else if (key.keysym.sym == SDLK_RETURN || key.keysym.sym == SDLK_KP_ENTER || key.keysym.sym == SDLK_SPACE) {
    state.activate = state.focus;
  } else if (key.keysym.sym == SDLK_PAGEDOWN || key.keysym.sym == SDLK_DOWN) {
    state.scroll.y = std::min(10000u, state.scroll.y + 100);
  } else if (key.keysym.sym == SDLK_PAGEUP || key.keysym.sym == SDLK_UP) {
    state.scroll.y = state.scroll.y > 100 ? state.scroll.y - 100 : 0;
  } else if (key.keysym.sym == SDLK_HOME) {
    state.scroll.y = 0;
  } else if (key.keysym.sym == SDLK_END) {
    state.scroll.y = 10000;
  }
}

void DrawShell(nk_context* context, ShellState& state, int width, int height,
               nk_user_font* body, nk_user_font* heading) {
  ApplyTheme(context, state.preferences.dark);
  nk_style_set_font(context, body);
  const auto p = BrandPalette(state.preferences.dark);
  const float action_height = body->height + 20;
  const float header_height = heading->height + 12;
  const float subtitle_height = body->height + 8;
  const float status_height = body->height * 2 + 8;
  const float panel_height = std::max(100.0f, height - 40 - header_height - subtitle_height -
      action_height * 2 - status_height - 48);
  state.controls.fill(nk_rect(0,0,0,0));
  if (nk_begin(context, "Workspace", nk_rect(0,0,width,height), NK_WINDOW_NO_SCROLLBAR)) {
    const float columns[] = {0.65f,0.35f};
    nk_layout_row(context, NK_DYNAMIC, header_height, 2, columns);
    nk_style_set_font(context, heading);
    nk_label_colored(context, "Quietproof", NK_TEXT_LEFT, state.preferences.dark ? p.highlight : p.strong);
    nk_style_set_font(context, body);
    if (Button(context,state,1,"Display",state.view == View::Settings)) {
      ChangeView(state, state.view == View::Settings ? View::Request : View::Settings);
    }
    nk_layout_row_dynamic(context, subtitle_height, 1);
    nk_label_colored(context, "Proof of wallet ownership", NK_TEXT_LEFT, p.soft_text);
    nk_layout_row_dynamic(context, action_height, 3);
    if (Button(context,state,2,"Request",state.view == View::Request)) ChangeView(state,View::Request);
    if (Button(context,state,3,"Node",state.view == View::Node)) ChangeView(state,View::Node);
    if (Button(context,state,4,"Result",state.view == View::Result)) ChangeView(state,View::Result);

    nk_layout_row_dynamic(context, panel_height, 1);
    if (nk_group_scrolled_begin(context,&state.scroll,"Details",NK_WINDOW_BORDER)) {
      const auto viewport = nk_window_get_content_region(context);
      const float content_width = nk_window_get_content_region_size(context).x;
      if (state.view == View::Settings) {
        nk_layout_row_dynamic(context,body->height + 8,1);
        nk_label(context,"Appearance",NK_TEXT_LEFT);
        nk_layout_row_dynamic(context,action_height,2);
        if (Button(context,state,5,"Light",!state.preferences.dark)) {
          state.preferences.dark=false; state.save_preferences=true;
        }
        if (Button(context,state,6,"Dark",state.preferences.dark)) {
          state.preferences.dark=true; state.save_preferences=true;
        }
        nk_layout_row_dynamic(context,body->height + 8,1);
        nk_label(context,"Text size",NK_TEXT_LEFT);
        nk_layout_row_dynamic(context,action_height,3);
        for (int index=0;index<3;++index) {
          const char* labels[] = {"100%","125%","150%"};
          if (Button(context,state,7+index,labels[index],state.preferences.font_index==index)) {
            state.preferences.font_index=index; state.save_preferences=true;
          }
        }
        Paragraph(context,"Display choices are saved on this device. No wallet credentials or request data are stored in these preferences.",content_width);
        Paragraph(context,"Keyboard: Tab or Shift+Tab moves focus. Enter or Space activates a control. Page Up and Page Down scroll details. Escape closes display settings.",content_width);
        Paragraph(context,"Quietproof uses Plan B colors and the Inter typeface. Your proof workspace stays available without downloading fonts or themes.",content_width);
      } else {
        const char* titles[] = {"Review a request","Connect your node","Your portable proof"};
        const char* descriptions[] = {
          "Start with a proof request. Review what it asks before allowing access to your wallet.",
          "Use a local Bitcoin node and an RPC wallet. Connection status and wallet readiness will appear here.",
          "A completed proof can be saved to a file and shared with your verifier. Nothing is uploaded automatically."};
        const auto index=static_cast<int>(state.view);
        Heading(context,titles[index],heading,body);
        Paragraph(context,descriptions[index],content_width);
        nk_layout_row_dynamic(context,body->height+12,1);
        nk_label_colored(context,"LOCAL  /  PRIVATE",NK_TEXT_LEFT,p.soft_text);
        nk_layout_row_dynamic(context,action_height,1);
        if (Button(context,state,10,state.details ? "Hide guide" : "How it works")) state.details=!state.details;
        if (state.details) {
          const char* guide[] = {
            "1. Review the request. Check its network, verifier, purpose and expiry. Only approve a statement you understand.",
            "2. Connect your node. Your local RPC wallet supplies the key required by a matching request. A connection alone does not establish proof readiness.",
            "3. Approve wallet access. Review the proof request before permitting key access. Wallet passwords belong only in the private unlock dialog.",
            "4. Save your proof. Keep a complete proof file for your verifier. Saving a proof does not publish it or upload it to a service.",
            "A proof attests to its reviewed statement. It does not grant permission to spend coins or replace a verifier's current-chain checks."};
          for (const char* text:guide) Paragraph(context,text,content_width);
        }
      }
      // Use actual laid-out bounds so keyboard navigation also works after
      // manual scrolling and at every supported text size.
      int scroll_delta = 0;
      if (state.reveal_focus && state.focus >= 5 && state.focus <= 10) {
        const auto target = state.controls[state.focus];
        if (target.w > 0) {
          if (target.y < viewport.y) scroll_delta = static_cast<int>(target.y - viewport.y - 4);
          else if (target.y + target.h > viewport.y + viewport.h)
            scroll_delta = static_cast<int>(target.y + target.h - viewport.y - viewport.h + 4);
        }
      }
      nk_group_scrolled_end(context);
      state.scroll.y = static_cast<nk_uint>(std::max(0, static_cast<int>(state.scroll.y) + scroll_delta));
    }
    nk_layout_row_dynamic(context,status_height,1);
    if (state.view == View::Settings) {
      nk_label_wrap(context,state.preference_status.empty() ? "Theme and text size only. No wallet access." : state.preference_status.c_str());
    } else {
      const char* statuses[] = {"No request loaded. Review is unavailable.",
                                "No node configured. Connection test is unavailable.",
                                "No completed proof. Save is unavailable."};
      nk_label_wrap(context,statuses[static_cast<int>(state.view)]);
    }
    nk_layout_row_dynamic(context,action_height,1);
    if (state.view == View::Settings) {
      if (Button(context,state,11,"Done",true)) ChangeView(state,View::Request);
    } else {
      const char* labels[] = {"Review request","Test connection","Save proof"};
      // A disabled affordance has no activation target until its prerequisite exists.
      struct nk_rect bounds;
      nk_widget(&bounds,context);
      state.controls[11] = bounds;
      auto* canvas=nk_window_get_canvas(context);
      nk_fill_rect(canvas,bounds,8,p.panel_strong);
      nk_stroke_rect(canvas,bounds,8,1,p.accent);
      nk_draw_text(canvas,nk_rect(bounds.x+12,bounds.y+(bounds.h-body->height)/2,
                   bounds.w-24,body->height),labels[static_cast<int>(state.view)],
                   nk_strlen(labels[static_cast<int>(state.view)]),body,p.panel_strong,p.soft_text);
    }
  }
  nk_end(context);
  state.activate=0;
  state.reveal_focus=false;
}
}  // namespace quietproof::gui
