#include "shell.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string_view>
#include <vector>

namespace quietproof::gui {
namespace {
void ChangeView(ShellState& state, View view) {
  state.view = view;
  state.editing_path = false;
  if (view != View::Request) state.chooser.Cancel();
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

void ReviewText(nk_context* context, const std::string& text, float width) {
  // Lay out literal UTF-8 one measured line at a time. Long hashes/URLs cannot
  // overflow their row or consume a following control's space.
  const auto* font = context->style.font;
  const float available = std::max(40.0f,width-20);
  for (size_t begin=0; begin<text.size();) {
    size_t end=begin, last_space=begin;
    while (end<text.size()) {
      nk_rune rune = 0;
      const int bytes = nk_utf_decode(text.data()+end,&rune,static_cast<int>(text.size()-end));
      if (bytes <= 0) break;
      const size_t next=end+static_cast<size_t>(bytes);
      if (end>begin && font->width(font->userdata,font->height,text.data()+begin,
          static_cast<int>(next-begin)) > available) break;
      end=next;
      if (rune==' ') last_space=end;
    }
    if (end==begin) break;
    if (end<text.size() && last_space>begin) end=last_space;
    nk_layout_row_dynamic(context,font->height+6,1);
    nk_text(context,text.data()+begin,static_cast<int>(end-begin),NK_TEXT_LEFT);
    begin=end;
  }
}
void ReviewField(nk_context* context, const char* label, const std::string& text, float width) {
  ReviewText(context,label,width);
  ReviewText(context,text,width);
}

void DrawNodeProbe(nk_context* context, ShellState& state, float width, float action_height) {
  if (!state.node_probe.result) return;
  const auto& result = *state.node_probe.result;
  const auto& probe = result.probe;
  Paragraph(context,result.Message().c_str(),width);
  ReviewText(context,std::string("Authentication: ")+(probe.authenticated ? "accepted" :
      result.error.code == proofs::BitcoinRpcErrorCode::kAuthentication ? "rejected; check node cookie" : "not established"),width);
  if (probe.version) ReviewText(context,"Node version: "+std::to_string(*probe.version),width);
  if (probe.chain) ReviewText(context,"Node chain: "+*probe.chain+
      (probe.network_matches == true ? " (matches)" : " (wrong network)"),width);
  if (probe.syncing) ReviewText(context,std::string("Sync: ")+(*probe.syncing ? "initial block download" : "initial block download complete"),width);
  if (probe.export_address_key) ReviewText(context,std::string("Key export capability: ")+
      (*probe.export_address_key ? "exportaddresskey advertised" : "unsupported; Core proving deferred"),width);
  if (probe.wallets_listed) ReviewText(context,"Loaded wallets: "+std::to_string(probe.wallets.size()),width);
  std::optional<std::string> selection;
  for (size_t i=0; i<probe.wallets.size(); ++i) {
    const auto& wallet = probe.wallets[i];
    ReviewText(context,"Wallet "+std::to_string(i+1)+": "+
        (wallet.name.empty() ? "(default unnamed wallet)" : RequestDisplayText(wallet.name)),width);
    ReviewText(context,wallet.private_keys_enabled == false ? "Private keys disabled / watch-only" :
        wallet.private_keys_enabled == true ? "Private keys enabled" : "Wallet capability not checked",width);
    if (wallet.descriptor_wallet) ReviewText(context,*wallet.descriptor_wallet ?
        "Descriptor wallet supported" : "Legacy wallet unsupported by Roots export",width);
    if (wallet.external_signer == true) ReviewText(context,"External-signer wallet unsupported by Roots export",width);
    if (wallet.request_matches) ReviewText(context,*wallet.request_matches ? "Request address and script match" : "Request address/script is ineligible for local export",width);
    if (result.selected_wallet && *result.selected_wallet == wallet.name) ReviewText(context,"Selected wallet",width);
    else if (result.Eligible(wallet)) {
      nk_layout_row_dynamic(context,action_height,1);
      const auto label = "Select wallet "+std::to_string(i+1);
      if (Button(context,state,285+static_cast<int>(i),label.c_str())) selection = wallet.name;
    }
  }
  if (selection) {
    state.CancelWalletInput();
    state.node_probe.Invalidate();
    state.node_selection.swap(selection);
    state.test_node = true;
  }
}

void DrawNodeSettings(nk_context* context, ShellState& state, float width, float action_height) {
  const auto network = state.request.loaded ? state.request.loaded->statement.network : state.node_network;
  ReviewText(context,std::string(state.request.loaded ? "Request network: " : "Test network (no request): ")+
      proofs::QuietProofNetworkName(network),width);
  if (!state.request.loaded) {
    nk_layout_row_dynamic(context,action_height,1);
    if (Button(context,state,277,"Change test network")) {
      state.node_network = static_cast<proofs::QuietProofNetwork>((static_cast<unsigned>(state.node_network)+1)%5);
      state.InvalidateNodeProbe();
    }
  }
  if (state.node_busy) Paragraph(context,"Testing local RPC on the worker. You can keep reviewing or changing settings. Total test budget: 10 seconds.",width);
  if (!state.node_advanced) DrawNodeProbe(context,state,width,action_height);
  std::string error;
  const auto configured = ConfigureNode(state.node_settings,network,&error);
  if (configured) {
    ReviewField(context,"Local RPC endpoint",configured->resolved.url,width);
    ReviewField(context,"Cookie authentication",configured->resolved.cookie_path,width);
    Paragraph(context,"Cookie is read only when connecting and reloaded on each call. It must be owned by you with owner-only permissions.",width);
  } else Paragraph(context,error.c_str(),width);
  nk_layout_row_dynamic(context,action_height,1);
  if (Button(context,state,274,state.node_advanced ? "Hide advanced settings" : "Advanced settings",state.node_advanced)) {
    state.node_advanced = !state.node_advanced;
  }
  if (state.node_advanced) {
    const auto previous = state.node_settings.fields;
    Paragraph(context,"Blank fields use defaults. Port follows the request network unless overridden. Cookie path overrides data directory. Overrides remain until cleared or reset. No passwords are accepted here.",width);
    // Nuklear has one active editor per window. Unfocusing each nonselected
    // field would also clear the selected editor before the next frame.
    if (state.focus < 278 || state.focus > 284) nk_edit_unfocus(context);
    for (size_t i=0; i<state.node_settings.fields.size(); ++i) {
      const auto field = static_cast<NodeField>(i);
      ReviewText(context,NodeFieldLabel(field),width);
      nk_layout_row_dynamic(context,action_height,1);
      const int id = 278+static_cast<int>(i);
      state.controls[id] = nk_widget_bounds(context);
      if (state.focus == id) nk_edit_focus(context,NK_EDIT_ALWAYS_INSERT_MODE);
      const auto edit = nk_edit_string_zero_terminated(context,NK_EDIT_FIELD,
          state.node_settings.Text(field),static_cast<int>(state.node_settings.fields[i].size()),nk_filter_default);
      if (edit & NK_EDIT_ACTIVATED) state.focus = id;
      if (state.focus == id) state.editing_path = (edit & NK_EDIT_ACTIVE) != 0;
    }
    nk_layout_row_dynamic(context,action_height,1);
    if (Button(context,state,275,"Save connection settings")) state.save_node_settings = true;
    nk_layout_row_dynamic(context,action_height,1);
    if (Button(context,state,276,"Reset overrides")) {
      state.node_settings = {};
      state.InvalidateNodeProbe();
      state.save_node_settings = true;
    }
    if (state.node_settings.fields != previous) state.InvalidateNodeProbe();
  }
  if (!state.node_settings_status.empty()) Paragraph(context,state.node_settings_status.c_str(),width);
  Paragraph(context,"Connection success does not establish proof readiness. Wallet passwords belong in the private unlock dialog after explicit approval.",width);
}

void DrawRequestReview(nk_context* context, ShellState& state, float width, float action_height) {
  const auto& statement = state.request.loaded->statement;
  const auto review = InspectRequest(statement);
  ReviewText(context,"Network: "+review.network,width);
  nk_layout_row_dynamic(context,action_height,1);
  const auto toggle = state.claims_expanded ? "Back to summary" :
      "Show "+std::to_string(review.claim_count)+" claim(s)";
  if (Button(context,state,272,toggle.c_str(),state.claims_expanded)) {
    state.claims_expanded = !state.claims_expanded;
    state.scroll = {};
  }
  if (state.claims_expanded) {
    ReviewField(context,"Total claimed amount",RequestAmount(review.total_sats),width);
    for (size_t i=0; i<review.claims.size(); ++i) {
      const auto& claim = review.claims[i];
      ReviewText(context,"Claim "+std::to_string(i+1)+" / "+claim.script_kind,width);
      ReviewText(context,RequestAmount(claim.amount_sats),width);
      ReviewField(context,"Outpoint (transaction ID : output)",claim.txid+":"+std::to_string(claim.vout),width);
      ReviewField(context,"Public key hash (HASH160)",claim.key_hash,width);
      ReviewField(context,"Output script (hex)",claim.script_hex,width);
    }
  } else {
    ReviewField(context,"Verifier (request-provided)",RequestDisplayText(review.verifier),width);
    Paragraph(context,"Identity unverified. URLs are text only.",width);
    ReviewField(context,"Purpose",review.purpose,width);
    ReviewField(context,"Expires at",RequestUtcTime(review.expires_at),width);
    ReviewText(context,RequestWindowMessage(RequestWindowAt(statement,state.now)),width);
    ReviewField(context,"Request created / not before",RequestUtcTime(review.not_before),width);
    ReviewField(context,"Proof created at","None (request only)",width);
    ReviewField(context,"Request format",review.format,width);
    ReviewField(context,"Statement version",std::to_string(review.statement_version),width);
    ReviewField(context,"Claim count",std::to_string(review.claim_count),width);
    std::string kinds;
    for (const auto& kind : review.script_kinds) {
      if (!kinds.empty()) kinds += ", ";
      kinds += kind;
    }
    ReviewField(context,"Script kinds (claim order)",kinds,width);
    if (review.has_snapshot) {
      ReviewField(context,"Requested snapshot height",std::to_string(review.snapshot_height),width);
      ReviewField(context,"Requested snapshot block",review.snapshot,width);
      Paragraph(context,"Snapshot requested. Chain status has not been checked.",width);
    } else Paragraph(context,"No snapshot requested. Current chain status has not been checked.",width);
    if (statement.has_bridge_binding) {
      ReviewField(context,"Bridge destination network",proofs::QuietProofNetworkName(statement.bridge.destination_network),width);
      ReviewField(context,"Bridge asset (request-provided)",RequestDisplayText(statement.bridge.asset_id),width);
      // Binding bytes are already validated by the native request decoder.
      constexpr char digits[]="0123456789abcdef";
      auto hex = [&](const auto& bytes) {
        std::string out;
        for (auto byte : bytes) { out += digits[byte>>4]; out += digits[byte&15]; }
        return out;
      };
      ReviewField(context,"Destination commitment",hex(statement.bridge.destination_commitment),width);
      ReviewField(context,"Bridge lock ID",hex(statement.bridge.lock_id),width);
    }
  }
}
}  // namespace

namespace {
bool WalletReady(const ShellState& state) {
  return state.request.loaded && RequestWindowAt(state.request.loaded->statement,state.now) == RequestWindow::Valid &&
    state.node_probe.result && state.node_probe.result->selected_wallet &&
    state.node_probe.result->complete && state.node_probe.result->probe.syncing == false &&
    !state.node_busy && !state.wallet_busy;
}
void DrawWalletDialog(nk_context* context, ShellState& state, int width, int height,
                      nk_user_font* body, nk_user_font* heading) {
  const auto p = BrandPalette(state.preferences.dark);
  const float action = body->height+22;
  if (nk_begin(context,"Private wallet input",nk_rect(0,0,width,height),NK_WINDOW_NO_SCROLLBAR)) {
    nk_edit_unfocus(context);
    Heading(context,"Unlock selected wallet",heading,body);
    nk_layout_row_dynamic(context,std::max(120.0f,height-action*4-heading->height-90),1);
    if (nk_group_scrolled_begin(context,&state.wallet_scroll,"Unlock information",NK_WINDOW_BORDER)) {
      const float available = nk_window_get_content_region_size(context).x;
      const auto wallet = state.wallet_job && state.wallet_job->wallet ? *state.wallet_job->wallet : "";
      ReviewField(context,"Selected RPC wallet",wallet.empty() ? "Default unnamed wallet" : RequestDisplayText(wallet),available);
      Paragraph(context,"Wallet password only. RPC cookie authentication is separate.",available);
      Paragraph(context,"One 15-second unlock, then relock. Other wallet clients can change this timer.",available);
      Paragraph(context,"Typing only, up to 1024 UTF-8 bytes. Paste, copy, cut and undo are disabled. Backspace removes a character; Delete clears.",available);
      if (!state.wallet_status.empty()) Paragraph(context,state.wallet_status.c_str(),available);
      nk_group_scrolled_end(context);
    }
    nk_layout_row_dynamic(context,body->height+10,1);
    nk_label(context,"Wallet password",NK_TEXT_LEFT);
    nk_layout_row_dynamic(context,action,1);
    // Nuklear sees only a mask. No nk_edit buffer or undo storage ever holds
    // the input. Appending/backspace happens directly from intercepted SDL.
    const std::string mask = state.wallet_input->Size() ? std::string(std::min<size_t>(24,state.wallet_input->Size()),'*') : "Type password here";
    state.focus = 0;
    if (Button(context,state,301,mask.c_str(),state.wallet_focus == 0)) state.wallet_focus = 0;
    nk_layout_row_dynamic(context,action,2);
    if (Button(context,state,302,"Unlock once",state.wallet_focus == 1) && state.wallet_input->Size()) {
      state.wallet_prompt = false; state.private_input_guard = true; state.submit_wallet = true;
    }
    if (Button(context,state,303,"Cancel",state.wallet_focus == 2)) {
      state.CancelWalletInput(); state.wallet_status = "Wallet access canceled. Password cleared.";
    }
    nk_layout_row_dynamic(context,body->height+8,1);
    nk_label_colored(context,"LOCAL  /  PRIVATE",NK_TEXT_LEFT,p.soft_text);
  }
  nk_end(context);
  state.activate = 0;
}
}

void ShellState::OpenRequest(const std::filesystem::path& path) {
  InvalidateNodeProbe();
  request.Open(path);
  const auto text = path.string();
  request_path.fill(0);
  std::memcpy(request_path.data(), text.data(), std::min(text.size(), request_path.size() - 1));
  chooser.Cancel();
  claims_expanded = false;
  view = View::Request;
  scroll = {};
}

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
  if (key.keysym.sym == SDLK_ESCAPE && state.chooser.open) {
    state.chooser.Cancel();
    state.focus = 13;
    state.scroll = {};
    return;
  }
  if (state.editing_path && key.keysym.sym != SDLK_TAB && key.keysym.sym != SDLK_ESCAPE) return;
  if (key.keysym.sym == SDLK_ESCAPE && state.view == View::Settings) {
    ChangeView(state, View::Request);
    state.focus = 2;
  }
  if (key.keysym.sym == SDLK_TAB) {
    state.editing_path = false;
    std::vector<int> order = state.view == View::Settings ?
      std::vector<int>{1,2,3,4,5,6,7,8,9,11} : std::vector<int>{1,2,3,4,10};
    if (state.view == View::Request) {
      order = {1,2,3,4,12,13};
      if (state.chooser.open) {
        order.push_back(14);
        order.push_back(15);
        for (size_t i = 0; i < state.chooser.entries.size(); ++i) order.push_back(16 + static_cast<int>(i));
      } else {
        if (WalletReady(state)) order.push_back(304);
        if (state.wallet_busy) order.push_back(305);
        if (state.request.loaded) order.push_back(272);
        order.push_back(10);
        order.push_back(11);
      }
    } else if (state.view == View::Node) {
      order = {1,2,3,4};
      if (!state.request.loaded) order.push_back(277);
      if (!state.node_advanced && state.node_probe.result) {
        for (size_t i=0; i<state.node_probe.result->probe.wallets.size(); ++i) {
          const auto& wallet = state.node_probe.result->probe.wallets[i];
          if (state.node_probe.result->Eligible(wallet) &&
              state.node_probe.result->selected_wallet != std::optional<std::string>(wallet.name))
            order.push_back(285+static_cast<int>(i));
        }
      }
      order.push_back(274);
      if (state.node_advanced) {
        for (int id=278; id<=284; ++id) order.push_back(id);
        order.push_back(275);
        order.push_back(276);
      }
      order.push_back(10);
      if (!state.node_busy && !state.wallet_busy) order.push_back(11);
    }
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
  if (state.wallet_prompt) { DrawWalletDialog(context,state,width,height,body,heading); return; }
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
        Heading(context,state.view == View::Request && state.chooser.open ? "Choose a file" : titles[index],heading,body);
        if (state.view == View::Request) {
          if (!state.wallet_warning.empty()) Paragraph(context,state.wallet_warning.c_str(),content_width);
          if (WalletReady(state)) {
            nk_layout_row_dynamic(context,action_height,1);
            if (Button(context,state,304,"Prove: approve wallet access")) state.prove_wallet = true;
            Paragraph(context,"Approval permits only this request's matching key. Proof generation follows in a later release.",content_width);
          }
          if (state.wallet_busy) {
            Paragraph(context,"Checking wallet access on the worker. You can cancel; an in-flight RPC finishes before cleanup.",content_width);
            nk_layout_row_dynamic(context,action_height,1);
            if (Button(context,state,305,"Cancel wallet access")) {
              state.CancelWalletInput(); state.wallet_status = "Wallet access canceled. Password cleared.";
            }
          }
          if (!state.wallet_status.empty()) Paragraph(context,state.wallet_status.c_str(),content_width);
          if (!state.chooser.open && state.request.loaded) DrawRequestReview(context,state,content_width,action_height);
          if (!state.chooser.open && !state.request.loaded) Paragraph(context,state.request.error != RequestError::None ? state.request.Message() :
              "Choose a request file or enter its path. Files are checked locally before wallet access.",content_width);
          nk_layout_row_dynamic(context,body->height+8,1);
          nk_label(context,"Request file path",NK_TEXT_LEFT);
          nk_layout_row_dynamic(context,action_height,1);
          state.controls[12] = nk_widget_bounds(context);
          if (state.focus == 12 && !state.editing_path) nk_edit_focus(context,NK_EDIT_ALWAYS_INSERT_MODE);
          if (state.focus != 12) nk_edit_unfocus(context);
          const auto edit = nk_edit_string_zero_terminated(context,static_cast<nk_flags>(NK_EDIT_FIELD) | NK_EDIT_SIG_ENTER,
              state.request_path.data(),static_cast<int>(state.request_path.size()),nk_filter_default);
          state.editing_path = (edit & NK_EDIT_ACTIVE) != 0;
          if (edit & NK_EDIT_ACTIVATED) state.focus = 12;
          if (edit & NK_EDIT_COMMITED) state.OpenRequest(std::filesystem::path(state.request_path.data()));
          nk_layout_row_dynamic(context,action_height,1);
          if (Button(context,state,13,"Browse files")) {
            state.chooser.Browse(std::filesystem::path(state.request_path.data()));
            state.scroll = {};
          }
          if (state.chooser.open) {
            nk_layout_row_dynamic(context,action_height,2);
            if (Button(context,state,14,"Parent folder")) {
              state.chooser.Browse(state.chooser.directory.parent_path());
              state.scroll = {};
            }
            if (Button(context,state,15,"Cancel")) {
              state.chooser.Cancel(); state.scroll = {}; state.focus = 13;
            }
            Paragraph(context,state.chooser.directory.string().c_str(),content_width);
            if (!state.chooser.error.empty()) Paragraph(context,state.chooser.error.c_str(),content_width);
            // Copy a selected path before refreshing the bounded directory list.
            std::optional<FileEntry> selection;
            for (size_t i=0; i<state.chooser.entries.size(); ++i) {
              const auto& entry = state.chooser.entries[i];
              auto label = (entry.directory ? "[Folder] " : "") + entry.path.filename().string();
              nk_layout_row_dynamic(context,action_height,1);
              if (Button(context,state,16+static_cast<int>(i),label.c_str())) selection = entry;
            }
            if (selection) {
              if (selection->directory) state.chooser.Browse(selection->path);
              else state.OpenRequest(selection->path);
              state.scroll = {};
            }
          }
        } else if (state.view == View::Node) DrawNodeSettings(context,state,content_width,action_height);
        else Paragraph(context,descriptions[index],content_width);
        nk_layout_row_dynamic(context,body->height+12,1);
        nk_label_colored(context,"LOCAL  /  PRIVATE",NK_TEXT_LEFT,p.soft_text);
        nk_layout_row_dynamic(context,action_height,1);
        if (!state.chooser.open && Button(context,state,10,state.details ? "Hide guide" : "How it works")) state.details=!state.details;
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
      if (state.reveal_focus && state.focus >= 5 && state.focus != 11) {
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
    if (!state.wallet_warning.empty()) {
      nk_label_wrap(context,"Wallet cleanup needs attention. Open Request for the captured wallet and details.");
    } else if (state.view == View::Settings) {
      nk_label_wrap(context,state.preference_status.empty() ? "Theme and text size only. No wallet access." : state.preference_status.c_str());
    } else {
      const char* statuses[] = {state.request.error != RequestError::None ? "Request rejected. Recovery details above." :
                                state.request.loaded ? RequestWindowMessage(RequestWindowAt(state.request.loaded->statement,state.now)) : "No request loaded. Proving is unavailable.",
                                state.node_busy ? "Testing connection. Wallet secrets are not accessed." :
                                  state.node_probe.result ? "Connection report above. Proving remains unavailable." :
                                  "Connection untested or settings changed. Test again.",
                                "No completed proof. Save is unavailable."};
      nk_label_wrap(context,statuses[static_cast<int>(state.view)]);
    }
    nk_layout_row_dynamic(context,action_height,1);
    if (state.view == View::Settings) {
      if (Button(context,state,11,"Done",true)) ChangeView(state,View::Request);
    } else if (state.view == View::Request) {
      if (Button(context,state,11,"Open request",true)) {
        state.OpenRequest(std::filesystem::path(state.request_path.data()));
      }
    } else if (state.view == View::Node && !state.node_busy && !state.wallet_busy) {
      if (Button(context,state,11,"Test connection",true)) {
        state.test_node = true;
        state.node_advanced = false;
        state.editing_path = false;
        state.scroll = {};
      }
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
