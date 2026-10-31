#include "application.h"
#include "asset_path.h"
#include "nuklear_config.h"
#include "shell.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace quietproof::gui {
namespace {
[[noreturn]] void SdlError(const char* operation) {
  throw std::runtime_error(std::string(operation) + ": " + SDL_GetError());
}
struct SdlSession {
  SdlSession() {
    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
      const std::string message = SDL_GetError();
      SDL_Quit();
      throw std::runtime_error("Initialize SDL: " + message);
    }
  }
  ~SdlSession() { SDL_Quit(); }
  SdlSession(const SdlSession&) = delete;
  SdlSession& operator=(const SdlSession&) = delete;
};
struct NuklearSession {
  NuklearSession(SDL_Window* window, SDL_Renderer* renderer)
      : context(nk_sdl_init(window, renderer)) {}
  ~NuklearSession() { nk_sdl_shutdown(); }
  NuklearSession(const NuklearSession&) = delete;
  NuklearSession& operator=(const NuklearSession&) = delete;
  nk_context* context;
};

std::filesystem::path FontPath() {
  std::unique_ptr<char, decltype(&SDL_free)> base(SDL_GetBasePath(), SDL_free);
  if (!base) return {};
  const std::filesystem::path directory(base.get());
  for (const auto& path : {directory / "quietproof-gui-assets/Inter.ttf",
                           directory / QUIETPROOF_GUI_ASSET_PATH / "Inter.ttf"}) {
    std::error_code error;
    if (std::filesystem::is_regular_file(path, error)) return path;
  }
  return {};
}

void Capture(SDL_Renderer* renderer, const std::filesystem::path& path) {
  int width = 0, height = 0;
  if (SDL_GetRendererOutputSize(renderer, &width, &height) != 0) SdlError("Read renderer size");
  std::unique_ptr<SDL_Surface, decltype(&SDL_FreeSurface)> surface(
      SDL_CreateRGBSurfaceWithFormat(0, width, height, 32, SDL_PIXELFORMAT_ARGB8888),
      SDL_FreeSurface);
  if (!surface) SdlError("Create screenshot");
  if (SDL_RenderReadPixels(renderer, nullptr, surface->format->format,
                           surface->pixels, surface->pitch) != 0) SdlError("Read screenshot");
  if (SDL_SaveBMP(surface.get(), path.string().c_str()) != 0) SdlError("Save screenshot");
}

std::filesystem::path PreferencePath() {
  std::unique_ptr<char, decltype(&SDL_free)> directory(
      SDL_GetPrefPath("Plan-B", "quietproof"), SDL_free);
  return directory ? std::filesystem::path(directory.get()) / "display.conf" : std::filesystem::path{};
}

struct TestEvent {
  SDL_Keycode key = 0;
  bool shift = false;
  int x = -1, y = -1;
  std::string text;
  bool drop = false;
  bool private_synthetic = false;
  bool control_modifier = false;
  int control = 0;
  bool quit = false;
  std::filesystem::path public_proof;
  std::string destination;
  bool await_proof = false, await_save = false;
  std::filesystem::path capture;
  int resize_width = 0, resize_height = 0;
};
std::vector<TestEvent> ReadTestEvents(const std::filesystem::path& path) {
  if (path.empty()) return {};
  std::error_code error;
  if (std::filesystem::file_size(path,error) > 32768 || error)
    throw std::runtime_error("Invalid rendering event script");
  std::ifstream input(path);
  if (!input) throw std::runtime_error("Cannot read rendering event script");
  std::vector<TestEvent> events;
  std::string line;
  while (std::getline(input,line)) {
    TestEvent event;
    if (line=="tab") event.key=SDLK_TAB;
    else if (line=="backtab") {event.key=SDLK_TAB;event.shift=true;}
    else if (line=="enter") event.key=SDLK_RETURN;
    else if (line=="space") event.key=SDLK_SPACE;
    else if (line=="pagedown") event.key=SDLK_PAGEDOWN;
    else if (line=="pageup") event.key=SDLK_PAGEUP;
    else if (line=="home") event.key=SDLK_HOME;
    else if (line=="end") event.key=SDLK_END;
    else if (line=="wait") event.key=SDLK_UNKNOWN;
    else if (line=="escape") event.key=SDLK_ESCAPE;
    else if (line=="backspace") event.key=SDLK_BACKSPACE;
    else if (line=="delete") event.key=SDLK_DELETE;
    else if (line=="private-synthetic") event.private_synthetic=true;
    else if (line=="quit") event.quit=true;
    else if (line=="await-proof") event.await_proof=true;
    else if (line=="await-save") event.await_save=true;
    else if (line.starts_with("proof-fixture ")) event.public_proof=line.substr(14);
    else if (line.starts_with("destination ")) event.destination=line.substr(12);
    else if (line.starts_with("capture ")) event.capture=line.substr(8);
    else if (line.starts_with("resize ")) {
      std::istringstream words(line.substr(7)); std::string extra;
      if (!(words>>event.resize_width>>event.resize_height) || (words>>extra) ||
          event.resize_width<400 || event.resize_height<640 || event.resize_width>8192 || event.resize_height>8192)
        throw std::runtime_error("Invalid rendering resize");
    }
    else if (line=="copy" || line=="cut" || line=="paste" || line=="undo" || line=="redo") {
      event.control_modifier=true;
      event.key=line=="copy" ? SDLK_c : line=="cut" ? SDLK_x : line=="paste" ? SDLK_v : line=="undo" ? SDLK_z : SDLK_y;
    } else if (line.starts_with("control ")) {
      std::istringstream words(line.substr(8)); std::string extra;
      if (!(words>>event.control) || event.control<1 || event.control>309 || (words>>extra))
        throw std::runtime_error("Invalid rendering control");
    }
    else if (line.starts_with("text ")) {
      event.text = line.substr(5);
      if (event.text.size() > 31) throw std::runtime_error("Rendering text event too long");
    } else if (line.starts_with("drop ")) {
      event.text = line.substr(5);
      event.drop = true;
    } else {
      std::istringstream words(line);
      std::string command,extra;
      if (!(words>>command>>event.x>>event.y) || command!="click" || (words>>extra) ||
          event.x<0 || event.y<0 || event.x>8192 || event.y>8192)
        throw std::runtime_error("Unknown rendering event");
    }
    if (events.size()==1024) throw std::runtime_error("Too many rendering events");
    events.push_back(event);
  }
  return events;
}

void InjectTestEvent(const TestEvent& test, bool down, Uint32 window_id,
                     SDL_Renderer* renderer, const ShellState& state) {
  SDL_Event event{};
  if (test.private_synthetic) {
    if (!down) return;
    event.type=SDL_TEXTINPUT; event.text.windowID=window_id;
    for (int i=0;i<12;++i) event.text.text[i]=static_cast<char>(65+i);
  } else if (test.quit) {
    if (!down) return;
    event.type=SDL_QUIT;
  } else if (!test.text.empty()) {
    if (!down) return;
    if (test.drop) {
      event.type = SDL_DROPFILE;
      event.drop.windowID = window_id;
      event.drop.file = SDL_strdup(test.text.c_str());
      if (!event.drop.file) throw std::bad_alloc();
    } else {
      event.type = SDL_TEXTINPUT;
      event.text.windowID = window_id;
      SDL_strlcpy(event.text.text,test.text.c_str(),sizeof(event.text.text));
    }
  } else if (test.key) {
    event.type=down ? SDL_KEYDOWN : SDL_KEYUP;
    event.key.windowID=window_id;
    event.key.keysym.sym=test.key;
    event.key.keysym.mod=test.control_modifier ? KMOD_CTRL : test.shift ? KMOD_SHIFT : KMOD_NONE;
  } else {
    const auto bounds = state.controls[test.control];
    int x = test.x, y = test.y;
    if (test.control && (bounds.w<=0 || bounds.h<=0)) throw std::runtime_error("Rendering control unavailable");
    // SDL filters queued pointer events from window to renderer coordinates.
    // Control bounds are logical; literal click events already use window pixels.
    if (test.control) SDL_RenderLogicalToWindow(renderer,bounds.x+bounds.w/2,
                                                bounds.y+bounds.h/2,&x,&y);
    if (down) {
      SDL_Event motion{};
      motion.type=SDL_MOUSEMOTION;
      motion.motion.windowID=window_id;
      motion.motion.x=x;
      motion.motion.y=y;
      if (SDL_PushEvent(&motion)<0) SdlError("Queue pointer motion");
    }
    event.type=down ? SDL_MOUSEBUTTONDOWN : SDL_MOUSEBUTTONUP;
    event.button.windowID=window_id;
    event.button.button=SDL_BUTTON_LEFT;
    event.button.x=x;
    event.button.y=y;
  }
  if (SDL_PushEvent(&event)<0) SdlError("Queue rendering event");
  ErasePrivateEvent(event);
}
}  // namespace

int Run(const Options& options) {
  const auto test_events=ReadTestEvents(options.test_events);
  SdlSession sdl;
  std::unique_ptr<SDL_Window, decltype(&SDL_DestroyWindow)> window(
      SDL_CreateWindow("Quietproof", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                       options.width*options.pixel_scale, options.height*options.pixel_scale,
                       SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI),
      SDL_DestroyWindow);
  if (!window) SdlError("Create window");
  SDL_SetWindowMinimumSize(window.get(), 400*options.pixel_scale, 640*options.pixel_scale);
  std::unique_ptr<SDL_Renderer, decltype(&SDL_DestroyRenderer)> renderer(
      SDL_CreateRenderer(window.get(), -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC),
      SDL_DestroyRenderer);
  if (!renderer) renderer.reset(SDL_CreateRenderer(window.get(), -1, SDL_RENDERER_SOFTWARE));
  if (!renderer) SdlError("Create renderer");
  if (SDL_RenderSetLogicalSize(renderer.get(),options.width,options.height)!=0) SdlError("Set logical size");
  const auto preference_path=PreferencePath();
  ShellState state;
  NodeProbeWorker node_worker;
  state.preferences=LoadPreferences(preference_path);
  const auto node_path = preference_path.empty() ? std::filesystem::path{} : preference_path.parent_path()/"node.conf";
  state.node_settings=LoadNodeSettings(node_path,&state.node_settings_status);
  if (options.theme_override) state.preferences.dark=options.dark;
  if (options.font_override) state.preferences.font_index=options.font_scale==1.5f ? 2 : options.font_scale==1.25f ? 1 : 0;
  if (options.settings) {state.view=View::Settings;state.focus=5;}
  if (!options.request.empty()) state.OpenRequest(options.request);
  NuklearSession nuklear(window.get(), renderer.get());
  nk_font_atlas* atlas = nullptr;
  nk_sdl_font_stash_begin(&atlas);
  std::array<nk_font*,3> body{},heading{};
  const auto path = options.builtin_font ? std::filesystem::path{} : FontPath();
  bool native_font=!path.empty();
  int output_width=0,output_height=0;
  if (SDL_GetRendererOutputSize(renderer.get(),&output_width,&output_height)!=0) SdlError("Read renderer size");
  const float density=std::max(2.0f,static_cast<float>(output_width)/options.width);
  for (int index=0;index<3;++index) {
    const float scale=1.0f+index*0.25f;
    auto add_font=[&](float size) {
      nk_font* font=nullptr;
      if (!path.empty()) font=nk_font_atlas_add_from_file(atlas,path.string().c_str(),size*scale*density,nullptr);
      if (!font) {native_font=false;font=nk_font_atlas_add_default(atlas,size*scale*density,nullptr);}
      if (!font) throw std::runtime_error("Load offline font");
      return font;
    };
    body[index]=add_font(17);
    heading[index]=add_font(22);
  }
  nk_sdl_font_stash_end();
  for (int index=0;index<3;++index) {
    body[index]->handle.height/=density;
    heading[index]->handle.height/=density;
  }
  SDL_StartTextInput();
  bool running = true;
  bool closing_wallet = false;
  bool closing_save = false;
  bool private_prompt_before_close = false;
  bool private_mask_before_close = false;
  int private_focus_before_close = 0;
  nk_uint private_scroll_before_close = 0;
  bool wallet_status_before_close = false;
  bool wallet_checked_before_close = false;
  bool wallet_warning_before_close = false;
  bool proof_cancel_before_close = false;
  bool proof_generated_before_close = false;
  bool save_retained_before_close = false, save_confirm_before_close = false, save_status_before_close = false;
  int frames = 0;
  const int smoke_frames=3+static_cast<int>(test_events.size())*2;
  int test_wait_frames = 0;
  std::optional<std::chrono::steady_clock::time_point> test_wait_started;
  std::filesystem::path test_capture;
  int capture_index = 0;
  while (running) {
    const int event_frame=frames-test_wait_frames;
    if (event_frame>0 && static_cast<size_t>((event_frame-1)/2)<test_events.size()) {
      const auto& test=test_events[(event_frame-1)/2]; const bool down=(event_frame-1)%2==0;
      if (test.await_proof || test.await_save) {
        const bool ready=test.await_proof ? bool(state.completed_proof) : !state.save_busy && !state.save_status.empty();
        if (!ready) {
          if (!test_wait_started) test_wait_started=std::chrono::steady_clock::now();
          if (std::chrono::steady_clock::now()-*test_wait_started>std::chrono::seconds(120)) throw std::runtime_error("Rendering worker precondition timed out");
          ++test_wait_frames;
        } else test_wait_started.reset();
      } else if (!test.capture.empty() || test.resize_width) {
        if (!options.smoke_test) throw std::runtime_error("Rendering capture/resize requires smoke mode");
        if (down && !test.capture.empty()) test_capture=test.capture;
        if (down && test.resize_width) { SDL_SetWindowSize(window.get(),test.resize_width*options.pixel_scale,test.resize_height*options.pixel_scale); state.scroll={}; }
      } else if (!test.public_proof.empty()) {
        if (down) {
          if (!options.smoke_test || !state.request.loaded || node_worker.Running()) throw std::runtime_error("Public fixture validation precondition unavailable");
          state.CancelWalletInput(); state.cancel_wallet=false;
          state.validation_job=ValidationJob{state.node_probe.revision,state.request.loaded,test.public_proof};
          state.proof_started=std::chrono::steady_clock::now();
          state.wallet_busy=node_worker.StartValidation(*state.validation_job);
          if (!state.wallet_busy) throw std::runtime_error("Public fixture worker unavailable");
        }
      } else if (!test.destination.empty()) {
        if (down) {
          if (!options.smoke_test || !state.save_dialog || test.destination.size()>=state.save_path.size()) throw std::runtime_error("Rendering destination precondition unavailable");
          SDL_strlcpy(state.save_path.data(),test.destination.c_str(),state.save_path.size()); state.InvalidateSaveDestination();
        }
      } else InjectTestEvent(test,down,SDL_GetWindowID(window.get()),renderer.get(),state);
    }
    nk_input_begin(nuklear.context);
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
      if (event.type == SDL_QUIT) {
        private_prompt_before_close = state.wallet_prompt;
        private_mask_before_close = state.wallet_input->Size() != 0;
        private_focus_before_close = state.wallet_focus;
        private_scroll_before_close = state.wallet_scroll.y;
        wallet_status_before_close = !state.wallet_status.empty();
        wallet_checked_before_close = !state.wallet_cancel_pending && state.proof_progress.has_value() &&
            state.proof_progress->stage >= ProofStage::Prove;
        wallet_warning_before_close = !state.wallet_warning.empty();
        proof_cancel_before_close = state.wallet_cancel_pending;
        proof_generated_before_close = bool(state.completed_proof);
        save_retained_before_close = bool(state.completed_proof);
        save_confirm_before_close = bool(state.save_confirm);
        save_status_before_close = !state.save_status.empty();
        if (!state.save_busy) state.CancelWalletInput();
        else state.wallet_input->Clear();
        node_worker.CancelWallet();
        if (state.save_busy) {
          closing_save = true; state.view = View::Result; state.scroll = {};
          state.save_status = "Closing: finishing the current write or atomic publication.";
          if (options.smoke_test) std::cout << "GUI save close: waiting for current output step" << std::endl;
        } else if (state.wallet_busy) {
          closing_wallet = true;
          state.view = View::Request; state.scroll = {};
          state.wallet_status = "Closing: finishing the current proof step and wallet cleanup. No result will be kept.";
          if (options.smoke_test) std::cout << "GUI wallet close: waiting for bounded cleanup" << std::endl;
        } else running = false;
      }
      if (event.type == SDL_KEYDOWN && event.key.keysym.sym == SDLK_ESCAPE && state.wallet_busy) {
        state.CancelWalletInput();
        state.wallet_status = "Cancel requested. Finishing the current step; no proof will be kept.";
        ErasePrivateEvent(event); continue;
      }
      const bool private_mode = state.wallet_prompt || state.WalletPrivatePhase() || state.private_input_guard;
      if (private_mode && (event.type == SDL_TEXTINPUT || event.type == SDL_TEXTEDITING ||
          event.type == SDL_TEXTEDITING_EXT || event.type == SDL_KEYDOWN || event.type == SDL_KEYUP)) {
        const auto action = HandlePrivateEvent(*state.wallet_input,event,state.wallet_prompt && state.wallet_focus == 0);
        if (action == PrivateAction::Cancel) {
          state.CancelWalletInput(); state.wallet_status = state.wallet_busy ?
              "Cancel requested. Finishing the current step; no proof will be kept." : "Wallet access canceled. Password cleared.";
        } else if (state.wallet_prompt) {
          if (action == PrivateAction::Next) state.wallet_focus = (state.wallet_focus+1)%3;
          if (action == PrivateAction::Previous) state.wallet_focus = (state.wallet_focus+2)%3;
          if (action == PrivateAction::ScrollDown) state.wallet_scroll.y = std::min(10000u,state.wallet_scroll.y+100);
          if (action == PrivateAction::ScrollUp) state.wallet_scroll.y = state.wallet_scroll.y > 100 ? state.wallet_scroll.y-100 : 0;
          if (action == PrivateAction::Submit) {
            if (state.wallet_focus == 2) {
              state.CancelWalletInput(); state.wallet_status = "Wallet access canceled. Password cleared.";
            }
            else if (state.wallet_input->Size()) {
              state.submit_wallet = true; state.wallet_prompt = false; state.private_input_guard = true;
            }
          }
        }
        continue;
      }
      if (event.type == SDL_TEXTEDITING || event.type == SDL_TEXTEDITING_EXT) { ErasePrivateEvent(event); continue; }
      if (event.type == SDL_KEYDOWN) HandleShellKey(state,event.key);
      if (event.type == SDL_DROPFILE) {
        std::unique_ptr<char, decltype(&SDL_free)> dropped(event.drop.file, SDL_free);
        if (dropped) state.OpenRequest(std::filesystem::path(dropped.get()));
        continue;
      }
      if (event.type == SDL_TEXTINPUT) {
        // The pinned upstream backend forwards only the first glyph. SDL text
        // input may contain several UTF-8 characters (including IME commits).
        const int length = static_cast<int>(std::find(std::begin(event.text.text),
            std::end(event.text.text),'\0') - std::begin(event.text.text));
        for (int offset=0; offset<length;) {
          nk_rune rune = 0;
          const int consumed = nk_utf_decode(event.text.text+offset,&rune,length-offset);
          if (consumed <= 0) break;
          nk_input_unicode(nuklear.context,rune);
          offset += consumed;
        }
        ErasePrivateEvent(event);
        continue;
      }
      nk_sdl_handle_event(&event);
    }
    nk_input_end(nuklear.context);
    if (!running) break;
    int width = 0, height = 0;
    SDL_GetWindowSize(window.get(), &width, &height);
    width/=options.pixel_scale;
    height/=options.pixel_scale;
    if (width <= 0 || height <= 0) { SDL_Delay(16); continue; }
    if (SDL_RenderSetLogicalSize(renderer.get(), width, height) != 0) SdlError("Set logical size");
    const int font_index=state.preferences.font_index;
    state.now = options.test_now.value_or(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    if (state.wallet_prompt && (!state.request.loaded ||
        RequestWindowAt(state.request.loaded->statement,state.now) != RequestWindow::Valid)) {
      state.CancelWalletInput(); state.wallet_status = "Request is no longer valid. Wallet password cleared.";
    }
    state.node_busy = node_worker.Running() && !state.wallet_busy && !state.save_busy;
    if (auto result = node_worker.Poll()) state.node_probe.Accept(std::move(*result));
    if (auto progress = node_worker.PollProgress()) {
      if ((state.wallet_job || state.validation_job) && progress->revision == state.node_probe.revision) {
        state.proof_progress = *progress;
        if (progress->stage == ProofStage::Prove || progress->stage == ProofStage::Verify)
          state.wallet_status = "Wallet secrets have been cleared from input. Work continues on the proof worker.";
        if (options.smoke_test) std::cout << "GUI proof stage: " << static_cast<int>(progress->stage)
            << " phase=" << static_cast<int>(progress->phase) << std::endl;
      }
    }
    if (auto result = node_worker.PollWallet()) {
      if (state.wallet_status.starts_with("Cancel requested."))
        state.wallet_status = "Canceled. Current work and wallet cleanup have finished; no proof was kept.";
      state.wallet_busy = false;
      state.wallet_cancel_pending = false;
      const bool cleanup_warning = result->cleanup == WalletCleanup::Failed ||
          (result->unlock_attempted && !result->unlock_confirmed && result->cleanup == WalletCleanup::Relocked);
      const bool current = (state.wallet_job || state.validation_job) && result->revision == state.node_probe.revision;
      if (closing_wallet) {
        if (cleanup_warning) {
          closing_wallet = false; state.view = View::Request; state.scroll = {};
        } else running = false;
      }
      if (current || cleanup_warning) {
        const auto wallet = result->wallet.value_or("");
        state.wallet_status = "Wallet "+(wallet.empty() ? std::string("(default unnamed)") : RequestDisplayText(wallet))+": "+result->Message();
        if (cleanup_warning) state.wallet_warning = state.wallet_status;
        if (current && (result->status == WalletSessionStatus::PasswordRequired ||
            result->error.code == proofs::BitcoinRpcErrorCode::kWrongPassphrase)) {
          state.wallet_input->Clear(); state.wallet_focus = 0; state.wallet_scroll = {};
          state.wallet_prompt = true; state.private_input_guard = true;
        } else {
          if (current && result->status == WalletSessionStatus::Proved && result->verified) {
            state.completed_proof = std::move(result->verified);
            state.view = View::Result; state.scroll = {}; state.focus = 11;
            const auto path = state.request.loaded->path.parent_path()/(state.request.loaded->path.stem().string()+".qpf");
            SDL_strlcpy(state.save_path.data(),path.string().c_str(),state.save_path.size());
          }
          state.validation_job.reset();
          state.wallet_job.reset();
        }
      }
    }
    if (auto result = node_worker.PollSave()) {
      state.AcceptSaveResult(*result);
      if (closing_save) running = false;
    }
    if (!running) break;
    DrawShell(nuklear.context,state,width,height,&body[font_index]->handle,&heading[font_index]->handle);
    if (state.cancel_wallet) { node_worker.CancelWallet(); state.cancel_wallet = false; }
    if (state.cancel_save) { node_worker.CancelWallet(); state.cancel_save = false; state.save_status = "Cancel requested. Finishing the current write or atomic publication."; }
    if (state.save_file) {
      state.save_file = false;
      if (!node_worker.Running() && state.completed_proof) {
        std::error_code error;
        const auto destination = std::filesystem::absolute(std::filesystem::path(state.save_path.data()),error);
        if (error || state.save_path[0] == 0) state.save_status = "Choose a destination filename";
        else {
          state.save_busy = node_worker.StartSave(SaveJob{state.node_probe.revision,state.save_attempt,state.completed_proof,destination,state.save_confirm});
          state.save_confirm.reset();
          state.save_status = state.save_busy ? "Writing complete verified proof; cancellation is checked before atomic publication." : "Save worker unavailable. Proof retained; retry explicitly.";
        }
      }
    }
    if (state.prove_wallet) {
      state.prove_wallet = false;
      std::string error;
      if (!node_worker.Running() && !state.completed_proof && state.request.loaded && state.node_probe.result && state.node_probe.result->selected_wallet) {
        if (auto config = ConfigureNode(state.node_settings,state.request.loaded->statement.network,&error)) {
          state.wallet_job = WalletSessionJob{state.node_probe.revision,std::move(*config),state.request.loaded,
              state.node_probe.result->selected_wallet,true};
          state.wallet_input->Clear();
          state.completed_proof.reset(); state.proof_progress.reset(); state.wallet_cancel_pending = false;
          state.proof_started = std::chrono::steady_clock::now();
          state.wallet_busy = node_worker.StartProof(ProofJob{*state.wallet_job},std::make_unique<PrivateInput>());
          state.private_input_guard = true;
          state.wallet_status = "Rechecking the reviewed request and selected RPC wallet.";
          if (!state.wallet_busy) { state.wallet_job.reset(); state.wallet_status = "Wallet worker unavailable. Start a new attempt explicitly."; }
        } else state.wallet_status = error;
      }
    }
    if (state.submit_wallet) {
      state.submit_wallet = false;
      auto password = std::move(state.wallet_input);
      state.wallet_input = std::make_unique<PrivateInput>();
      if (state.wallet_job && state.wallet_job->revision == state.node_probe.revision) {
        state.proof_progress.reset(); state.wallet_cancel_pending = false;
        state.proof_started = std::chrono::steady_clock::now();
        state.wallet_busy = node_worker.StartProof(ProofJob{*state.wallet_job},std::move(password));
      }
      state.private_input_guard = true;
      state.wallet_status = "Accessing the selected wallet, then generating this request's proof.";
      if (!state.wallet_busy) { state.wallet_job.reset(); state.wallet_status = "Wallet worker unavailable. Password cleared; start a new attempt explicitly."; }
    }
    if (state.private_input_guard) {
      DrainPrivateTextEvents();
      ErasePrivateMemory(nuklear.context->input.keyboard.text,sizeof(nuklear.context->input.keyboard.text));
      nuklear.context->input.keyboard.text_len = 0;
      state.private_input_guard = state.wallet_prompt || state.WalletPrivatePhase();
    }
    if (state.test_node && !state.wallet_busy && !state.save_busy) {
      state.test_node = false;
      const auto network = state.request.loaded ? state.request.loaded->statement.network : state.node_network;
      std::string error;
      if (auto configuration = ConfigureNode(state.node_settings,network,&error)) {
        state.CancelWalletInput();
        state.node_probe.Invalidate();
        NodeProbeJob job{state.node_probe.revision,std::move(*configuration),{},bool(state.request.loaded),state.node_selection};
        if (state.request.loaded) job.match = MatchRequest(*state.request.loaded);
        if (!node_worker.Start(std::move(job))) state.node_settings_status = "Connection test already running or worker unavailable.";
      } else state.node_settings_status = error;
    }
    if (state.save_preferences) {
      state.preference_status=SavePreferences(preference_path,state.preferences) ?
        "Display preferences saved on this device." : "Display preferences could not be saved.";
      state.save_preferences=false;
    }
    if (state.save_node_settings) {
      state.node_settings_status=SaveNodeSettings(node_path,state.node_settings) ?
          "Nonsecret connection settings saved on this device." :
          "Settings not saved. Check fields and local file permissions.";
      state.save_node_settings=false;
    }
    const auto canvas = BrandPalette(state.preferences.dark).canvas;
    SDL_SetRenderDrawColor(renderer.get(), canvas.r, canvas.g, canvas.b, 255);
    if (SDL_RenderClear(renderer.get()) != 0) SdlError("Clear renderer");
    nk_sdl_render(NK_ANTI_ALIASING_ON);
    if (!test_capture.empty()) {
      Capture(renderer.get(),test_capture); test_capture.clear(); ++capture_index;
      std::cout << "GUI capture: " << capture_index << " retained=" << bool(state.completed_proof)
                << " confirm=" << bool(state.save_confirm) << " dialog=" << state.save_dialog
                << " busy=" << state.save_busy << " status=" << !state.save_status.empty() << std::endl;
      for (const int id : {11,307,308}) {
        const auto r=state.controls[id];
        if(r.w>0) std::cout << "GUI capture control: " << capture_index << ' ' << id << ' ' << r.x << ' ' << r.y << ' ' << r.w << ' ' << r.h << std::endl;
      }
    }
    if (++frames == smoke_frames+test_wait_frames && !options.screenshot.empty()) Capture(renderer.get(), options.screenshot);
    SDL_RenderPresent(renderer.get());
    if (options.smoke_test && frames == smoke_frames+test_wait_frames) {
      SDL_Event quit{};
      quit.type = SDL_QUIT;
      if (SDL_PushEvent(&quit) < 0) SdlError("Queue close event");
    }
    SDL_Delay(16);
  }
  SDL_StopTextInput();
  state.CancelWalletInput();
  node_worker.CancelWallet();
  DrainPrivateTextEvents();
  if (options.smoke_test)
    std::cout << "GUI smoke: " << frames << " frames; orderly SDL_QUIT; font="
              << (native_font ? "Inter" : "builtin") << '\n';
  if (options.smoke_test) {
    SDL_RendererInfo renderer_info{};
    if (SDL_GetRendererInfo(renderer.get(), &renderer_info) != 0) SdlError("Read renderer identity");
    std::cout << "GUI assets: font=" << (native_font ? path.lexically_normal().string() : "builtin")
              << " renderer=" << (renderer_info.name ? renderer_info.name : "unknown") << '\n';
    std::cout << "GUI wallet: prompt=" << private_prompt_before_close
              << " masked=" << private_mask_before_close << " cleared=" << (state.wallet_input->Size() == 0)
              << " busy=" << state.wallet_busy << " focus=" << private_focus_before_close
              << " scroll=" << private_scroll_before_close << '\n';
    std::cout << "GUI wallet context: transient=" << wallet_status_before_close
              << " checked=" << wallet_checked_before_close << " warning=" << wallet_warning_before_close << '\n';
    std::cout << "GUI proof: canceled=" << proof_cancel_before_close
              << " generated=" << proof_generated_before_close << '\n';
    std::cout << "GUI save: retained=" << save_retained_before_close << " attempt=" << state.save_attempt
              << " dialog=" << state.save_dialog << " confirm=" << save_confirm_before_close
              << " busy=" << state.save_busy << " status=" << save_status_before_close << '\n';
    const auto node_network = state.request.loaded ? state.request.loaded->statement.network : state.node_network;
    std::cout << "GUI node: network=" << proofs::QuietProofNetworkName(node_network)
              << " configured=" << bool(ConfigureNode(state.node_settings,node_network,nullptr))
              << " advanced=" << state.node_advanced << '\n';
    std::cout << "GUI probe: busy=" << state.node_busy << " report=" << bool(state.node_probe.result)
              << " revision=" << state.node_probe.revision;
    if (state.node_probe.result)
      std::cout << " authenticated=" << state.node_probe.result->probe.authenticated
                << " complete=" << state.node_probe.result->complete
                << " selected=" << bool(state.node_probe.result->selected_wallet)
                << " error=" << static_cast<int>(state.node_probe.result->error.code);
    std::cout << '\n';
    std::cout << "GUI request: loaded=" << bool(state.request.loaded)
              << " error=" << static_cast<int>(state.request.error)
              << " revision=" << state.request.revision << " chooser=" << state.chooser.open
              << " prove=disabled\n";
    if (state.request.loaded)
      std::cout << "GUI review: version=" << unsigned(state.request.loaded->statement.statement_version)
                << " window=" << RequestWindowName(RequestWindowAt(state.request.loaded->statement,state.now))
                << " claimsExpanded=" << state.claims_expanded
                << " claimCount=" << state.request.loaded->statement.claims.size() << '\n';
    std::cout << "GUI state: view=" << ViewName(state.view) << " theme=" << (state.preferences.dark ? "dark" : "light")
              << " fontIndex=" << state.preferences.font_index << " focus=" << state.focus << " scrollY=" << state.scroll.y
              << " pixels=" << output_width << 'x' << output_height
              << " logical=" << options.width << 'x' << options.height << '\n';
    for (size_t id=1;id<state.controls.size();++id) {
      const auto r=state.controls[id];
      if (r.w>0) std::cout << "control " << id << ' ' << r.x << ' ' << r.y << ' ' << r.w << ' ' << r.h << '\n';
    }
  }
  if (options.smoke_test) std::cout.flush();
  return 0;
}
}  // namespace quietproof::gui
