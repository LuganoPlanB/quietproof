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
};
std::vector<TestEvent> ReadTestEvents(const std::filesystem::path& path) {
  if (path.empty()) return {};
  std::error_code error;
  if (std::filesystem::file_size(path,error) > 4096 || error)
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
    else if (line=="escape") event.key=SDLK_ESCAPE;
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
    if (events.size()==64) throw std::runtime_error("Too many rendering events");
    events.push_back(event);
  }
  return events;
}

void InjectTestEvent(const TestEvent& test, bool down, Uint32 window_id) {
  SDL_Event event{};
  if (!test.text.empty()) {
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
    event.key.keysym.mod=test.shift ? KMOD_SHIFT : KMOD_NONE;
  } else {
    if (down) {
      SDL_Event motion{};
      motion.type=SDL_MOUSEMOTION;
      motion.motion.windowID=window_id;
      motion.motion.x=test.x;
      motion.motion.y=test.y;
      if (SDL_PushEvent(&motion)<0) SdlError("Queue pointer motion");
    }
    event.type=down ? SDL_MOUSEBUTTONDOWN : SDL_MOUSEBUTTONUP;
    event.button.windowID=window_id;
    event.button.button=SDL_BUTTON_LEFT;
    event.button.x=test.x;
    event.button.y=test.y;
  }
  if (SDL_PushEvent(&event)<0) SdlError("Queue rendering event");
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
  state.preferences=LoadPreferences(preference_path);
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
  int frames = 0;
  const int smoke_frames=3+static_cast<int>(test_events.size())*2;
  while (running) {
    if (frames>0 && static_cast<size_t>((frames-1)/2)<test_events.size())
      InjectTestEvent(test_events[(frames-1)/2],(frames-1)%2==0,SDL_GetWindowID(window.get()));
    nk_input_begin(nuklear.context);
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
      if (event.type == SDL_QUIT) running = false;
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
    DrawShell(nuklear.context,state,width,height,&body[font_index]->handle,&heading[font_index]->handle);
    if (state.save_preferences) {
      state.preference_status=SavePreferences(preference_path,state.preferences) ?
        "Display preferences saved on this device." : "Display preferences could not be saved.";
      state.save_preferences=false;
    }
    const auto canvas = BrandPalette(state.preferences.dark).canvas;
    SDL_SetRenderDrawColor(renderer.get(), canvas.r, canvas.g, canvas.b, 255);
    if (SDL_RenderClear(renderer.get()) != 0) SdlError("Clear renderer");
    nk_sdl_render(NK_ANTI_ALIASING_ON);
    if (++frames == smoke_frames && !options.screenshot.empty()) Capture(renderer.get(), options.screenshot);
    SDL_RenderPresent(renderer.get());
    if (options.smoke_test && frames == smoke_frames) {
      SDL_Event quit{};
      quit.type = SDL_QUIT;
      if (SDL_PushEvent(&quit) < 0) SdlError("Queue close event");
    }
    SDL_Delay(16);
  }
  SDL_StopTextInput();
  if (options.smoke_test)
    std::cout << "GUI smoke: " << frames << " frames; orderly SDL_QUIT; font="
              << (native_font ? "Inter" : "builtin") << '\n';
  if (options.smoke_test) {
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
  return 0;
}
}  // namespace quietproof::gui
