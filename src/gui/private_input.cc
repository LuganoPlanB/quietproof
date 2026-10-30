#include "private_input.h"

#include <algorithm>

namespace quietproof::gui {
void ErasePrivateMemory(void* pointer, size_t size) noexcept {
  volatile unsigned char* p = static_cast<unsigned char*>(pointer);
  while (size--) *p++ = 0;
}
bool PrivateInput::Append(std::string_view input) {
  if (input.size() > kCapacity-size_) return false;
  // Strict, complete UTF-8 commits only. Reject ASCII controls/NUL and overlong,
  // surrogate or out-of-range encodings without making a string copy.
  for (size_t i=0;i<input.size();) {
    const auto lead = static_cast<unsigned char>(input[i++]);
    if (lead < 0x80) { if (lead < 0x20 || lead == 0x7f) return false; continue; }
    const int count = lead >= 0xc2 && lead <= 0xdf ? 1 : lead >= 0xe0 && lead <= 0xef ? 2 : lead >= 0xf0 && lead <= 0xf4 ? 3 : -1;
    if (count < 0 || i+count > input.size()) return false;
    uint32_t code = lead & ((1u << (6-count))-1);
    for (int j=0;j<count;++j) {
      const auto byte = static_cast<unsigned char>(input[i++]);
      if ((byte & 0xc0) != 0x80) return false;
      code = (code << 6) | (byte & 0x3f);
    }
    if ((count == 1 && code < 0x80) || (count == 2 && code < 0x800) ||
        (count == 3 && code < 0x10000) || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return false;
  }
  std::copy(input.begin(),input.end(),bytes_.begin()+size_);
  size_ += input.size();
  return true;
}
void PrivateInput::Backspace() {
  if (!size_) return;
  const size_t previous = size_;
  do { --size_; } while (size_ && (static_cast<unsigned char>(bytes_[size_]) & 0xc0) == 0x80);
  ErasePrivateMemory(bytes_.data()+size_,previous-size_);
}
void PrivateInput::Clear() noexcept {
  ErasePrivateMemory(bytes_.data(),bytes_.size());
  size_ = 0;
}
void ErasePrivateEvent(SDL_Event& event) noexcept {
  if (event.type == SDL_TEXTINPUT) ErasePrivateMemory(event.text.text,sizeof(event.text.text));
  if (event.type == SDL_TEXTEDITING) ErasePrivateMemory(event.edit.text,sizeof(event.edit.text));
  if (event.type == SDL_TEXTEDITING_EXT && event.editExt.text) {
    ErasePrivateMemory(event.editExt.text,SDL_strlen(event.editExt.text));
    SDL_free(event.editExt.text);
    event.editExt.text = nullptr;
  }
}
void DrainPrivateTextEvents() noexcept {
  SDL_Event event{};
  for (const auto type : {SDL_TEXTINPUT,SDL_TEXTEDITING,SDL_TEXTEDITING_EXT}) {
    while (SDL_PeepEvents(&event,1,SDL_GETEVENT,type,type) > 0) ErasePrivateEvent(event);
  }
  ErasePrivateMemory(&event,sizeof(event));
}
PrivateAction HandlePrivateEvent(PrivateInput& input, SDL_Event& event, bool accept_text) {
  if (event.type == SDL_TEXTINPUT && accept_text) {
    const auto end = std::find(std::begin(event.text.text),std::end(event.text.text),'\0');
    if (end != std::end(event.text.text)) input.Append({event.text.text,static_cast<size_t>(end-std::begin(event.text.text))});
  }
  ErasePrivateEvent(event);
  if (event.type != SDL_KEYDOWN) return PrivateAction::None;
  const auto key = event.key.keysym.sym;
  const auto modifiers = event.key.keysym.mod;
  // No clipboard API is called. Refuse Ctrl/Super shortcuts and Shift+Insert.
  if ((modifiers & (KMOD_CTRL|KMOD_GUI)) || (key == SDLK_INSERT && (modifiers & KMOD_SHIFT))) return PrivateAction::None;
  if (accept_text && key == SDLK_BACKSPACE) input.Backspace();
  if (accept_text && key == SDLK_DELETE) input.Clear();
  if (event.key.repeat) return PrivateAction::None;
  if (key == SDLK_ESCAPE) return PrivateAction::Cancel;
  if (key == SDLK_RETURN || key == SDLK_KP_ENTER) return PrivateAction::Submit;
  if (key == SDLK_TAB) return modifiers & KMOD_SHIFT ? PrivateAction::Previous : PrivateAction::Next;
  if (key == SDLK_PAGEDOWN) return PrivateAction::ScrollDown;
  if (key == SDLK_PAGEUP) return PrivateAction::ScrollUp;
  return PrivateAction::None;
}
}  // namespace quietproof::gui
