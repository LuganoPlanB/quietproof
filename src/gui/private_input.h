#pragma once

#include <array>
#include <span>
#include <string_view>
#include <SDL.h>

namespace quietproof::gui {
void ErasePrivateMemory(void*, size_t) noexcept;
// Append-only UTF-8 input with no editor, selection, clipboard or history.
class PrivateInput final {
 public:
  static constexpr size_t kCapacity = 1024;
  ~PrivateInput() { Clear(); }
  PrivateInput() = default;
  PrivateInput(const PrivateInput&) = delete;
  PrivateInput& operator=(const PrivateInput&) = delete;
  bool Append(std::string_view);
  void Backspace();
  void Clear() noexcept;
  std::span<const char> Bytes() const { return {bytes_.data(),size_}; }
  size_t Size() const { return size_; }
 private:
  std::array<char,kCapacity> bytes_{};
  size_t size_ = 0;
};
enum class PrivateAction { None, Submit, Cancel, Next, Previous, ScrollDown, ScrollUp };
// Consumes text/key input without passing plaintext to Nuklear. Clipboard and
// undo shortcuts are ignored; paste is deliberately unsupported. Event-owned
// text is erased/freed, including composition text that is never rendered.
PrivateAction HandlePrivateEvent(PrivateInput&, SDL_Event&, bool accept_text);
void ErasePrivateEvent(SDL_Event&) noexcept;
void DrainPrivateTextEvents() noexcept;
}  // namespace quietproof::gui
