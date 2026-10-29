#pragma once

#include <filesystem>

namespace quietproof::gui {
struct DisplayPreferences {
  bool dark = false;
  int font_index = 0;
};
DisplayPreferences LoadPreferences(const std::filesystem::path& path);
bool SavePreferences(const std::filesystem::path& path, DisplayPreferences preferences);
}  // namespace quietproof::gui
