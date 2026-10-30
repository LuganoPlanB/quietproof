#pragma once

#include <filesystem>
#include <string_view>

namespace quietproof::gui {
struct DisplayPreferences {
  bool dark = false;
  int font_index = 0;
};
DisplayPreferences LoadPreferences(const std::filesystem::path& path);
bool SavePreferences(const std::filesystem::path& path, DisplayPreferences preferences);
bool SavePrivatePreferences(const std::filesystem::path& path, std::string_view contents);
}  // namespace quietproof::gui
