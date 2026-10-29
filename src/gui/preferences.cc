#include "preferences.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#ifndef _WIN32
#include <unistd.h>
#endif

namespace quietproof::gui {
DisplayPreferences LoadPreferences(const std::filesystem::path& path) {
  DisplayPreferences preferences;
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error || size > 128) return preferences;
  std::ifstream input(path);
  std::string theme, font, trailing;
  if (!std::getline(input, theme) || !std::getline(input, font) || std::getline(input, trailing))
    return preferences;
  if ((theme != "theme=light" && theme != "theme=dark") ||
      (font != "font=0" && font != "font=1" && font != "font=2")) return preferences;
  preferences.dark = theme == "theme=dark";
  preferences.font_index = font.back() - '0';
  return preferences;
}

bool SavePreferences(const std::filesystem::path& path, DisplayPreferences preferences) {
  if (path.empty() || preferences.font_index < 0 || preferences.font_index > 2) return false;
  const std::string contents = std::string("theme=") + (preferences.dark ? "dark" : "light") +
                               "\nfont=" + char('0' + preferences.font_index) + "\n";
#ifndef _WIN32
  // Exclusive temporary creation keeps the nonsecret display file atomic and private.
  std::string pattern = path.string() + ".XXXXXX";
  std::vector<char> temporary(pattern.begin(), pattern.end());
  temporary.push_back('\0');
  const int descriptor = mkstemp(temporary.data());
  if (descriptor < 0) return false;
  const auto written = write(descriptor, contents.data(), contents.size());
  const int closed = close(descriptor);
  if (written != static_cast<ssize_t>(contents.size()) || closed != 0 ||
      std::rename(temporary.data(), path.string().c_str()) != 0) {
    std::remove(temporary.data());
    return false;
  }
  return true;
#else
  // Linux is the initial packaged platform. A failed persistence attempt is visible.
  (void)contents;
  return false;
#endif
}
}  // namespace quietproof::gui
