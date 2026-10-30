#pragma once

#include <filesystem>
#include <cstdint>
#include <optional>

namespace quietproof::gui {
struct Options {
  bool dark = false;
  bool smoke_test = false;
  bool builtin_font = false;
  bool theme_override = false;
  bool font_override = false;
  bool settings = false;
  int pixel_scale = 1;
  int width = 480;
  int height = 720;
  float font_scale = 1.0f;
  std::filesystem::path screenshot;
  std::filesystem::path test_events;
  std::filesystem::path request;
  std::optional<int64_t> test_now;
};
int Run(const Options& options);
}  // namespace quietproof::gui
