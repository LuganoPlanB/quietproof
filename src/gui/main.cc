#include "application.h"

#include <charconv>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
int Dimension(std::string_view text, int minimum) {
  int value = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || end != text.data() + text.size() ||
      value < minimum || value > 4096) {
    throw std::runtime_error("Window dimension outside supported range");
  }
  return value;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    quietproof::gui::Options options;
    for (int i = 1; i < argc; ++i) {
      const std::string_view arg(argv[i]);
      auto value = [&]() -> std::string_view {
        if (++i == argc) throw std::runtime_error("Missing option value");
        return argv[i];
      };
      if (arg == "--help") {
        std::cout << "Quietproof native prover\n"
                     "  --theme light|dark  --width 400..4096  --height 640..4096\n"
                     "  --font-scale 1|1.25|1.5  --builtin-font\n"
                     "  --settings  --request request-file\n"
                     "  --smoke-test [--screenshot output.bmp] [--pixel-scale 1|2]\n"
                     "               [--test-events events.txt] [--test-now unix-seconds]\n";
        return 0;
      } else if (arg == "--theme") {
        const auto theme = value();
        if (theme != "light" && theme != "dark") throw std::runtime_error("Unknown theme");
        options.dark = theme == "dark";
        options.theme_override = true;
      } else if (arg == "--width") {
        options.width = Dimension(value(), 400);
      } else if (arg == "--height") {
        options.height = Dimension(value(), 640);
      } else if (arg == "--font-scale") {
        const auto scale = value();
        if (scale == "1") options.font_scale = 1.0f;
        else if (scale == "1.25") options.font_scale = 1.25f;
        else if (scale == "1.5") options.font_scale = 1.5f;
        else throw std::runtime_error("Unsupported font scale");
        options.font_override = true;
      } else if (arg == "--smoke-test") {
        options.smoke_test = true;
      } else if (arg == "--builtin-font") {
        options.builtin_font = true;
      } else if (arg == "--screenshot") {
        options.screenshot = value();
      } else if (arg == "--settings") {
        options.settings = true;
      } else if (arg == "--request") {
        options.request = value();
      } else if (arg == "--pixel-scale") {
        const auto scale = value();
        if (scale != "1" && scale != "2") throw std::runtime_error("Unsupported pixel scale");
        options.pixel_scale = scale == "2" ? 2 : 1;
      } else if (arg == "--test-events") {
        options.test_events = value();
      } else if (arg == "--test-now") {
        const auto text = value();
        int64_t now = 0;
        const auto [end,error] = std::from_chars(text.data(),text.data()+text.size(),now);
        if (error != std::errc{} || end != text.data()+text.size())
          throw std::runtime_error("Invalid rendering test time");
        options.test_now = now;
      } else {
        throw std::runtime_error("Unknown option; see --help");
      }
    }
    if (!options.screenshot.empty() && !options.smoke_test)
      throw std::runtime_error("Screenshot capture requires --smoke-test");
    if ((!options.test_events.empty() || options.pixel_scale != 1 || options.test_now) && !options.smoke_test)
      throw std::runtime_error("Rendering test options require --smoke-test");
    return quietproof::gui::Run(options);
  } catch (const std::exception& error) {
    std::cerr << "Quietproof GUI: " << error.what() << '\n';
    return 1;
  }
}
