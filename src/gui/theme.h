#pragma once

#include "nuklear_config.h"

namespace quietproof::gui {
struct Palette {
  nk_color canvas, panel, panel_strong, text, soft_text, accent, strong, highlight, focus;
};
Palette BrandPalette(bool dark);
void ApplyTheme(nk_context* context, bool dark);
}  // namespace quietproof::gui
