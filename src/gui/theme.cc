#include "theme.h"

namespace quietproof::gui {
Palette BrandPalette(bool dark) {
  // Official Plan B CSS tokens, captured 2026-10-29; see BRANDING.md.
  if (dark) return {nk_rgb(23,23,23), nk_rgb(33,29,29), nk_rgb(41,36,36),
                    nk_rgb(255,255,255), nk_rgb(193,191,191), nk_rgb(225,83,100),
                    nk_rgb(255,255,255), nk_rgb(247,147,26), nk_rgb(116,104,255)};
  return {nk_rgb(255,254,250), nk_rgb(252,252,252), nk_rgb(243,248,253),
          nk_rgb(3,11,32), nk_rgb(73,78,93), nk_rgb(79,151,233),
          nk_rgb(8,41,82), nk_rgb(255,182,4), nk_rgb(116,104,255)};
}

void ApplyTheme(nk_context* context, bool dark) {
  const auto p = BrandPalette(dark);
  nk_color colors[NK_COLOR_COUNT];
  for (auto& color : colors) color = p.panel;
  colors[NK_COLOR_TEXT] = p.text;
  colors[NK_COLOR_WINDOW] = p.canvas;
  colors[NK_COLOR_HEADER] = p.panel_strong;
  colors[NK_COLOR_BORDER] = p.accent;
  colors[NK_COLOR_BUTTON] = p.panel_strong;
  colors[NK_COLOR_BUTTON_HOVER] = p.panel_strong;
  colors[NK_COLOR_BUTTON_ACTIVE] = p.accent;
  colors[NK_COLOR_TOGGLE] = p.panel_strong;
  colors[NK_COLOR_TOGGLE_HOVER] = p.accent;
  colors[NK_COLOR_TOGGLE_CURSOR] = p.strong;
  colors[NK_COLOR_SELECT] = p.panel;
  colors[NK_COLOR_SELECT_ACTIVE] = p.accent;
  colors[NK_COLOR_SLIDER] = p.panel_strong;
  colors[NK_COLOR_SLIDER_CURSOR] = p.accent;
  colors[NK_COLOR_SLIDER_CURSOR_HOVER] = p.highlight;
  colors[NK_COLOR_SLIDER_CURSOR_ACTIVE] = p.strong;
  colors[NK_COLOR_PROPERTY] = p.panel;
  colors[NK_COLOR_EDIT] = p.panel;
  colors[NK_COLOR_EDIT_CURSOR] = p.text;
  colors[NK_COLOR_COMBO] = p.panel;
  colors[NK_COLOR_CHART] = p.panel;
  colors[NK_COLOR_CHART_COLOR] = p.accent;
  colors[NK_COLOR_CHART_COLOR_HIGHLIGHT] = p.highlight;
  colors[NK_COLOR_SCROLLBAR] = p.panel_strong;
  colors[NK_COLOR_SCROLLBAR_CURSOR] = p.accent;
  colors[NK_COLOR_SCROLLBAR_CURSOR_HOVER] = p.highlight;
  colors[NK_COLOR_SCROLLBAR_CURSOR_ACTIVE] = p.strong;
  colors[NK_COLOR_TAB_HEADER] = p.panel_strong;
  nk_style_from_table(context, colors);
  context->style.window.padding = nk_vec2(20,20);
  context->style.window.group_padding = nk_vec2(12,12);
  context->style.window.spacing = nk_vec2(8,8);
  context->style.window.rounding = 12;
  context->style.button.rounding = 8;
  context->style.button.border = 1;
  context->style.button.padding = nk_vec2(8,8);
}
}  // namespace quietproof::gui
