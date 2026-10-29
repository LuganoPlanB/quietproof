# Plan B native token mapping

Verified 2026-10-29 against https://plan-b.foundation/branding and its official
https://plan-b.foundation/branding/tokens/tokens.css (both retrieved directly).
The CSS is the exact token authority; the page identifies light/dark palettes.
Font: Inter, bundled under SIL OFL 1.1; see assets/Inter-OFL.txt.

| Native role | Light | Dark |
| --- | --- | --- |
| Canvas | #FFFEFA | #171717 |
| Panel / strong panel | #FCFCFC / #F3F8FD | #211D1D / #292424 |
| Text | #030B20 | #FFFFFF |
| Accent | #4F97E9 | #E15364 |
| Strong accent | #082952 | #FFFFFF |
| Highlight | #FFB604 | #F7931A |
| Keyboard focus | #7468FF | #7468FF |

Soft text is the 72% text token composited onto a panel. Light selected actions
use Lugano Night with white text; dark selected actions use Bitcoin Orange
with charcoal text. This retains readable text contrast instead of putting
white labels on Civic Sky or Civic Coral. Accent colors also mark borders and
scrollbars. Keyboard focus uses a two-pixel violet ring. Disabled primary
actions retain full text contrast and explicitly say what prerequisite is absent.

All geometry is logical pixels; SDL scales rendering and input coordinates.
Font atlases are rasterized at output pixel density, with logical glyph metrics.
The qualification option `--pixel-scale 2` creates an actual doubled renderer
surface at unchanged logical layout dimensions, exercising the same SDL scaling
path as a HiDPI output. This is a software HiDPI qualification, not a claim of
physical monitor testing.
