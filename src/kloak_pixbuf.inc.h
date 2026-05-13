/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pixbuf-painting helper factored out of kloak.c so fuzz/
 * fuzz_draw_block.c can exercise the bounds-clamping +
 * pixel-write loop without dragging in kloak's wayland / state
 * surface. Single source of truth: kloak.c #include's this
 * after kloak.h; the harness #include's just this header.
 */

#ifndef KLOAK_PIXBUF_INC_H
#define KLOAK_PIXBUF_INC_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Stamp a (2*rad+1) x (2*rad+1) block onto a pixbuf starting at
 * 'offset' (units of uint32_t pixels) with center (x, y).
 * Clamps x +/- rad, y +/- rad to the layer's [0, width-1] x
 * [0, height-1] range. When 'crosshair' is true, only the
 * vertical / horizontal lines through (x, y) get painted with
 * 'cursor_color'; the rest are cleared to 0x00000000.
 *
 * The arithmetic that builds the pixbuf index is done in
 * int64_t intermediates: work_y * layer_width can overflow
 * int32_t for adversarial layer_width values (production never
 * gets near INT32_MAX, but a hostile compositor / fuzzer can).
 * Production caller behaviour is unchanged for the small
 * pixel-count layer_widths kloak ever sees in real screens.
 *
 * Previously a 'assert(should_draw_cursor)' guarded the function
 * entry; the assert was a precondition check ('do not call when
 * cursor drawing is disabled'). Removed during the extract so
 * the helper is callable from the fuzz harness, which always
 * paints unconditionally. Production callers are still gated by
 * the should_draw_cursor check in draw_frame() before they
 * reach this function.
 */
static void draw_block(uint32_t *pixbuf, int32_t offset, int32_t x, int32_t y,
  int32_t layer_width, int32_t layer_height, int32_t rad, bool crosshair,
  uint32_t cursor_color) __attribute__((unused));
static void draw_block(uint32_t *pixbuf, int32_t offset, int32_t x, int32_t y,
  int32_t layer_width, int32_t layer_height, int32_t rad, bool crosshair,
  uint32_t cursor_color) {
  int32_t start_x = 0;
  int32_t start_y = 0;
  int32_t end_x = 0;
  int32_t end_y = 0;
  int32_t work_x = 0;
  int32_t work_y = 0;
  int64_t step_sx = 0;
  int64_t step_sy = 0;
  int64_t step_ex = 0;
  int64_t step_ey = 0;

  /*
   * Promote the four x/y +/- rad arithmetic sites to int64_t and
   * clamp every result to the layer's [0, dim-1] range. The
   * fuzz_draw_block harness in CFLite caught two issues here:
   * (a) 'x - rad' with x near INT32_MIN and rad large overflows
   *     int32_t and traps under -ftrapv, and
   * (b) a negative rad makes 'x - rad' larger than INT32_MAX, so
   *     even after the int64_t promotion the bare (int32_t) cast
   *     wraps to a negative value -- which the loop then uses as
   *     an array index and reads outside the pixbuf.
   * Clamping every step to [0, dim-1] makes the loop a no-op
   * when start > end after clamping (correct production
   * behaviour: nothing to paint). Production callers pass small
   * cursor coordinates and a tiny non-negative rad, so the
   * additional clamps never fire for real screens.
   */
  step_sx = (int64_t)x - (int64_t)rad;
  step_sy = (int64_t)y - (int64_t)rad;
  step_ex = (int64_t)x + (int64_t)rad;
  step_ey = (int64_t)y + (int64_t)rad;
  if (step_sx < 0) step_sx = 0;
  if (step_sy < 0) step_sy = 0;
  if (step_ex < 0) step_ex = 0;
  if (step_ey < 0) step_ey = 0;
  if (step_sx >= (int64_t)layer_width)  step_sx = (int64_t)layer_width  - 1;
  if (step_sy >= (int64_t)layer_height) step_sy = (int64_t)layer_height - 1;
  if (step_ex >= (int64_t)layer_width)  step_ex = (int64_t)layer_width  - 1;
  if (step_ey >= (int64_t)layer_height) step_ey = (int64_t)layer_height - 1;
  start_x = (int32_t)step_sx;
  start_y = (int32_t)step_sy;
  end_x   = (int32_t)step_ex;
  end_y   = (int32_t)step_ey;

  for (work_y = start_y; work_y <= end_y; work_y++) {
    for (work_x = start_x; work_x <= end_x; work_x++) {
      int64_t idx = (int64_t)offset
        + (int64_t)work_y * (int64_t)layer_width
        + (int64_t)work_x;
      if (crosshair && work_x == x) {
        pixbuf[idx] = cursor_color;
      } else if (crosshair && work_y == y) {
        pixbuf[idx] = cursor_color;
      } else {
        pixbuf[idx] = 0x00000000;
      }
    }
  }
}

#endif /* KLOAK_PIXBUF_INC_H */
