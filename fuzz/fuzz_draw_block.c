/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for draw_block() (kloak_pixbuf.inc.h), the
 * crosshair / clear painter kloak uses to stamp the virtual
 * cursor onto each output layer's pixbuf. Production callers
 * pass coordinates derived from compositor screen geometry
 * (~thousands of pixels); the harness sweeps the parameter
 * space adversarially so libFuzzer + UBSan catch any signed-
 * arithmetic overflow or off-by-one in the bounds-clamping
 * loop.
 *
 * Invariant the harness enforces: layer_width and layer_height
 * are constants chosen so 'offset + work_y*layer_width + work_x'
 * cannot exceed the pre-allocated pixbuf size even at maximum
 * clamped extents. That keeps OOB writes out of the harness'
 * own bookkeeping while still exercising every interesting
 * branch of draw_block: clamping start_x/y < 0, end_x/y >=
 * layer_width/height, the crosshair-on-x / crosshair-on-y /
 * cleared-pixel ternary.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/kloak_pixbuf.inc.h"

/*
 * Pixbuf dimensions chosen to give the fuzzer a non-trivial
 * canvas (256 x 256 = 64 KiB) while keeping the maximum
 * draw_block index <= 65535. The fuzzed 'offset' is masked to
 * one of the slots so 'offset + 65535 < total pixbuf size'.
 */
#define KLOAK_FUZZ_LAYER_W 256
#define KLOAK_FUZZ_LAYER_H 256
#define KLOAK_FUZZ_FRAME_PIXELS (KLOAK_FUZZ_LAYER_W * KLOAK_FUZZ_LAYER_H)
#define KLOAK_FUZZ_FRAME_COUNT 4
#define KLOAK_FUZZ_TOTAL_PIXELS (KLOAK_FUZZ_FRAME_PIXELS * KLOAK_FUZZ_FRAME_COUNT)

static uint32_t g_pixbuf[KLOAK_FUZZ_TOTAL_PIXELS];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Each call consumes:
   *   1 byte    crosshair (low bit) + frame-slot selector (next 2 bits)
   *   4 bytes   x  (int32, LE)
   *   4 bytes   y  (int32, LE)
   *   4 bytes   rad (int32, LE)
   *   4 bytes   cursor_color (uint32, LE)
   */
  uint8_t flags = 0;
  bool crosshair = false;
  uint32_t frame_slot = 0;
  int32_t x = 0;
  int32_t y = 0;
  int32_t rad = 0;
  uint32_t cursor_color = 0;
  int32_t offset = 0;

  if (size < 17U) {
    return 0;
  }

  flags = data[0];
  crosshair = (flags & 0x1) != 0;
  frame_slot = (flags >> 1) & 0x3;
  memcpy(&x, data + 1, sizeof(int32_t));
  memcpy(&y, data + 5, sizeof(int32_t));
  memcpy(&rad, data + 9, sizeof(int32_t));
  memcpy(&cursor_color, data + 13, sizeof(uint32_t));

  offset = (int32_t)(frame_slot * KLOAK_FUZZ_FRAME_PIXELS);
  draw_block(g_pixbuf, offset, x, y,
    KLOAK_FUZZ_LAYER_W, KLOAK_FUZZ_LAYER_H, rad, crosshair, cursor_color);
  return 0;
}
