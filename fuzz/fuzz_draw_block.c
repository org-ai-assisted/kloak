/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's draw_block(). Renders the virtual
 * cursor (or crosshair) into a pixel buffer. The function is fed
 * compositor-derived dimensions in production, never attacker
 * input, but exercising it under ASan/UBSan still surfaces real
 * arithmetic concerns:
 *   - start_x = x - rad, end_x = x + rad, plus the start/end_y
 *     siblings (-ftrapv on signed overflow)
 *   - the clamp branches start_x < 0, end_x >= layer_width and
 *     their y-axis siblings
 *   - the pixbuf write index offset + (work_y * layer_width +
 *     work_x), bounded by ASan
 *
 * Inputs are clamped via well-defined uint32_t modulo before being
 * cast back to int32_t so the harness setup itself never invokes
 * -ftrapv on truly arbitrary fuzz bytes; the target function still
 * sees a wide range of (x, y, rad, dims) tuples in the bands kloak
 * actually drives in production.
 *
 * The default value of `should_draw_cursor` in kloak.c is already
 * true; we set it explicitly anyway to make the assertion intent
 * obvious to the next reader.
 */

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"
#include "fuzz_overflow_recovery.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /*
   * Static backing buffer rather than calloc: draw_block's checked
   * arithmetic can siglongjmp out on overflow (via
   * KLOAK_FUZZ_OVERFLOW_GUARD), which would skip a free() and leak.
   * Sized to the maximum the dim/offset bounds below allow:
   * offset (< 1024) + layer_width (<= 256) * layer_height (<= 256).
   */
  static uint32_t pixbuf[1024U + (256U * 256U)];
  struct {
    int32_t x;
    int32_t y;
    int32_t layer_width;
    int32_t layer_height;
    int32_t rad;
    int32_t offset;
    uint8_t crosshair;
  } hdr = { 0 };
  size_t pixbuf_len = 0;

  KLOAK_FUZZ_OVERFLOW_GUARD();
  if (size < sizeof(hdr)) {
    return 0;
  }
  memcpy(&hdr, data, sizeof(hdr));

  /*
   * Bound only the layer dimensions and offset, via uint32_t modulo
   * (well-defined wrap), so the write index stays inside the static
   * pixbuf and draw_block's internal end_x/end_y clamps hold.
   *
   * x / y / rad are deliberately left UNbounded now that the
   * foundation routes draw_block's x +/- rad and
   * offset + work_y*layer_width + work_x arithmetic through the
   * checked helpers: an overflowing coordinate is detected and
   * recovered via KLOAK_FUZZ_OVERFLOW_GUARD rather than trapping, so
   * the fuzzer is free to explore the full int32 coordinate space.
   */
  hdr.layer_width = (int32_t)(((uint32_t)hdr.layer_width) % 256U) + 1;
  hdr.layer_height = (int32_t)(((uint32_t)hdr.layer_height) % 256U) + 1;
  hdr.offset = (int32_t)(((uint32_t)hdr.offset) % 1024U);

  pixbuf_len = (size_t)hdr.offset
    + ((size_t)hdr.layer_width * (size_t)hdr.layer_height);
  assert(pixbuf_len <= sizeof(pixbuf) / sizeof(pixbuf[0]));
  memset(pixbuf, 0, pixbuf_len * sizeof(pixbuf[0]));

  should_draw_cursor = true;
  cursor_color = 0xff00ff00U;

  draw_block(pixbuf, hdr.offset, hdr.x, hdr.y, hdr.layer_width,
    hdr.layer_height, hdr.rad, (hdr.crosshair & 0x1U) != 0U);

  return 0;
}
