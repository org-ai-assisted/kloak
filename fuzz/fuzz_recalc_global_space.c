/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's recalc_global_space(). Computes
 * the bounding box of the active displays and detects gaps between
 * them; called whenever the compositor reports a new output layout.
 * Worth fuzzing for:
 *   - the bounding-box arithmetic
 *       temp_br_x = cur_geom_x + cur_geom_width
 *       temp_br_y = cur_geom_y + cur_geom_height
 *     on signed int32_t (-ftrapv on overflow)
 *   - the transitive check_screen_touch() graph traversal that
 *     walks every screen pair
 *
 * The harness populates state.output_geometries[] from fuzz input
 * before each call. Production code hits this with at most one
 * output per physical display; the harness exercises up to
 * MAX_SCREEN_COUNT (128) outputs per iteration.
 *
 * The gap-detection FATAL ERROR (kloak.c around line 707) is
 * suppressed under KLOAK_FUZZING; otherwise random inputs would
 * trigger it on the overwhelming majority of layouts and the
 * fuzzer would never reach the arithmetic paths we care about.
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
   * Static backing storage rather than malloc: recalc_global_space's
   * checked arithmetic can siglongjmp out on overflow (via
   * KLOAK_FUZZ_OVERFLOW_GUARD), which would skip a heap cleanup and
   * leak. Static storage has nothing to leak - the overflow path
   * just returns, and the next iteration overwrites it.
   */
  static struct output_geometry geoms[MAX_SCREEN_COUNT];
  int32_t output_count = 0;
  size_t needed = 0;
  int32_t i = 0;

  KLOAK_FUZZ_OVERFLOW_GUARD();
  if (size < 1U) {
    return 0;
  }
  output_count = (int32_t)(data[0] % MAX_SCREEN_COUNT) + 1;
  needed = 1U + (size_t)output_count * sizeof(struct output_geometry);
  if (size < needed) {
    return 0;
  }

  memset(state.output_geometries, 0, sizeof(state.output_geometries));
  memset(geoms, 0, sizeof(geoms));

  for (i = 0; i < output_count; i++) {
    assert(i >= 0 && i < MAX_SCREEN_COUNT);
    memcpy(&geoms[i], data + 1U + (size_t)i * sizeof(geoms[i]),
      sizeof(geoms[i]));
    state.output_geometries[i] = &geoms[i];
  }

  recalc_global_space(&state);

  memset(state.output_geometries, 0, sizeof(state.output_geometries));
  return 0;
}
