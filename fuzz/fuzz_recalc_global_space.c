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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int32_t output_count = 0;
  size_t needed = 0;
  int32_t i = 0;
  struct output_geometry *g = NULL;

  if (size < 1U) {
    return 0;
  }
  output_count = (int32_t)(data[0] % MAX_SCREEN_COUNT) + 1;
  needed = 1U + (size_t)output_count * sizeof(struct output_geometry);
  if (size < needed) {
    return 0;
  }

  /* Defensive: clear all slots before populating, in case a previous
     iteration left a slot allocated (it should not, but the cost is
     trivial relative to the cleanup branch below). */
  memset(state.output_geometries, 0, sizeof(state.output_geometries));

  for (i = 0; i < output_count; i++) {
    g = malloc(sizeof(*g));
    if (g == NULL) {
      goto cleanup;
    }
    memcpy(g, data + 1U + (size_t)i * sizeof(*g), sizeof(*g));
    assert(i >= 0 && i < MAX_SCREEN_COUNT);
    state.output_geometries[i] = g;
  }

  recalc_global_space(&state);

cleanup:
  for (i = 0; i < MAX_SCREEN_COUNT; i++) {
    assert(i >= 0 && i < MAX_SCREEN_COUNT);
    free(state.output_geometries[i]);
    state.output_geometries[i] = NULL;
  }
  return 0;
}
