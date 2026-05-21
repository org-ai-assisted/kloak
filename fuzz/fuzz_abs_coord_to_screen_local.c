/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's abs_coord_to_screen_local_coord().
 * Maps a (x, y) point in compositor-global space to the matching
 * (output_idx, x, y) triple in screen-local space, scanning
 * state.output_geometries[] for the covering display. Worth fuzzing
 * for:
 *   - the cur_geom_x + cur_geom_width / cur_geom_y + cur_geom_height
 *     comparisons (-ftrapv on signed overflow)
 *   - the sign-check fall-throughs that skip negative geometries
 *   - the MAX_SCREEN_COUNT-bounded loop interacting with arbitrary
 *     output_geometries[] slot density (some NULL, some not)
 *
 * The harness fills state.output_geometries[] from fuzz input then
 * cleans up after each call.
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
  /* Static backing storage - see fuzz_recalc_global_space.c for why
     (overflow siglongjmp would leak a heap allocation). */
  static struct output_geometry geoms[MAX_SCREEN_COUNT];
  int32_t output_count = 0;
  size_t needed = 0;
  size_t hdr_len = 0;
  int32_t i = 0;
  int32_t query_x = 0;
  int32_t query_y = 0;

  KLOAK_FUZZ_OVERFLOW_GUARD();
  hdr_len = 1U + 2U * sizeof(int32_t);
  if (size < hdr_len) {
    return 0;
  }
  output_count = (int32_t)(data[0] % MAX_SCREEN_COUNT) + 1;
  memcpy(&query_x, data + 1U, sizeof(query_x));
  memcpy(&query_y, data + 1U + sizeof(int32_t), sizeof(query_y));
  needed = hdr_len + (size_t)output_count * sizeof(struct output_geometry);
  if (size < needed) {
    return 0;
  }

  memset(state.output_geometries, 0, sizeof(state.output_geometries));
  memset(geoms, 0, sizeof(geoms));

  for (i = 0; i < output_count; i++) {
    assert(i >= 0 && i < MAX_SCREEN_COUNT);
    memcpy(&geoms[i], data + hdr_len + (size_t)i * sizeof(geoms[i]),
      sizeof(geoms[i]));
    state.output_geometries[i] = &geoms[i];
  }

  (void)abs_coord_to_screen_local_coord(query_x, query_y);

  memset(state.output_geometries, 0, sizeof(state.output_geometries));
  return 0;
}
