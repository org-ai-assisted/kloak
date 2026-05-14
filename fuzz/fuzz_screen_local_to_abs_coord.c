/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's screen_local_coord_to_abs_coord().
 * Inverse of abs_coord_to_screen_local_coord: given (x, y,
 * output_idx) in screen-local space, returns the compositor-global
 * coordinate. Worth fuzzing for:
 *   - cur_geom_x + x, cur_geom_y + y (-ftrapv on signed overflow)
 *   - the sign-check fall-through for negative geometries / inputs
 *
 * The function asserts 0 <= output_idx < MAX_SCREEN_COUNT, so the
 * harness clamps output_idx into that range before calling (the
 * asserts encode a caller contract, not a fuzz-finding surface).
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
  size_t hdr_len = 0;
  int32_t i = 0;
  int32_t query_x = 0;
  int32_t query_y = 0;
  int32_t output_idx_raw = 0;
  int32_t output_idx = 0;
  struct output_geometry *g = NULL;

  hdr_len = 1U + 3U * sizeof(int32_t);
  if (size < hdr_len) {
    return 0;
  }
  output_count = (int32_t)(data[0] % MAX_SCREEN_COUNT) + 1;
  memcpy(&query_x, data + 1U, sizeof(query_x));
  memcpy(&query_y, data + 1U + sizeof(int32_t), sizeof(query_y));
  memcpy(&output_idx_raw, data + 1U + 2U * sizeof(int32_t),
    sizeof(output_idx_raw));
  needed = hdr_len + (size_t)output_count * sizeof(struct output_geometry);
  if (size < needed) {
    return 0;
  }

  /* Map an arbitrary int32_t into [0, MAX_SCREEN_COUNT) via
     uint32_t modulo so the harness honours the assert(output_idx
     >= 0 && output_idx < MAX_SCREEN_COUNT) contract without itself
     invoking -ftrapv on the abs() path. */
  output_idx = (int32_t)(((uint32_t)output_idx_raw) % MAX_SCREEN_COUNT);

  memset(state.output_geometries, 0, sizeof(state.output_geometries));

  for (i = 0; i < output_count; i++) {
    g = malloc(sizeof(*g));
    if (g == NULL) {
      goto cleanup;
    }
    memcpy(g, data + hdr_len + (size_t)i * sizeof(*g), sizeof(*g));
    assert(i >= 0 && i < MAX_SCREEN_COUNT);
    state.output_geometries[i] = g;
  }

  (void)screen_local_coord_to_abs_coord(query_x, query_y, output_idx);

cleanup:
  for (i = 0; i < MAX_SCREEN_COUNT; i++) {
    assert(i >= 0 && i < MAX_SCREEN_COUNT);
    free(state.output_geometries[i]);
    state.output_geometries[i] = NULL;
  }
  return 0;
}
