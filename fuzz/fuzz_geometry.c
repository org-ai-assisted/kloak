/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for the kloak multi-screen geometry helpers
 * check_point_in_area() and check_screen_touch(). Both are pure
 * functions of their integer / struct output_geometry arguments
 * and are reached from recalc_global_space() whenever the
 * compositor reports a new output configuration. A compositor
 * cannot directly steer the inputs - they are deltas from
 * configure events - but signed-overflow or off-by-one bugs in
 * pixel-coordinate arithmetic are a classic bug class worth a
 * regression sentry.
 *
 * The harness consumes raw bytes as a packed sequence of int32_t
 * coordinates, fans them out across both helpers, and exercises
 * the union of the two functions' coverage surface in a single
 * binary.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../src/kloak_geometry.inc.h"

/* Pull a little-endian int32_t out of the fuzz input. Advances
 * *cursor by 4 bytes; if there are not enough bytes left, returns
 * 0 and clamps the cursor so the caller's next read is a no-op
 * too. */
static int32_t take_int32(const uint8_t *data, size_t size, size_t *cursor) {
  if (*cursor + sizeof(int32_t) > size) {
    *cursor = size;
    return 0;
  }
  int32_t v = 0;
  memcpy(&v, data + *cursor, sizeof(int32_t));
  *cursor += sizeof(int32_t);
  return v;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t c = 0;

  /* check_point_in_area: 6 int32_t args. */
  int32_t x      = take_int32(data, size, &c);
  int32_t y      = take_int32(data, size, &c);
  int32_t rx     = take_int32(data, size, &c);
  int32_t ry     = take_int32(data, size, &c);
  int32_t rw     = take_int32(data, size, &c);
  int32_t rh     = take_int32(data, size, &c);
  (void)check_point_in_area(x, y, rx, ry, rw, rh);

  /* check_screen_touch: 2 output_geometry structs (4 int32_t each). */
  struct output_geometry a = {
    .x      = take_int32(data, size, &c),
    .y      = take_int32(data, size, &c),
    .width  = take_int32(data, size, &c),
    .height = take_int32(data, size, &c),
  };
  struct output_geometry b = {
    .x      = take_int32(data, size, &c),
    .y      = take_int32(data, size, &c),
    .width  = take_int32(data, size, &c),
    .height = take_int32(data, size, &c),
  };
  (void)check_screen_touch(a, b);

  return 0;
}
