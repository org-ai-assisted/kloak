/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure coordinate-conversion helpers factored out of kloak.c so
 * fuzz/fuzz_coord.c can exercise the global<->local mapping
 * without dragging in the rest of the program. Single source of
 * truth: kloak.c #include's this after kloak_geometry.inc.h
 * (which provides struct output_geometry and check_point_in_area)
 * and the fuzz harness #include's just these two .inc.h files.
 *
 * Production semantics: abs_coord_to_screen_local_coord and
 * screen_local_coord_to_abs_coord in kloak.c are now thin
 * wrappers around these.
 *
 * Bug class addressed: coord_local_to_abs_pure adds
 * 'geom->x + x' and 'geom->y + y' in int64_t with a saturating
 * range check. The original int32_t add was UB on adversarial
 * compositor geometry (same class fuzz_geometry already flagged
 * for check_screen_touch / check_point_in_area / recalc_global_
 * space). Production callers never come close to INT32_MAX, so
 * behaviour is unchanged for real screens.
 */

#ifndef KLOAK_COORD_INC_H
#define KLOAK_COORD_INC_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Requires the following to be defined by the includer before this
 * header is processed:
 *   struct coord              { int32_t x, y; }
 *   struct screen_local_coord { int32_t x, y, output_idx; bool valid; }
 *   struct output_geometry    { int32_t x, y, width, height; }
 *   bool check_point_in_area(int32_t x, int32_t y, int32_t rect_x,
 *     int32_t rect_y, int32_t rect_width, int32_t rect_height);
 *
 * kloak.c gets these via kloak.h + kloak_geometry.inc.h. The fuzz
 * harness defines shims that mirror those types and then
 * #include's kloak_geometry.inc.h for check_point_in_area before
 * including this file.
 */

/*
 * Look up which output the (x, y) compositor-global coordinate
 * falls inside, and translate to that output's screen-local
 * coordinates. Returns an all-zero screen_local_coord (valid =
 * false, x = y = output_idx = 0) if no output covers the point.
 *
 * 'geometries' is an array of pointers; entries may be NULL
 * (slot reserved but no geometry yet) and those are skipped.
 */
static struct screen_local_coord coord_abs_to_local_pure(int32_t x, int32_t y,
  struct output_geometry *const *geometries,
  size_t geometries_len) __attribute__((unused));
static struct screen_local_coord coord_abs_to_local_pure(int32_t x, int32_t y,
  struct output_geometry *const *geometries,
  size_t geometries_len) {
  struct screen_local_coord out_data = { 0 };
  size_t i = 0;

  if (x < 0 || y < 0) {
    return out_data;
  }

  for (i = 0; i < geometries_len; i++) {
    if (geometries[i] == NULL) {
      continue;
    }
    if (check_point_in_area(x, y, geometries[i]->x, geometries[i]->y,
      geometries[i]->width, geometries[i]->height)) {
      out_data.output_idx = (int32_t)i;
      out_data.x = x - geometries[i]->x;
      out_data.y = y - geometries[i]->y;
      out_data.valid = true;
      return out_data;
    }
  }

  return out_data;
}

/*
 * Translate a screen-local (x, y) on the given output back to
 * compositor-global coordinates. Returns {-1, -1} on invalid
 * input (negative coords, NULL geom, negative geometry fields,
 * or sum overflowing int32_t).
 */
static struct coord coord_local_to_abs_pure(int32_t x, int32_t y,
  const struct output_geometry *geom) __attribute__((unused));
static struct coord coord_local_to_abs_pure(int32_t x, int32_t y,
  const struct output_geometry *geom) {
  struct coord out_val = { .x = -1, .y = -1 };
  int64_t abs_x = 0;
  int64_t abs_y = 0;

  if (geom == NULL) {
    return out_val;
  }
  if (x < 0 || y < 0) {
    return out_val;
  }
  if (geom->x < 0 || geom->y < 0 || geom->width < 0 || geom->height < 0) {
    return out_val;
  }

  abs_x = (int64_t)geom->x + (int64_t)x;
  abs_y = (int64_t)geom->y + (int64_t)y;
  if (abs_x > INT32_MAX || abs_y > INT32_MAX) {
    return out_val;
  }

  out_val.x = (int32_t)abs_x;
  out_val.y = (int32_t)abs_y;
  return out_val;
}

#endif /* KLOAK_COORD_INC_H */
