/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure line-walking helper factored out of kloak.c so
 * fuzz/fuzz_traverse_line.c can exercise the slope / fabs /
 * int32-cast arithmetic without dragging in the rest of kloak.
 * Single source of truth: kloak.c #include's this after kloak.h
 * (which defines 'struct coord'); the fuzz harness defines its
 * own equivalent 'struct coord' shim before including this
 * header.
 *
 * Production semantics unchanged. The function walks a 2D line
 * from 'start' towards 'end' by 'pos' pixels and returns the
 * intermediate coord; update_virtual_cursor() iterates pos from
 * 0 to the integer distance between the points.
 */

#ifndef KLOAK_TRAVERSE_INC_H
#define KLOAK_TRAVERSE_INC_H

#include <limits.h>
#include <math.h>
#include <stdint.h>

/*
 * Requires 'struct coord { int32_t x; int32_t y; }' to be defined
 * by the includer. kloak.h provides it for production builds; the
 * fuzz harness defines an identical shim.
 */

/*
 * Clamp a double to the signed-int32 range. The original
 * traverse_line did '(int32_t)((double) pos * steep)' directly;
 * that cast is undefined behaviour when the double exceeds
 * int32_t range, which fuzz/fuzz_traverse_line.c exposed at
 * adversarial inputs. Production callers stay well below
 * INT32_MAX so behaviour is unchanged for real geometry.
 */
static int64_t kloak_clamp_double_to_int32(double d) __attribute__((unused));
static int64_t kloak_clamp_double_to_int32(double d) {
  if (d >= (double)INT32_MAX) return INT32_MAX;
  if (d <= (double)INT32_MIN) return INT32_MIN;
  return (int64_t)d;
}

static struct coord traverse_line(struct coord start, struct coord end,
  int32_t pos) __attribute__((unused));
static struct coord traverse_line(struct coord start, struct coord end,
  int32_t pos) {
  struct coord out_val = { 0 };
  double num = 0.0;
  double denom = 0.0;
  double slope = 0.0;
  double steep = 0.0;
  int64_t step_x = 0;
  int64_t step_y = 0;
  int64_t off = 0;

  num = ((double) end.y) - ((double) start.y);
  denom = ((double) start.x) - ((double) end.x);

  if (pos == 0) return start;

  if ((int64_t)(denom) == 0) {
    /* vertical line */
    step_x = (int64_t)start.x;
    if (start.y < end.y) {
      step_y = (int64_t)start.y + (int64_t)pos;
    } else {
      step_y = (int64_t)start.y - (int64_t)pos;
    }
    goto clamp_and_return;
  }

  slope = num / denom;
  steep = fabs(slope);

  if (steep < 1) {
    if (start.x < end.x) {
      step_x = (int64_t)start.x + (int64_t)pos;
    } else {
      step_x = (int64_t)start.x - (int64_t)pos;
    }
    off = kloak_clamp_double_to_int32((double) pos * steep);
    if (start.y < end.y) {
      step_y = (int64_t)start.y + off;
    } else {
      step_y = (int64_t)start.y - off;
    }
  } else {
    if (start.y < end.y) {
      step_y = (int64_t)start.y + (int64_t)pos;
    } else {
      step_y = (int64_t)start.y - (int64_t)pos;
    }
    off = kloak_clamp_double_to_int32((double) pos * (1.0 / steep));
    if (start.x < end.x) {
      step_x = (int64_t)start.x + off;
    } else {
      step_x = (int64_t)start.x - off;
    }
  }

clamp_and_return:
  if (step_x > INT32_MAX) step_x = INT32_MAX;
  if (step_x < INT32_MIN) step_x = INT32_MIN;
  if (step_y > INT32_MAX) step_y = INT32_MAX;
  if (step_y < INT32_MIN) step_y = INT32_MIN;
  out_val.x = (int32_t)step_x;
  out_val.y = (int32_t)step_y;
  return out_val;
}

#endif /* KLOAK_TRAVERSE_INC_H */
