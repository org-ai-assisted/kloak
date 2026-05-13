/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure-geometry surface for kloak's multi-screen recalculation.
 * Included by kloak.c (where the helpers are called from
 * recalc_global_space) and by the libFuzzer harness in
 * fuzz/fuzz_geometry.c. The functions touch nothing but their
 * int32_t / struct output_geometry arguments, so the harness
 * binary picks up only this header's content with zero
 * libinput / wayland linkage.
 *
 * Single source of truth: editing these functions or the
 * output_geometry struct here is automatically picked up by
 * both kloak proper (kloak.h forward-declares 'struct
 * output_geometry' for its disp_state pointer fields; the full
 * definition lives below) and the fuzz harness.
 */

#ifndef KLOAK_GEOMETRY_INC_H
#define KLOAK_GEOMETRY_INC_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Defines the position and dimensions of a screen.
 */
struct output_geometry {
  int32_t x;
  int32_t y;
  int32_t width;
  int32_t height;
};

/*
 * Determine if a point falls inside an area.
 *
 * All arithmetic that combines coordinates with widths/heights is
 * done in int64_t to avoid signed-integer overflow on
 * adversarially large geometry inputs. Production callers see
 * compositor pixel coordinates that never approach INT32_MAX, but
 * the fuzz harness in fuzz/fuzz_geometry.c does, and UBSan flags
 * the bare int32_t addition as UB even though x86 wraps it
 * harmlessly.
 */
static __attribute__((unused))
bool check_point_in_area(int32_t x, int32_t y, int32_t rect_x,
  int32_t rect_y, int32_t rect_width, int32_t rect_height) {
  int64_t rect_right = 0;
  int64_t rect_bottom = 0;
  if (x < 0 || y < 0 || rect_x < 0 || rect_y < 0 || rect_width < 0
    || rect_height < 0) {
    return false;
  }
  rect_right = (int64_t)rect_x + (int64_t)rect_width;
  rect_bottom = (int64_t)rect_y + (int64_t)rect_height;
  if (x >= rect_x && (int64_t)x < rect_right
    && y >= rect_y && (int64_t)y < rect_bottom) {
    return true;
  }
  return false;
}

/*
 * Determine if two screens are touching or overlapping given their
 * geometries.
 *
 * As in check_point_in_area, every addition that combines a
 * coordinate with a width/height is performed via an int64_t
 * intermediate. We also reject inputs whose corner coordinates
 * would overflow int32_t: production callers never produce such
 * inputs (real screen pixel counts are small) but the fuzz
 * harness exercises the full int32 range, and the alternative -
 * letting UBSan trip on every adversarial input - hides any
 * future real bug behind boilerplate findings.
 */
static __attribute__((unused))
bool check_screen_touch(struct output_geometry scr1,
  struct output_geometry scr2) {
  /*
   * We check for both touching and overlapping screens. Screens are
   * overlapping if any of one screen's corner points falls inside the area of
   * the other screen. The criteria to establish touching screens is a bit
   * tricky, but a shortcut we can take is to simply grow the size of one of
   * the screens by one pixel in every direction (i.e., subtract one from both
   * the X and Y position coordinates and then add two to the width and
   * height). Then any form of screen touching will be seen as an overlap,
   * including touching at the corners.
   */

  if (scr1.x < 0 || scr1.y < 0 || scr1.width < 0 || scr1.height < 0
    || scr2.x < 0 || scr2.y < 0 || scr2.width < 0 || scr2.height < 0) {
    return false;
  }
  /*
   * Reject inputs whose grown / corner coordinates would step
   * outside int32_t. +2 is the maximum width/height bump from
   * the grow step below.
   */
  if ((int64_t)scr1.x + (int64_t)scr1.width + 2 > INT32_MAX
    || (int64_t)scr1.y + (int64_t)scr1.height + 2 > INT32_MAX
    || (int64_t)scr2.x + (int64_t)scr2.width > INT32_MAX
    || (int64_t)scr2.y + (int64_t)scr2.height > INT32_MAX) {
    return false;
  }

  if (scr1.x > 0) {
    scr1.x -= 1;
    scr1.width += 2;
  } else {
    scr1.width += 1;
  }
  if (scr1.y > 0) {
    scr1.y -= 1;
    scr1.height += 2;
  } else {
    scr1.height += 1;
  }

  if (check_point_in_area(scr1.x, scr1.y, scr2.x, scr2.y, scr2.width,
    scr2.height)) {
    return true;
  }
  if (check_point_in_area(scr1.x + scr1.width, scr1.y, scr2.x, scr2.y,
    scr2.width, scr2.height)) {
    return true;
  }
  if (check_point_in_area(scr1.x, scr1.y + scr1.height, scr2.x, scr2.y,
    scr2.width, scr2.height)) {
    return true;
  }
  if (check_point_in_area(scr1.x + scr1.width, scr1.y + scr1.height, scr2.x,
    scr2.y, scr2.width, scr2.height)) {
    return true;
  }
  /*
   * It's possible for none of screen 1's corners to be inside screen 2, but
   * for some of screen 2's corners to be inside screen 1, i.e. in this
   * configuration:
   *
   * +------------------+
   * |                  |
   * |               +------------------+
   * |     Screen 1  |  |  Screen 2     |
   * |               +------------------+
   * |                  |
   * +------------------+
   *
   * Therefore we need to repeat the above checks to see if screen 2 has a
   * corner within screen 1. We do NOT need to grow screen 2 by one pixel in
   * all directions like we did with screen 1; the growing of screen 1 is
   * enough to allow touch detection, we just need to actually detect it.
   */
  if (check_point_in_area(scr2.x, scr2.y, scr1.x, scr1.y, scr1.width,
    scr1.height)) {
    return true;
  }
  if (check_point_in_area(scr2.x + scr2.width, scr2.y, scr1.x, scr1.y,
    scr1.width, scr1.height)) {
    return true;
  }
  if (check_point_in_area(scr2.x, scr2.y + scr2.height, scr1.x, scr1.y,
    scr1.width, scr1.height)) {
    return true;
  }
  if (check_point_in_area(scr2.x + scr2.width, scr2.y + scr2.height, scr1.x,
    scr1.y, scr1.width, scr1.height)) {
    return true;
  }
  return false;
}

#endif /* KLOAK_GEOMETRY_INC_H */
