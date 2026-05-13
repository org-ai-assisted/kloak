/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure multi-screen geometry-recalculation surface factored out
 * of recalc_global_space() in kloak.c so fuzz/fuzz_recalc_global_
 * space.c can exercise the corner-finding + connectivity-graph
 * traversal + gap-detection logic without dragging in the rest
 * of the program. Single source of truth: kloak.c #include's
 * this after kloak_geometry.inc.h (which provides struct
 * output_geometry + check_screen_touch); the harness #include's
 * just kloak_geometry.inc.h + this header.
 *
 * Production semantics: kloak.c's recalc_global_space() is now a
 * thin wrapper that calls recalc_global_space_pure() and decides
 * what to do with each status:
 *   KLOAK_RECALC_INCOMPLETE  -> silent return (waiting for more
 *                               output configure events)
 *   KLOAK_RECALC_GAP         -> 'FATAL ERROR: ... gaps ...' + exit(1)
 *   KLOAK_RECALC_OK          -> copy the four global_space_* /
 *                               pointer_space_* fields into
 *                               disp_state
 * The exit(1) is intentionally kept out of the pure helper so
 * libFuzzer can exercise the gap-detection path without treating
 * the panic as a crash.
 */

#ifndef KLOAK_RECALC_INC_H
#define KLOAK_RECALC_INC_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Requires the following to be defined by the includer before
 * this header is processed:
 *   struct output_geometry { int32_t x, y, width, height; }
 *   bool check_screen_touch(struct output_geometry,
 *     struct output_geometry);
 * kloak.c gets these via kloak_geometry.inc.h; the fuzz harness
 * #include's kloak_geometry.inc.h directly before including
 * this file.
 */

enum kloak_recalc_status {
  KLOAK_RECALC_INCOMPLETE = 0,
  KLOAK_RECALC_GAP        = 1,
  KLOAK_RECALC_OK         = 2
};

struct kloak_recalc_result {
  enum kloak_recalc_status status;
  int32_t global_space_width;
  int32_t global_space_height;
  int32_t pointer_space_x;
  int32_t pointer_space_y;
};

/*
 * Walk 'geometries' (an array of pointers, NULL slots skipped),
 * find the union bounding box and detect whether the screens
 * form a single connected blob (no gaps). Returns one of the
 * status codes above; on KLOAK_RECALC_OK the four global / pointer
 * space fields are filled, otherwise they are 0.
 *
 * Bounds on geometries_len: KLOAK_RECALC_MAX_SCREENS (mirrors
 * kloak.c's MAX_SCREEN_COUNT). The production caller passes the
 * full MAX_SCREEN_COUNT slot count from disp_state; the harness
 * supplies a smaller bound but never larger.
 */
#ifndef KLOAK_RECALC_MAX_SCREENS
#define KLOAK_RECALC_MAX_SCREENS 128
#endif

static __attribute__((unused))
struct kloak_recalc_result recalc_global_space_pure(
  struct output_geometry *const *geometries,
  size_t geometries_len) {
  struct kloak_recalc_result out = { 0 };
  int32_t ul_corner_x = INT32_MAX;
  int32_t ul_corner_y = INT32_MAX;
  int32_t br_corner_x = 0;
  int32_t br_corner_y = 0;
  int32_t cur_geom_x = 0;
  int32_t cur_geom_y = 0;
  int32_t cur_geom_width = 0;
  int32_t cur_geom_height = 0;
  int32_t temp_br_x = 0;
  int32_t temp_br_y = 0;
  struct output_geometry *screen_list[KLOAK_RECALC_MAX_SCREENS];
  ssize_t screen_list_len = 0;
  struct output_geometry *conn_screen_list[KLOAK_RECALC_MAX_SCREENS];
  ssize_t conn_screen_list_len = 0;
  bool screen_in_conn_list = false;
  struct output_geometry *conn_screen = NULL;
  struct output_geometry *cur_screen = NULL;
  size_t i = 0;
  ssize_t ci = 0;
  ssize_t j = 0;
  ssize_t k = 0;

  if (geometries == NULL) {
    return out;
  }
  if (geometries_len > KLOAK_RECALC_MAX_SCREENS) {
    geometries_len = KLOAK_RECALC_MAX_SCREENS;
  }

  for (i = 0; i < geometries_len; i++) {
    if (geometries[i] == NULL) {
      continue;
    }
    cur_geom_x = geometries[i]->x;
    cur_geom_y = geometries[i]->y;
    cur_geom_width = geometries[i]->width;
    cur_geom_height = geometries[i]->height;
    if (cur_geom_x < 0 || cur_geom_y < 0
      || cur_geom_width < 0 || cur_geom_height < 0) {
      continue;
    }
    /*
     * Reject geometries whose corner coordinates would overflow
     * int32_t arithmetic. Same int64 guard the fuzz_geometry
     * harness installed on check_point_in_area /
     * check_screen_touch.
     */
    if ((int64_t)cur_geom_x + (int64_t)cur_geom_width > INT32_MAX
      || (int64_t)cur_geom_y + (int64_t)cur_geom_height > INT32_MAX) {
      continue;
    }
    screen_list[screen_list_len] = geometries[i];
    screen_list_len++;
    if (cur_geom_x < ul_corner_x) {
      ul_corner_x = cur_geom_x;
    }
    if (cur_geom_y < ul_corner_y) {
      ul_corner_y = cur_geom_y;
    }
    temp_br_x = cur_geom_x + cur_geom_width;
    temp_br_y = cur_geom_y + cur_geom_height;
    if (temp_br_x > br_corner_x) {
      br_corner_x = temp_br_x;
    }
    if (temp_br_y > br_corner_y) {
      br_corner_y = temp_br_y;
    }
  }

  if (screen_list_len <= 0) {
    out.status = KLOAK_RECALC_INCOMPLETE;
    return out;
  }
  if (ul_corner_x > br_corner_x) {
    out.status = KLOAK_RECALC_INCOMPLETE;
    return out;
  }
  if (ul_corner_y > br_corner_y) {
    out.status = KLOAK_RECALC_INCOMPLETE;
    return out;
  }

  conn_screen_list[0] = screen_list[0];
  conn_screen_list_len = 1;

  /*
   * Connectivity flood-fill. Start from screen 0, find every
   * screen that touches one already in the connected set, and
   * repeat. If conn_screen_list_len == screen_list_len at the
   * end, the whole set is connected; otherwise there is a gap.
   */
  for (ci = 0; ci < conn_screen_list_len; ci++) {
    for (j = 0; j < screen_list_len; j++) {
      screen_in_conn_list = false;
      for (k = 0; k < conn_screen_list_len; k++) {
        if (screen_list[j] == conn_screen_list[k]) {
          screen_in_conn_list = true;
          break;
        }
      }
      if (screen_in_conn_list) {
        continue;
      }
      conn_screen = conn_screen_list[ci];
      cur_screen = screen_list[j];
      if (check_screen_touch(*conn_screen, *cur_screen)) {
        conn_screen_list[conn_screen_list_len] = cur_screen;
        conn_screen_list_len++;
      }
    }
  }

  if (conn_screen_list_len != screen_list_len) {
    out.status = KLOAK_RECALC_GAP;
    return out;
  }

  out.status = KLOAK_RECALC_OK;
  out.global_space_width = br_corner_x;
  out.global_space_height = br_corner_y;
  out.pointer_space_x = ul_corner_x;
  out.pointer_space_y = ul_corner_y;
  return out;
}

#endif /* KLOAK_RECALC_INC_H */
