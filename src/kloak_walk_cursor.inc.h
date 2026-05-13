/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure 'glide along the wall' cursor walker, factored out of
 * the inner loop of update_virtual_cursor() in kloak.c so
 * fuzz/fuzz_walk_cursor.c can exercise the algorithm against
 * adversarial start/end coordinates + screen layouts without
 * dragging in libinput / wayland / cursor / scroll globals.
 *
 * The algorithm: walk a straight line from start to end, one
 * pixel at a time. If the next pixel is off-screen, try to
 * step back one pixel in whichever direction we just moved and
 * adjust 'end' so the remaining walk stays in that dimension.
 * If none of the four directional rebounds land on a screen,
 * snap to the previous on-screen pixel and stop. The walk loop
 * terminates when both axes have reached 'end'.
 *
 * Production wrapper (kloak.c::update_virtual_cursor) feeds the
 * result back into the cursor_x / cursor_y globals and flags
 * the relevant drawable_layer for redraw. The pure helper does
 * neither - it just returns the final coord and lets the caller
 * apply it.
 *
 * Safety bound: 'max_iterations'. Production passes a large
 * value bounded by the manhattan distance between start and
 * end (a few thousand for real cursor moves). The fuzz harness
 * caps it tightly so an adversarial geometry that would
 * theoretically infinite-loop the glide algorithm shows up as
 * a bounded-time test failure rather than as a libFuzzer hang.
 */

#ifndef KLOAK_WALK_CURSOR_INC_H
#define KLOAK_WALK_CURSOR_INC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Requires the following to be defined by the includer before
 * this header is processed:
 *   struct coord              { int32_t x, y; }
 *   struct screen_local_coord { int32_t x, y, output_idx; bool valid; }
 *   struct output_geometry    { int32_t x, y, width, height; }
 *   coord_abs_to_local_pure(int32_t, int32_t, ...) -> struct screen_local_coord
 *   traverse_line(struct coord, struct coord, int32_t) -> struct coord
 *
 * kloak.c #include's this after kloak_coord.inc.h and
 * kloak_traverse.inc.h. The fuzz harness defines shims for the
 * structs and includes the same .inc.h headers.
 */

/*
 * Walk a 2D cursor from 'start' to 'end', constrained to
 * remain within the union of the given output geometries.
 *
 * Returns the final cursor position. 'reached_end' is set to
 * true if both axes hit 'end' before max_iterations expired,
 * false otherwise (degenerate input, off-screen-stuck, or
 * iteration-cap hit).
 */
struct kloak_walk_cursor_result {
  struct coord final_pos;
  bool reached_end;
};

static __attribute__((unused))
struct kloak_walk_cursor_result walk_cursor_pure(
  struct coord start, struct coord end,
  struct output_geometry *const *geometries,
  size_t geometries_len,
  int32_t max_iterations) {
  struct kloak_walk_cursor_result out = { 0 };
  struct coord prev_trav_coord = { 0 };
  struct coord trav_coord = { 0 };
  struct screen_local_coord trav_scr_coord = { 0 };
  bool end_x_hit = false;
  bool end_y_hit = false;
  int32_t i = 0;
  int32_t iter_count = 0;

  out.final_pos = start;
  prev_trav_coord = start;

  for (i = 0; iter_count < max_iterations; i++, iter_count++) {
    trav_coord = traverse_line(start, end, i);
    if (trav_coord.x == end.x) end_x_hit = true;
    if (trav_coord.y == end.y) end_y_hit = true;
    trav_scr_coord = coord_abs_to_local_pure(trav_coord.x, trav_coord.y,
      geometries, geometries_len);
    if (!trav_scr_coord.valid) {
      /*
       * Walked off-screen. Try the four directional rebounds:
       * step back one pixel in whichever axis we just moved
       * and re-aim 'end' to keep the rest of the walk in that
       * single dimension. The four prev_trav_coord.X < / >
       * branches mirror the four production code paths.
       *
       * Each rebound resets i = -1 so the next loop iteration
       * starts the walk from i = 0 against the adjusted start/
       * end pair. iter_count keeps counting so an adversarial
       * geometry that always rebounds without making progress
       * is bounded by max_iterations.
       */
      if (prev_trav_coord.x < trav_coord.x) {
        trav_scr_coord = coord_abs_to_local_pure(trav_coord.x - 1,
          trav_coord.y, geometries, geometries_len);
        if (trav_scr_coord.valid) {
          start.x = trav_coord.x - 1;
          start.y = trav_coord.y;
          end.x = trav_coord.x - 1;
          i = -1;
          continue;
        }
      }
      if (prev_trav_coord.x > trav_coord.x) {
        trav_scr_coord = coord_abs_to_local_pure(trav_coord.x + 1,
          trav_coord.y, geometries, geometries_len);
        if (trav_scr_coord.valid) {
          start.x = trav_coord.x + 1;
          start.y = trav_coord.y;
          end.x = trav_coord.x + 1;
          i = -1;
          continue;
        }
      }
      if (prev_trav_coord.y < trav_coord.y) {
        trav_scr_coord = coord_abs_to_local_pure(trav_coord.x,
          trav_coord.y - 1, geometries, geometries_len);
        if (trav_scr_coord.valid) {
          start.y = trav_coord.y - 1;
          start.x = trav_coord.x;
          end.y = trav_coord.y - 1;
          i = -1;
          continue;
        }
      }
      if (prev_trav_coord.y > trav_coord.y) {
        trav_scr_coord = coord_abs_to_local_pure(trav_coord.x,
          trav_coord.y + 1, geometries, geometries_len);
        if (trav_scr_coord.valid) {
          start.y = trav_coord.y + 1;
          start.x = trav_coord.x;
          end.y = trav_coord.y + 1;
          i = -1;
          continue;
        }
      }
      /* Stuck - snap to the previous on-screen pixel and stop. */
      out.final_pos = prev_trav_coord;
      return out;
    }
    if (end_x_hit && end_y_hit) {
      out.final_pos = end;
      out.reached_end = true;
      return out;
    }
    prev_trav_coord = trav_coord;
  }
  /* iteration cap hit - return the last on-screen coord we saw */
  out.final_pos = prev_trav_coord;
  return out;
}

#endif /* KLOAK_WALK_CURSOR_INC_H */
