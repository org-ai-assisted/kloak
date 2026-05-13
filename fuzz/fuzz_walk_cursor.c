/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for walk_cursor_pure() - the
 * glide-along-the-wall cursor walker extracted from the inner
 * loop of update_virtual_cursor() in kloak.c. Production
 * reaches this every time the user moves the mouse, with
 * start/end constrained to int32 cursor coordinates and the
 * geometries fed from disp_state. The harness sweeps the full
 * int32 range for start/end and feeds fuzz-controlled
 * geometries (up to 8 entries, NULL slots interleaved) so it
 * can exercise:
 *
 *   - The walk_cursor termination invariant (both axes must
 *     reach end OR the iteration cap fires)
 *   - The four directional rebounds when traverse_line steps
 *     off-screen
 *   - The 'snap to prev on-screen pixel' diagonal-stuck branch
 *   - int32 +/- 1 arithmetic on trav_coord at INT32_MIN /
 *     INT32_MAX boundaries
 *   - Behaviour when no geometry covers the start position
 *
 * Iteration cap is set tight enough that an adversarial
 * geometry causing an infinite loop in the original algorithm
 * would manifest as a libFuzzer timeout rather than a hang.
 */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Shims for the production structs - identical layout. */
struct coord {
  int32_t x;
  int32_t y;
};
struct screen_local_coord {
  int32_t x;
  int32_t y;
  int32_t output_idx;
  bool valid;
};

#include "../src/kloak_geometry.inc.h"
#include "../src/kloak_coord.inc.h"
#include "../src/kloak_traverse.inc.h"
#include "../src/kloak_walk_cursor.inc.h"

#define KLOAK_FUZZ_MAX_GEOMS 8
#define KLOAK_FUZZ_MAX_ITERATIONS 2048

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t hdr = 0;
  size_t geom_count = 0;
  uint8_t slot_byte = 0;
  struct coord start = { 0 };
  struct coord end = { 0 };
  struct output_geometry geoms_storage[KLOAK_FUZZ_MAX_GEOMS] = { 0 };
  struct output_geometry *geoms_ptrs[KLOAK_FUZZ_MAX_GEOMS] = { 0 };
  struct kloak_walk_cursor_result r;
  size_t cursor = 0;
  size_t i = 0;

  /* Wire format:
   *   1 byte    hdr: low 3 bits = geom_count
   *   1 byte    NULL-slot mask
   *   4 bytes   start.x  (LE int32)
   *   4 bytes   start.y
   *   4 bytes   end.x
   *   4 bytes   end.y
   *   geom_count * 16 bytes (x, y, w, h - 4 x LE int32)
   */
  if (size < 18U) {
    return 0;
  }

  hdr        = data[0];
  slot_byte  = data[1];
  geom_count = (size_t)(hdr & 0x7);
  memcpy(&start.x, data +  2, sizeof(int32_t));
  memcpy(&start.y, data +  6, sizeof(int32_t));
  memcpy(&end.x,   data + 10, sizeof(int32_t));
  memcpy(&end.y,   data + 14, sizeof(int32_t));
  cursor = 18;

  if (size < cursor + geom_count * 16U) {
    return 0;
  }

  for (i = 0; i < geom_count; i++) {
    memcpy(&geoms_storage[i].x,      data + cursor +  0, sizeof(int32_t));
    memcpy(&geoms_storage[i].y,      data + cursor +  4, sizeof(int32_t));
    memcpy(&geoms_storage[i].width,  data + cursor +  8, sizeof(int32_t));
    memcpy(&geoms_storage[i].height, data + cursor + 12, sizeof(int32_t));
    if ((slot_byte >> i) & 0x1) {
      geoms_ptrs[i] = NULL;
    } else {
      geoms_ptrs[i] = &geoms_storage[i];
    }
    cursor += 16;
  }

  r = walk_cursor_pure(start, end, geoms_ptrs, geom_count,
    KLOAK_FUZZ_MAX_ITERATIONS);
  asm volatile("" : :
    "r"(r.final_pos.x), "r"(r.final_pos.y), "r"(r.reached_end)
    : "memory");
  return 0;
}
