/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for recalc_global_space_pure() - the
 * multi-screen geometry recalculator extracted from kloak.c.
 * Production reaches this every time the compositor reports a
 * new output mode / logical position / size; the harness
 * exercises the corner-finding, the int64 overflow guards on
 * 'x + width' / 'y + height', and the connectivity-graph
 * flood-fill that detects screen gaps.
 *
 * Production aborts the process on KLOAK_RECALC_GAP; the pure
 * helper just returns that status, so the gap-detection path is
 * directly reachable from the fuzz binary with no abort()
 * involved.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The pure helpers we test live in src/kloak.c. KLOAK_
 * FUZZ carves out the production sections (wayland /
 * libinput dispatch, globals, main) so this translation
 * unit only compiles the helpers + the struct types they
 * need. See the kloak.c header for details. */
#define KLOAK_FUZZ
#include "../src/kloak.c"
/* Cap the per-input geometry count low so the inner O(n^3)
 * connectivity loop stays cheap; the production limit is 128
 * but the bug surface is the same at smaller counts. */
#define KLOAK_FUZZ_MAX_GEOMS 8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t hdr = 0;
  size_t geom_count = 0;
  size_t cursor = 1;
  size_t i = 0;
  uint8_t slot_byte = 0;
  struct output_geometry geoms_storage[KLOAK_FUZZ_MAX_GEOMS] = { 0 };
  struct output_geometry *geoms_ptrs[KLOAK_FUZZ_MAX_GEOMS] = { 0 };
  struct kloak_recalc_result r;

  /* Wire format:
   *   1 byte   hdr: low 3 bits = geom_count (0..7);
   *                 next 8 bits via subsequent byte = NULL mask
   *   geom_count * 16 bytes (x, y, w, h - 4 x int32 LE per geom)
   */
  if (size < 2U) {
    return 0;
  }

  hdr = data[0];
  geom_count = (size_t)(hdr & 0x7);
  slot_byte = data[1];
  cursor = 2;

  if (size < cursor + geom_count * 16U) {
    return 0;
  }

  for (i = 0; i < geom_count; i++) {
    memcpy(&geoms_storage[i].x,      data + cursor +  0, sizeof(int32_t));
    memcpy(&geoms_storage[i].y,      data + cursor +  4, sizeof(int32_t));
    memcpy(&geoms_storage[i].width,  data + cursor +  8, sizeof(int32_t));
    memcpy(&geoms_storage[i].height, data + cursor + 12, sizeof(int32_t));
    /* NULL slots mirror the production case where an output is
     * registered but its geometry hasn't arrived yet. */
    if ((slot_byte >> i) & 0x1) {
      geoms_ptrs[i] = NULL;
    } else {
      geoms_ptrs[i] = &geoms_storage[i];
    }
    cursor += 16;
  }

  r = recalc_global_space_pure(geoms_ptrs, geom_count);
  asm volatile("" : :
    "r"(r.status),
    "r"(r.global_space_width), "r"(r.global_space_height),
    "r"(r.pointer_space_x),    "r"(r.pointer_space_y)
    : "memory");
  return 0;
}
