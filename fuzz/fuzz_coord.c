/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for coord_abs_to_local_pure() and
 * coord_local_to_abs_pure() (kloak_coord.inc.h) - the
 * compositor-global <-> screen-local coordinate translators
 * kloak uses every time it moves the virtual cursor or queries
 * which screen a point falls on.
 *
 * Same overflow class as the fuzz_geometry harness exposed for
 * check_screen_touch / check_point_in_area. The coord-local-to-
 * abs path now does its add in int64_t with a saturating clamp
 * back to int32_t; this harness keeps that property under
 * libFuzzer + UBSan.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Shims for the production structs - identical layout to kloak.h. */
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

#define KLOAK_FUZZ_MAX_GEOMS 8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Each call consumes:
   *   1 byte    geom_count (low 3 bits, 0..7) + which-pure (bit 3)
   *   4 bytes   x  (int32, LE)
   *   4 bytes   y  (int32, LE)
   *   1 byte    output_idx_byte (low 3 bits used by coord_local_to_abs)
   *   geom_count * 16 bytes (x, y, w, h - 4 x int32 LE per geom)
   */
  uint8_t hdr = 0;
  size_t geom_count = 0;
  bool also_call_local_to_abs = false;
  int32_t x = 0;
  int32_t y = 0;
  uint8_t output_idx_byte = 0;
  size_t cursor = 10;
  size_t i = 0;
  size_t idx = 0;
  struct output_geometry geoms_storage[KLOAK_FUZZ_MAX_GEOMS] = { 0 };
  struct output_geometry *geoms_ptrs[KLOAK_FUZZ_MAX_GEOMS] = { 0 };
  struct screen_local_coord local = { 0 };
  struct coord abs_c = { 0 };

  if (size < 10U) {
    return 0;
  }

  hdr = data[0];
  geom_count = (size_t)(hdr & 0x7);  /* 0..7 */
  also_call_local_to_abs = (hdr & 0x8) != 0;
  memcpy(&x, data + 1, sizeof(int32_t));
  memcpy(&y, data + 5, sizeof(int32_t));
  output_idx_byte = data[9];

  if (size < cursor + geom_count * 16U) {
    return 0;
  }

  for (i = 0; i < geom_count; i++) {
    memcpy(&geoms_storage[i].x,      data + cursor +  0, sizeof(int32_t));
    memcpy(&geoms_storage[i].y,      data + cursor +  4, sizeof(int32_t));
    memcpy(&geoms_storage[i].width,  data + cursor +  8, sizeof(int32_t));
    memcpy(&geoms_storage[i].height, data + cursor + 12, sizeof(int32_t));
    /* Sprinkle NULL pointers in to exercise the "slot reserved but
     * geometry not yet set" production path. */
    if ((output_idx_byte >> i) & 0x1) {
      geoms_ptrs[i] = NULL;
    } else {
      geoms_ptrs[i] = &geoms_storage[i];
    }
    cursor += 16;
  }

  local = coord_abs_to_local_pure(x, y, geoms_ptrs, geom_count);
  asm volatile("" : :
    "r"(local.x), "r"(local.y), "r"(local.output_idx), "r"(local.valid)
    : "memory");

  if (also_call_local_to_abs && geom_count > 0) {
    idx = (size_t)(output_idx_byte & 0x7);
    if (idx >= geom_count) idx = geom_count - 1;
    abs_c = coord_local_to_abs_pure(x, y, geoms_ptrs[idx]);
    asm volatile("" : : "r"(abs_c.x), "r"(abs_c.y) : "memory");
  }

  return 0;
}
