/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's check_screen_touch(). The function
 * tests whether two compositor displays touch or overlap, and is
 * called from recalc_global_space() during multi-monitor layout
 * calculation. The interesting paths are:
 *   - the +1/+2 grow logic on signed int32_t coordinates (scr1.x,
 *     scr1.y, scr1.width, scr1.height)
 *   - the eight check_point_in_area() corner probes against either
 *     screen
 * -ftrapv will trap on signed overflow in scr1.x + scr1.width and
 * the like; that is a real finding worth surfacing.
 *
 * No global state is touched. Inputs are two struct output_geometry
 * values populated directly from the fuzz buffer.
 */

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct output_geometry scr1 = { 0 };
  struct output_geometry scr2 = { 0 };

  if (size < sizeof(scr1) + sizeof(scr2)) {
    return 0;
  }
  memcpy(&scr1, data, sizeof(scr1));
  memcpy(&scr2, data + sizeof(scr1), sizeof(scr2));

  (void)check_screen_touch(scr1, scr2);
  return 0;
}
