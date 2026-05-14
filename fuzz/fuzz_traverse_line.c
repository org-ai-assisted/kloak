/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for traverse_line() (kloak_traverse.inc.h),
 * the pure 2D line-walking helper kloak uses to interpolate
 * virtual-cursor positions between mouse events. Production
 * callers pass coordinates derived from compositor screen
 * geometry (a few thousand pixels at most) and small 'pos'
 * deltas; the harness sweeps the full int32 range adversarially
 * so libFuzzer + UBSan catch any signed-arithmetic overflow,
 * float-to-int conversion overflow, or NaN/Inf propagation in
 * the slope / fabs / cast chain.
 *
 * What the function looks at internally:
 *   denom = start.x - end.x         (as double)
 *   if (int64_t)denom == 0           -> vertical-line shortcut
 *   slope = (end.y - start.y) / denom
 *   steep = fabs(slope)
 *   then start.{x,y} +/- pos          (or pos * steep, cast to int32)
 * The +/- pos and the int32-cast of (pos * steep) are the two
 * places signed-int overflow can fire under -ftrapv / UBSan.
 */

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
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Each call consumes:
   *   4 bytes   start.x (int32, LE)
   *   4 bytes   start.y (int32, LE)
   *   4 bytes   end.x   (int32, LE)
   *   4 bytes   end.y   (int32, LE)
   *   4 bytes   pos     (int32, LE)
   */
  struct coord start = { 0 };
  struct coord end = { 0 };
  struct coord out = { 0 };
  int32_t pos = 0;

  if (size < 20U) {
    return 0;
  }

  memcpy(&start.x, data + 0,  sizeof(int32_t));
  memcpy(&start.y, data + 4,  sizeof(int32_t));
  memcpy(&end.x,   data + 8,  sizeof(int32_t));
  memcpy(&end.y,   data + 12, sizeof(int32_t));
  memcpy(&pos,     data + 16, sizeof(int32_t));

  out = traverse_line(start, end, pos);
  /* Force the compiler not to elide the call. */
  asm volatile("" : : "r"(out.x), "r"(out.y) : "memory");
  return 0;
}
