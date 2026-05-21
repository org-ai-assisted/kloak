/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's traverse_line(). Walks `pos` pixels
 * from start towards end along the line they define, used by the
 * cursor-draw pipeline to step over intermediate pixels between
 * frames. Worth fuzzing for:
 *   - double-precision math involving fabs() and ratios derived
 *     from int32_t deltas (slope, 1/steep)
 *   - the (int64_t)(denom) == 0 vertical-line short circuit
 *   - the four sign branches selecting start +/- pos along each
 *     axis
 *   - the (int32_t) casts of (double) pos * steep, which UBSan
 *     flags on invalid float-to-int conversion (NaN, +/-Inf, or
 *     values outside int32_t range)
 *
 * traverse_line is already non-static in kloak.c (visible without
 * any source edit), but we still use the existing #include pattern
 * for consistency with the other harnesses.
 */

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"
#include "fuzz_overflow_recovery.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct coord start = { 0 };
  struct coord end = { 0 };
  int32_t pos = 0;

  KLOAK_FUZZ_OVERFLOW_GUARD();
  if (size < sizeof(start) + sizeof(end) + sizeof(pos)) {
    return 0;
  }
  memcpy(&start, data, sizeof(start));
  memcpy(&end, data + sizeof(start), sizeof(end));
  memcpy(&pos, data + sizeof(start) + sizeof(end), sizeof(pos));

  (void)traverse_line(start, end, pos);
  return 0;
}
