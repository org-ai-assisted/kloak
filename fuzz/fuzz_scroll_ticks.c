/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for get_ticks_from_scroll_accum_pure() -
 * the float-to-int32 + accumulator-subtract math kloak uses to
 * decide how many scroll wheel "ticks" the user has generated.
 * Production callers always pass finite doubles within the
 * representable scroll-ticks range (libinput's scroll values
 * are bounded by physical scroll-wheel deltas); the harness
 * sweeps the full double bit pattern range including NaN, +/-
 * Inf, denormals, and the int32 boundary so the cast / bound
 * checks stay honest.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../src/kloak_scroll_ticks.inc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  double scroll_accum = 0.0;
  struct kloak_scroll_ticks_result r;

  if (size < 8U) {
    return 0;
  }
  memcpy(&scroll_accum, data, sizeof(double));
  r = get_ticks_from_scroll_accum_pure(scroll_accum);
  asm volatile("" : :
    "r"(r.ticks), "r"(r.valid),
    "m"(r.new_accum)
    : "memory");
  return 0;
}
