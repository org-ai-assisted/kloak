/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's get_ticks_from_scroll_accum().
 * Pure double-precision accumulator math: takes a *running scroll
 * total in libinput units, returns the whole-tick count and
 * deducts that count's worth of units from the accumulator. Worth
 * fuzzing for:
 *   - isfinite() invariant on the accumulator (asserts on NaN/Inf)
 *   - scroll_ticks_d <= INT32_MAX / SCROLL_UNITS_PER_TICK bound
 *     (asserts on huge magnitudes)
 *   - the int32_t cast of scroll_ticks_d and the subsequent
 *     `scroll_ticks * SCROLL_UNITS_PER_TICK` multiply (-ftrapv on
 *     signed overflow, UBSan on invalid float-to-int conversion)
 *
 * The asserts encode caller invariants: production code clamps
 * the accumulator before this call, so a NaN/Inf or out-of-band
 * value reaching get_ticks_from_scroll_accum is a caller bug. The
 * harness honours that contract by sanitising the fuzz double to
 * a finite value in [-INT32_MAX, INT32_MAX]; what the fuzzer then
 * explores is the cast/multiply arithmetic in the contract-honest
 * band.
 */

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"
#include "fuzz_overflow_recovery.h"

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  double accum = 0.0;

  KLOAK_FUZZ_OVERFLOW_GUARD();
  if (size < sizeof(double)) {
    return 0;
  }
  memcpy(&accum, data, sizeof(double));

  /*
   * Sanitise the fuzz bytes to satisfy the contract documented in
   * get_ticks_from_scroll_accum's asserts:
   *   isfinite(scroll_accum) &&
   *   scroll_ticks_d <= INT32_MAX / SCROLL_UNITS_PER_TICK &&
   *   scroll_ticks_d >= INT32_MIN / SCROLL_UNITS_PER_TICK
   * where the RHS bounds use *integer* division (SCROLL_UNITS_PER_TICK
   * is `int`), so the thresholds are slightly tighter than
   * INT32_MAX / 120.0. We clamp the accumulator well inside that
   * band - 1e9 is large enough to exercise the tick-extraction
   * loop and the multiply-back arithmetic without nudging the
   * divided value across the integer-truncated assert threshold.
   */
  if (!isfinite(accum)) {
    return 0;
  }
  if (accum > 1.0e9) {
    accum = 1.0e9;
  } else if (accum < -1.0e9) {
    accum = -1.0e9;
  }

  (void)get_ticks_from_scroll_accum(&accum);
  return 0;
}
