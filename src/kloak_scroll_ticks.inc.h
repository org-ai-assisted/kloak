/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure scroll-tick accumulator helper extracted from
 * get_ticks_from_scroll_accum() in kloak.c so fuzz/fuzz_scroll_
 * ticks.c can exercise the float-to-int32 cast + the int32
 * multiplication without the production assert() preconditions
 * firing as fuzz-time aborts.
 *
 * Production calls libinput which always feeds finite, sane
 * doubles; the asserts in the kloak.c wrapper catch any
 * libinput / arithmetic regression. The pure variant takes the
 * same input and silently returns 'valid = false' for inputs
 * that would otherwise violate a precondition, so the harness
 * can sweep the full double-bit range without false-positive
 * crashes.
 */

#ifndef KLOAK_SCROLL_TICKS_INC_H
#define KLOAK_SCROLL_TICKS_INC_H

#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef SCROLL_UNITS_PER_TICK
#define SCROLL_UNITS_PER_TICK 120
#endif
#ifndef SCROLL_UNITS_PER_TICK_D
#define SCROLL_UNITS_PER_TICK_D 120.0
#endif

struct kloak_scroll_ticks_result {
  int32_t ticks;         /* integer number of consumed scroll ticks */
  double  new_accum;     /* what scroll_accum should be after consume */
  bool    valid;         /* false on out-of-range / non-finite input */
};

/*
 * Given the current floating-point scroll accumulator, return:
 *   { ticks=0,  new_accum=scroll_accum, valid=true } if the
 *     accumulator is zero (nothing to consume yet),
 *   { ticks=N,  new_accum=scroll_accum - N*SCROLL_UNITS_PER_TICK,
 *     valid=true } in the normal case,
 *   { valid=false } if the input is non-finite or out of the
 *     representable scroll-ticks range.
 *
 * The precondition asserts that the production wrapper uses are
 * deliberately encoded here as silent rejects so the fuzz
 * harness can drive adversarial doubles.
 */
static __attribute__((unused))
struct kloak_scroll_ticks_result get_ticks_from_scroll_accum_pure(
  double scroll_accum) {
  struct kloak_scroll_ticks_result out = { 0 };
  double scroll_ticks_d = 0.0;
  int32_t scroll_ticks = 0;

  if (!isfinite(scroll_accum)) {
    return out;
  }
  out.new_accum = scroll_accum;
  out.valid = true;
  if (fpclassify(scroll_accum) == FP_ZERO) {
    return out;
  }
  scroll_ticks_d = scroll_accum / SCROLL_UNITS_PER_TICK_D;
  /* We intentionally compare against SCROLL_UNITS_PER_TICK (the
   * int constant) rather than SCROLL_UNITS_PER_TICK_D so the
   * threshold rounds DOWN slightly, leaving margin against the
   * (int32_t) cast below. Matches the production wrapper's
   * pre-extraction asserts. */
  if (scroll_ticks_d > ((double)INT32_MAX / SCROLL_UNITS_PER_TICK)) {
    out.valid = false;
    return out;
  }
  if (scroll_ticks_d < ((double)INT32_MIN / SCROLL_UNITS_PER_TICK)) {
    out.valid = false;
    return out;
  }
  scroll_ticks = (int32_t)scroll_ticks_d;
  out.ticks = scroll_ticks;
  if (scroll_ticks != 0) {
    out.new_accum = scroll_accum
      + -((double)scroll_ticks * SCROLL_UNITS_PER_TICK_D);
  }
  return out;
}

#endif /* KLOAK_SCROLL_TICKS_INC_H */
