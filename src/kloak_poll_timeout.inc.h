/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure saturating int64 -> int helper for kloak's poll() timeout
 * calculation, factored out of calc_poll_timeout() in kloak.c so
 * fuzz/fuzz_poll_timeout.c can exercise the saturation logic
 * over the full int64 range without needing the TAILQ /
 * current_time_ms() / packet-queue globals.
 *
 * Production semantics: calc_poll_timeout() in kloak.c is now a
 * thin wrapper that pulls TAILQ_FIRST and current_time_ms(),
 * delegates the (sched_time - current_time) saturating subtract
 * to this helper, and returns -1 on no-packet.
 *
 * Why a helper at all: production sched_time and current_time
 * are both clock-derived (positive, close together) so the int64
 * subtraction never overflows in practice. A hostile or buggy
 * caller passing INT64_MIN / INT64_MAX could trigger UB though,
 * and -ftrapv would catch it at runtime - so do the subtract via
 * an int128-style decomposition that cannot trap.
 */

#ifndef KLOAK_POLL_TIMEOUT_INC_H
#define KLOAK_POLL_TIMEOUT_INC_H

#include <limits.h>
#include <stdint.h>

/*
 * Compute 'sched_time - current_time' in saturated int range.
 * Returns:
 *   < 0 (clamped to 0):           sched_time is now or past
 *   in [0, INT_MAX]:              the actual delay in ms
 *   INT_MAX:                       delay > INT_MAX ms (saturate)
 *
 * The int64 subtraction is performed safely - if 'sched_time -
 * current_time' would overflow int64 the result is clamped to
 * INT_MAX (over) or 0 (under) before the int cast.
 */
static __attribute__((unused))
int kloak_poll_timeout_pure(int64_t sched_time, int64_t current_time) {
  int64_t timeout_duration = 0;

  /* Saturate the subtraction itself: if sched_time and current_
   * time are far apart enough that subtracting overflows int64,
   * fall back to the obvious saturation. */
  if (current_time < 0 && sched_time > INT64_MAX + current_time) {
    /* sched_time - current_time would overflow positively */
    return INT_MAX;
  }
  if (current_time > 0 && sched_time < INT64_MIN + current_time) {
    /* sched_time - current_time would overflow negatively */
    return 0;
  }

  timeout_duration = sched_time - current_time;
  if (timeout_duration < 0) {
    return 0;
  }
  if (timeout_duration > INT_MAX) {
    return INT_MAX;
  }
  return (int)timeout_duration;
}

#endif /* KLOAK_POLL_TIMEOUT_INC_H */
