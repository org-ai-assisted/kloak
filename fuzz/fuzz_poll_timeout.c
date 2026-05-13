/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak_poll_timeout_pure() - the
 * saturating int64 -> int subtraction kloak uses to compute the
 * poll() wait duration before the next scheduled input packet
 * is due. Production callers see sched_time / current_time
 * values that are clock-derived (positive, close together); the
 * harness sweeps the full int64 range so the saturating
 * subtraction stays honest at extremes.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../src/kloak_poll_timeout.inc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int64_t sched_time = 0;
  int64_t current_time = 0;
  int rslt = 0;

  if (size < 16U) {
    return 0;
  }
  memcpy(&sched_time,   data + 0, sizeof(int64_t));
  memcpy(&current_time, data + 8, sizeof(int64_t));

  rslt = kloak_poll_timeout_pure(sched_time, current_time);
  asm volatile("" : : "r"(rslt) : "memory");
  return 0;
}
