/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's random_between(). Generates a
 * random int64_t in the closed interval [lower, upper] via
 * rejection sampling backed by /dev/urandom. Worth fuzzing for:
 *   - maxval = upper - lower + 1 on signed int64_t (-ftrapv on
 *     overflow when upper - lower >= INT64_MAX)
 *   - the INT64_MIN special case in the rejection loop (llabs of
 *     INT64_MIN is undefined; the function handles this explicitly)
 *   - the (INT64_MAX - (INT64_MAX % maxval)) rejection threshold
 *
 * Transitively exercises read_random() (which is fenced by
 * #ifndef KLOAK_FUZZING in kloak.c so a short read aborts rather
 * than exit(1)).
 *
 * Production code initialises randfd in applayer_random_init().
 * The harness opens /dev/urandom once on first call so we do not
 * have to link the rest of the init dance. /dev/urandom is present
 * in OSS-Fuzz, ClusterFuzzLite, and developer environments alike;
 * if the open ever fails, that's a harness-environment bug worth
 * surfacing (the assert below will fire).
 */

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"
#include "fuzz_overflow_recovery.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool randfd_inited = false;
  int64_t lower_raw = 0;
  int64_t upper_raw = 0;
  int64_t lower = 0;
  int64_t upper = 0;

  KLOAK_FUZZ_OVERFLOW_GUARD();
  if (!randfd_inited) {
    randfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    assert(randfd != -1);
    randfd_inited = true;
  }

  if (size < 2U * sizeof(int64_t)) {
    return 0;
  }
  memcpy(&lower_raw, data, sizeof(int64_t));
  memcpy(&upper_raw, data + sizeof(int64_t), sizeof(int64_t));

  /*
   * random_between asserts lower >= 0 and upper >= 0; mask off the
   * sign bit via uint64_t (well-defined wrap) so we explore the
   * full non-negative int64_t range without violating the contract.
   * The fuzzer will still hit upper - lower + 1 == INT64_MAX + 1
   * (the -ftrapv surface) on a fair fraction of inputs.
   */
  lower = (int64_t)(((uint64_t)lower_raw) & (uint64_t)INT64_MAX);
  upper = (int64_t)(((uint64_t)upper_raw) & (uint64_t)INT64_MAX);

  (void)random_between(lower, upper);
  return 0;
}
