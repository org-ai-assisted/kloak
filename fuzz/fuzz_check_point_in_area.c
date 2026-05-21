/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's check_point_in_area(). This is a
 * pure point-in-rectangle predicate (no globals, no I/O), so the
 * harness exists to exercise the signed-arithmetic paths under
 * ASan/UBSan/-ftrapv:
 *   - rect_x + rect_width
 *   - rect_y + rect_height
 * Both additions sit on signed int32_t and will trap on overflow
 * given the build's -ftrapv flag, which would be a real finding.
 *
 * Pulling kloak.c into the harness via #include keeps the
 * file-scope `static` qualifier on the target intact (no
 * exported-symbol surface change) while letting the harness call
 * the predicate directly. Dead code in kloak.c (Wayland callbacks,
 * libinput dispatch) is linked in but never executed during
 * fuzzing.
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
  int32_t fields[6] = { 0 };

  KLOAK_FUZZ_OVERFLOW_GUARD();
  if (size < sizeof(fields)) {
    return 0;
  }
  memcpy(fields, data, sizeof(fields));

  (void)check_point_in_area(fields[0], fields[1], fields[2], fields[3],
    fields[4], fields[5]);
  return 0;
}
