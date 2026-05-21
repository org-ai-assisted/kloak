/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Shared overflow-recovery arming for kloak's libFuzzer harnesses.
 *
 * The checked-arithmetic helpers in kloak.h (add_i32 etc.) route a
 * detected signed overflow to kloak_arith_overflow(), which under
 * KLOAK_FUZZING records kloak_overflow_flagged and siglongjmp()s back
 * to a recovery point IF the fuzz entry point has armed one - and
 * abort()s otherwise. Every LLVMFuzzerTestOneInput must therefore arm
 * the recovery before exercising kloak code, otherwise an overflowing
 * input would crash the in-process fuzzer instead of being treated as
 * a handled (production-would-abort) condition.
 *
 * Usage - first statement of LLVMFuzzerTestOneInput, after the local
 * declarations (kloak builds with -Wdeclaration-after-statement):
 *
 *   int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 *     ... local declarations ...
 *     KLOAK_FUZZ_OVERFLOW_GUARD();
 *     ... body that calls kloak code ...
 *     return 0;
 *   }
 *
 * On overflow the sigsetjmp returns non-zero and the harness returns
 * 0 immediately (input discarded). Any cleanup after the guarded body
 * is skipped on that path; per the project's fuzzing policy leaks on
 * the overflow path are acceptable (restart the fuzzer if RSS grows).
 * Harnesses that accumulate global state across iterations should
 * reset it at the START of LLVMFuzzerTestOneInput so the next
 * iteration is unaffected by a skipped end-of-iteration cleanup.
 */

#ifndef KLOAK_FUZZ_OVERFLOW_RECOVERY_H
#define KLOAK_FUZZ_OVERFLOW_RECOVERY_H

#define KLOAK_FUZZ_OVERFLOW_GUARD()                                      \
  do {                                                                   \
    kloak_overflow_flagged = 0;                                          \
    if (sigsetjmp(kloak_overflow_jmp, 0) != 0) {                         \
      kloak_overflow_jmp_armed = 0;                                      \
      return 0;                                                          \
    }                                                                    \
    kloak_overflow_jmp_armed = 1;                                        \
  } while (0)

#endif /* KLOAK_FUZZ_OVERFLOW_RECOVERY_H */
