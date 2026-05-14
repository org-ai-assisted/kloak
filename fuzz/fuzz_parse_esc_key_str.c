/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's parse_esc_key_str(). Parses the
 * --esc-keys command-line argument: a comma-separated list of
 * alternative escape combinations, each combination being a
 * '|'-separated list of key names. The function strsep-tokenises
 * the string and grows three parallel global arrays
 * (esc_key_list, esc_key_sublist_len, active_esc_key_list) via
 * safe_reallocarray. Worth fuzzing for:
 *   - strsep-based two-level tokenisation (empty-token paths are
 *     intentionally rejected, but the rejection branches see
 *     fuzzer-controlled token boundaries)
 *   - safe_reallocarray sizing: esc_key_list_len and
 *     esc_key_sublist_len are size_t and grow with the input
 *   - the lookup_keycode side-channel (already covered by a
 *     dedicated harness, but exercised here in context)
 *
 * In kloak.c the three exit(1) bailouts on malformed input are
 * #ifndef-guarded to fall through to a fuzz_cleanup label so the
 * fuzzer keeps exploring the parser rather than silently halting
 * on the first empty / unknown token. State accumulated in
 * esc_key_list[] etc. across iterations is freed at the start of
 * each call so allocations stay bounded.
 */

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void fuzz_reset_esc_key_state(void) {
  size_t k = 0;

  if (esc_key_list != NULL) {
    for (k = 0; k < esc_key_list_len; k++) {
      free(esc_key_list[k]);
    }
    free(esc_key_list);
    esc_key_list = NULL;
  }
  free(esc_key_sublist_len);
  esc_key_sublist_len = NULL;
  free(active_esc_key_list);
  active_esc_key_list = NULL;
  esc_key_list_len = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *input = NULL;

  /*
   * Cap input at 4 KiB. parse_esc_key_str scales esc_key_list_len
   * with the number of commas; without a cap the fuzzer would
   * happily feed multi-megabyte strings and OOM the worker on
   * realloc bookkeeping rather than finding real bugs.
   */
  if (size > 4096U) {
    size = 4096U;
  }

  input = malloc(size + 1U);
  if (input == NULL) {
    return 0;
  }
  if (size > 0U) {
    memcpy(input, data, size);
  }
  input[size] = '\0';

  fuzz_reset_esc_key_state();
  parse_esc_key_str(input);
  fuzz_reset_esc_key_state();

  free(input);
  return 0;
}
