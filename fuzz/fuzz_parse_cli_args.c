/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's parse_cli_args() - the
 * argv-style entry point. This is the highest-leverage harness
 * in the set: every untrusted-user-input path in kloak that does
 * not come from /dev/input or /dev/urandom flows through here.
 * Worth fuzzing for:
 *   - getopt_long state machine across arbitrary --short/--long
 *     option sequences,
 *   - the integer / colour parsers parse_uint31_arg /
 *     parse_uint32_arg called via -d/-s/-c (already covered in
 *     isolation, but exercised here in option-sequence context),
 *   - parse_esc_key_str invoked via -k (same),
 *   - cursor_color & 0xff000000 -> should_draw_cursor=false
 *     transition (state machine across multiple -c options),
 *   - global-state pollution between option sequences if any
 *     handler leaks an allocation on its error path.
 *
 * argv construction:
 *   argv[0] is always "kloak" (program name; skipped by getopt).
 *   Remaining argv entries come from the fuzz buffer, split at
 *   0x00 separator bytes. argc is capped at KLOAK_FUZZ_MAX_ARGC to
 *   keep getopt's O(argc * options) inner loop bounded.
 *
 * In kloak.c the six exit() calls reachable from parse_cli_args
 * (- -? unknown option, -d / -s / -c parse failure, -h help,
 * default branch -) are #ifndef KLOAK_FUZZING -> goto fuzz_cleanup
 * so the fuzzer keeps exploring instead of silently halting on
 * the first malformed arg.
 *
 * Global state mutated by parse_cli_args (max_delay,
 * startup_delay, cursor_color, should_draw_cursor,
 * enable_natural_scrolling, esc_key_list*) is reset before and
 * after each iteration. getopt's optind / opterr are also reset
 * so successive calls behave like a fresh process.
 */

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define KLOAK_FUZZ_MAX_ARGC 16

static void fuzz_reset_cli_state(void) {
  size_t k = 0;

  max_delay = DEFAULT_MAX_DELAY_MS;
  startup_delay = DEFAULT_STARTUP_TIMEOUT_MS;
  cursor_color = 0x00000000U;
  should_draw_cursor = true;
  enable_natural_scrolling = false;

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

  /*
   * glibc getopt requires optind = 0 (not 1) for a full internal
   * state reset between independent argv scans; setting optind to
   * 1 leaves cached optarg / nextchar pointers from the previous
   * call. ASan caught this as a heap-use-after-free into the
   * previous iteration's buf via parse_uint32_arg(optarg, ...).
   * See `man 3 getopt` "Notes" section.
   */
  optind = 0;
  opterr = 0;
  optarg = NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = NULL;
  char *argv[KLOAK_FUZZ_MAX_ARGC + 1];
  /* Non-const local so argv[0] does not need a const-stripping
     cast (kloak compiles with -Wcast-qual). getopt does not
     modify argv[0] but its signature is `char **argv`. */
  char prog_name[] = "kloak";
  int argc = 1;
  size_t cursor = 0;

  /* Cap fuzz input length so getopt does not chew on multi-MB
     argv entries when the fuzzer happens to find a long run
     without a 0x00 separator. */
  if (size > 4096U) {
    size = 4096U;
  }

  buf = malloc(size + 1U);
  if (buf == NULL) {
    return 0;
  }
  if (size > 0U) {
    memcpy(buf, data, size);
  }
  buf[size] = '\0';

  argv[0] = prog_name;
  while (argc < KLOAK_FUZZ_MAX_ARGC && cursor < size) {
    argv[argc] = buf + cursor;
    argc++;
    while (cursor < size && buf[cursor] != '\0') {
      cursor++;
    }
    if (cursor < size) {
      cursor++; /* skip the separator */
    }
  }
  argv[argc] = NULL;

  fuzz_reset_cli_state();
  parse_cli_args(argc, argv);
  fuzz_reset_cli_state();

  free(buf);
  return 0;
}
