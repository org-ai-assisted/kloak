/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for parse_cli_args_pure() - kloak's CLI
 * argument parser. Sweeps:
 *
 *   - The getopt_long dispatch (option vs. argument
 *     misalignment, '=' style, missing required argument
 *     handling)
 *   - The per-option handlers' interaction with parse_uint31_
 *     arg / parse_uint32_arg (already individually fuzzed)
 *   - The cursor_color alpha-zero -> should_draw_cursor=false
 *     side effect
 *   - 'true' vs anything-else handling for --natural-scrolling
 *
 * The harness intentionally does NOT call parse_esc_key_str()
 * on the -k optarg (the pure parser only stores the pointer);
 * parse_esc_key_str is already fuzzed independently by
 * fuzz_parse_esc_key_str, and keeping it out of this harness
 * means we do not need reset_esc_key_state() between iterations.
 *
 * Input layout: fuzz input is split on NUL bytes into argv
 * tokens, with a synthetic "kloak" inserted at argv[0].
 * Maximum argc capped to keep the per-iteration cost bounded.
 *
 * getopt state reset between iterations: 'optind = 0' on glibc
 * resets the static 'nextchar' pointer in addition to the
 * usual optind/optarg/opterr; relying on 'optind = 1' alone
 * leaves nextchar pointing at the previous argv (broken
 * cross-iteration).
 */

#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Only the non-esc-key portion of kloak_parsers.inc.h is needed
 * here (parse_uint31_arg / parse_uint32_arg). Leaving
 * KLOAK_INCLUDE_ESC_KEY_PARSER undefined skips the esc_key
 * parser globals + safe_strdup forward decl, neither of which
 * parse_cli_args_pure references. */
#include "../src/kloak_parsers.inc.h"
#include "../src/kloak_cli_args.inc.h"

#define KLOAK_FUZZ_MAX_ARGS 16
#define KLOAK_FUZZ_MAX_TOTAL_LEN 4096

/* Silence parse_uint31_arg / parse_uint32_arg's potential
 * print_usage()-equivalent stderr noise during the run.
 * (parse_uint31/32_arg are exit()-free but the production
 * caller they were extracted from still prints to stderr; the
 * pure variant does not, but parse_cli_args_pure does not
 * either - this is belt-and-braces.) */
static int g_devnull_fd = -1;
static int g_saved_stderr_fd = -1;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  g_devnull_fd = open("/dev/null", O_WRONLY);
  g_saved_stderr_fd = dup(STDERR_FILENO);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* progname stays writable so getopt_long's char** signature
   * is satisfied without a const-drop cast. */
  static char progname[] = "kloak";
  char *argv_storage = NULL;
  char *argv_array[KLOAK_FUZZ_MAX_ARGS + 1] = { NULL };
  int argc_local = 0;
  size_t i = 0;
  /* Output sinks - production wires these to module-scope
   * globals; the harness uses locals. */
  int32_t max_delay = 100;
  int32_t startup_delay = 500;
  uint32_t cursor_color = 0;
  bool should_draw_cursor = true;
  bool enable_natural_scrolling = false;
  bool esc_key_str_set = false;
  const char *esc_key_str = NULL;
  enum kloak_cli_args_status rc;

  if (size == 0U || size > KLOAK_FUZZ_MAX_TOTAL_LEN) {
    return 0;
  }

  /* Build a NUL-terminated working copy of the input so we can
   * split it into argv tokens without modifying libFuzzer's
   * read-only buffer. */
  argv_storage = malloc(size + 1U);
  if (argv_storage == NULL) {
    return 0;
  }
  memcpy(argv_storage, data, size);
  argv_storage[size] = '\0';

  /* Slot 0 is always "kloak" for getopt_long's progname-style
   * expectations. */
  argv_array[0] = progname;
  argc_local = 1;

  /* Split on internal NUL bytes. Each NUL marks an argv
   * boundary; cap argc to avoid pathological inputs. */
  for (i = 0; i < size && argc_local < KLOAK_FUZZ_MAX_ARGS; i++) {
    if (i == 0 || argv_storage[i - 1] == '\0') {
      argv_array[argc_local] = argv_storage + i;
      argc_local++;
    }
  }

  /* Full glibc getopt_long state reset. optind = 1 leaves
   * nextchar populated from the previous call. */
  optind = 0;
  opterr = 0;

  if (g_devnull_fd >= 0) {
    fflush(stderr);
    dup2(g_devnull_fd, STDERR_FILENO);
  }

  rc = parse_cli_args_pure(argc_local, argv_array,
    &max_delay, &startup_delay, &cursor_color,
    &should_draw_cursor, &enable_natural_scrolling,
    &esc_key_str_set, &esc_key_str);

  if (g_saved_stderr_fd >= 0) {
    fflush(stderr);
    dup2(g_saved_stderr_fd, STDERR_FILENO);
  }

  asm volatile("" : :
    "r"(rc), "r"(max_delay), "r"(startup_delay), "r"(cursor_color),
    "r"(should_draw_cursor), "r"(enable_natural_scrolling),
    "r"(esc_key_str_set), "r"(esc_key_str)
    : "memory");

  free(argv_storage);
  return 0;
}
