/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure CLI argument parser factored out of parse_cli_args() in
 * kloak.c so fuzz/fuzz_cli_args.c can exercise the getopt_long
 * dispatch + per-option validation against adversarial argv
 * without the production exit() calls aborting libFuzzer.
 *
 * The pure helper writes its outputs through caller-provided
 * pointers and returns a status enum; the production wrapper in
 * kloak.c maps KLOAK_CLI_ARGS_HELP / _ERROR back to exit(0) /
 * exit(1) (preserving production behaviour exactly) and KLOAK_
 * CLI_ARGS_OK to applying the parsed values to module-scope
 * globals. The fuzz harness discards the status.
 *
 * Each call must be preceded by 'optind = 0' to fully reset
 * glibc getopt_long's internal state including the static
 * 'nextchar' pointer.
 *
 * Side effects:
 *   - parse_uint31_arg / parse_uint32_arg may be called
 *     (already exit()-free)
 *   - parse_esc_key_str is NOT called here; instead, when -k
 *     is given the optarg pointer is returned via
 *     *esc_key_str_out and the production caller invokes
 *     parse_esc_key_str on it (kept out of the pure helper so
 *     the fuzz harness does not have to manage esc_key state
 *     between iterations).
 */

#ifndef KLOAK_CLI_ARGS_INC_H
#define KLOAK_CLI_ARGS_INC_H

#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Requires kloak_parsers.inc.h (parse_uint31_arg, parse_uint32_
 * arg) to be included before this header so the symbols are in
 * scope. The production caller already does this; the fuzz
 * harness does the same.
 */

enum kloak_cli_args_status {
  KLOAK_CLI_ARGS_OK    = 0,
  KLOAK_CLI_ARGS_HELP  = 1,  /* -h / --help was passed */
  KLOAK_CLI_ARGS_ERROR = 2   /* invalid argument / unknown option */
};

/*
 * Parse argv using getopt_long. Every output pointer is
 * required to be non-NULL. Outputs are only written when the
 * corresponding option appears; the production caller passes
 * pointers to the matching module-scope globals which therefore
 * keep their previous defaults if an option is absent.
 *
 * 'esc_key_str_set_out' is set to true and 'esc_key_str_out' is
 * set to the optarg pointer when -k is seen; production caller
 * then calls parse_esc_key_str on that pointer. Pointer is into
 * argv, so the caller must not free argv before consuming it.
 */
static __attribute__((unused))
enum kloak_cli_args_status parse_cli_args_pure(
  int argc, char **argv,
  int32_t *max_delay_out,
  int32_t *startup_delay_out,
  uint32_t *cursor_color_out,
  bool *should_draw_cursor_out,
  bool *enable_natural_scrolling_out,
  bool *esc_key_str_set_out,
  const char **esc_key_str_out) {
  const char *optstring = "d:s:hc:k:n:";
  static struct option optarr[] = {
    {"delay", required_argument, NULL, 'd'},
    {"start-delay", required_argument, NULL, 's'},
    {"help", no_argument, NULL, 'h'},
    {"color", required_argument, NULL, 'c'},
    {"esc-key-combo", required_argument, NULL, 'k'},
    {"natural-scrolling", required_argument, NULL, 'n'},
    {0, 0, 0, 0}
  };
  int getopt_rslt = 0;

  while (true) {
    getopt_rslt = getopt_long(argc, argv, optstring, optarr, NULL);
    if (getopt_rslt == -1) {
      break;
    } else if (getopt_rslt == '?') {
      return KLOAK_CLI_ARGS_ERROR;
    } else if (getopt_rslt == 'd') {
      if (!parse_uint31_arg(optarg, 10, max_delay_out)) {
        return KLOAK_CLI_ARGS_ERROR;
      }
    } else if (getopt_rslt == 's') {
      if (!parse_uint31_arg(optarg, 10, startup_delay_out)) {
        return KLOAK_CLI_ARGS_ERROR;
      }
    } else if (getopt_rslt == 'c') {
      if (!parse_uint32_arg(optarg, 16, cursor_color_out)) {
        return KLOAK_CLI_ARGS_ERROR;
      }
      if ((*cursor_color_out >> 24) == 0) {
        /* Cursor is entirely transparent, disable drawing it
         * to save resources. */
        *should_draw_cursor_out = false;
      }
    } else if (getopt_rslt == 'n') {
      if (strcmp(optarg, "true") == 0) {
        *enable_natural_scrolling_out = true;
      } else {
        *enable_natural_scrolling_out = false;
      }
    } else if (getopt_rslt == 'k') {
      *esc_key_str_set_out = true;
      *esc_key_str_out = optarg;
    } else if (getopt_rslt == 'h') {
      return KLOAK_CLI_ARGS_HELP;
    } else {
      return KLOAK_CLI_ARGS_ERROR;
    }
  }
  return KLOAK_CLI_ARGS_OK;
}

#endif /* KLOAK_CLI_ARGS_INC_H */
