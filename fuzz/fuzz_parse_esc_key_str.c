/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's parse_esc_key_str(), which parses
 * the --esc-keys CLI argument (a comma-separated list of pipe-
 * separated evdev key-name groups). parse_esc_key_str() was
 * recently refactored to return bool instead of calling exit(1)
 * on malformed input, which is what makes it safe to fuzz at all
 * (libFuzzer interprets a process exit as a crash).
 *
 * The parser mutates four file-scope globals (esc_key_list and
 * friends) that grow on each successful parse. Without a reset
 * between iterations the harness would leak memory indefinitely
 * and eventually OOM; reset_esc_key_state() in
 * kloak_parsers.inc.h restores the clean-slate condition.
 *
 * safe_strdup / safe_reallocarray are forward-declared inside
 * kloak_parsers.inc.h's parser body but defined per-TU: kloak.c
 * provides the production versions that print FATAL ERROR and
 * exit on OOM; this harness provides minimal pass-through
 * wrappers so the parser links.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Stubs for the safe_* helpers parse_esc_key_str calls. Defined
 * before #include of kloak_parsers.inc.h so they are in scope
 * when the parser body is processed. malloc failure during
 * fuzzing of small inputs is not a realistic concern; if it
 * happens we abort rather than half-handle it. */
static char *safe_strdup(const char *s) {
  char *r = strdup(s);
  if (r == NULL) {
    abort();
  }
  return r;
}

static void *safe_reallocarray(void *ptr, size_t nmemb, size_t size) {
  void *r = reallocarray(ptr, nmemb, size);
  if (r == NULL) {
    abort();
  }
  return r;
}

#define KLOAK_INCLUDE_ESC_KEY_PARSER
#include "../src/kloak_parsers.inc.h"

/* parse_esc_key_str writes a FATAL ERROR diagnostic to stderr on
 * every bad-token path. libFuzzer generates several hundred
 * thousand inputs per second; almost all of them are malformed,
 * so without suppression the run produces gigabytes of duplicate
 * stderr output. Redirect fd 2 to /dev/null only around the
 * parser call and restore it afterwards so libFuzzer's own
 * crash-report / progress output on stderr survives. */
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
  char *buf = NULL;

  /* Reject inputs with embedded NUL bytes: parse_esc_key_str
   * treats its argument as a C string, so the libFuzzer-supplied
   * input slice must be losslessly convertible. */
  if (memchr(data, '\0', size) != NULL) {
    return 0;
  }

  buf = malloc(size + 1U);
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, data, size);
  buf[size] = '\0';

  if (g_devnull_fd >= 0) {
    fflush(stderr);
    dup2(g_devnull_fd, STDERR_FILENO);
  }

  reset_esc_key_state();
  (void)parse_esc_key_str(buf);
  reset_esc_key_state();

  if (g_saved_stderr_fd >= 0) {
    fflush(stderr);
    dup2(g_saved_stderr_fd, STDERR_FILENO);
  }

  free(buf);
  return 0;
}
