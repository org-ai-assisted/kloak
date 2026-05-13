/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for the xkbcommon parser surface kloak feeds
 * with Wayland-compositor-supplied keymap strings. See
 * kb_handle_keymap() in src/kloak.c around line 1074: the
 * function receives a fd + size from the compositor over the
 * wl_keyboard protocol, mmaps it, then calls
 * xkb_keymap_new_from_string() with the resulting string.
 *
 * kloak treats the compositor as trusted, but if the compositor
 * is hostile (or, more realistically, compromised) the keymap
 * string is the most direct adversary-controlled byte stream
 * that reaches kloak's address space. Whatever xkbcommon will
 * accept here, kloak will accept - so the harness fuzzes
 * xkb_keymap_new_from_string() with arbitrary inputs.
 *
 * This is xkbcommon-fuzzing rather than kloak-source-fuzzing,
 * by design - the parser surface lives in the library, not in
 * kloak. The harness exists in this repo because the integration
 * shape kloak chose (raw bytes -> xkb_keymap_new_from_string)
 * is what we want to keep under regression coverage.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <xkbcommon/xkbcommon.h>

/* Disable LeakSanitizer for this harness. xkbcommon's keymap
 * parser allocates memory that is not always freed on error
 * paths - real leaks in libxkbcommon, fuzzing-discoverable, but
 * not actionable from kloak's side and reproducible with stock
 * libxkbcommon 1.6.0 (Ubuntu 24.04) and 0.10.0 (Ubuntu 20.04).
 * ASan / UBSan instrumentation still detects OOB / UAF / signed
 * overflow / etc.; only the leak class is suppressed. The
 * __lsan_default_options weak symbol scopes the suppression to
 * THIS binary - the other fuzz harnesses still detect leaks. */
__attribute__((visibility("default"))) const char *
__lsan_default_options(void);
__attribute__((visibility("default"))) const char *
__lsan_default_options(void) {
  return "detect_leaks=0";
}

static struct xkb_context *g_ctx = NULL;

/* xkbcommon's default log handler writes parser-error diagnostics
 * to stderr. libFuzzer feeds ~10^5 inputs per second; almost all
 * of them are malformed keymaps, so unsuppressed output floods
 * the run log. Install a no-op log_fn that silently absorbs
 * everything. */
static void silent_log_fn(__attribute__((unused)) struct xkb_context *ctx,
  __attribute__((unused)) enum xkb_log_level level,
  __attribute__((unused)) const char *fmt,
  __attribute__((unused)) va_list args) {
  ;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  /* XKB_CONTEXT_NO_DEFAULT_INCLUDES skips the filesystem include-
   * path probing that xkbcommon 0.10 (the Ubuntu 20.04 / OSS-Fuzz
   * base-builder version) does in xkb_context_new(). The fuzzer
   * never compiles include-directives anyway - it feeds raw
   * keymap strings to xkb_keymap_new_from_string(), which does
   * not consult /usr/share/X11/xkb when the input is a complete
   * keymap text. */
  g_ctx = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES);
  if (g_ctx == NULL) {
    /* Treat init failure as a soft skip: returning non-zero
     * tells libFuzzer to bail out of LLVMFuzzerInitialize, but
     * does NOT trigger a crash report. The non-libFuzzer
     * harness path (LLVMFuzzerTestOneInput) also guards on
     * g_ctx so it short-circuits safely. */
    return 1;
  }
  xkb_context_set_log_fn(g_ctx, silent_log_fn);
  xkb_context_set_log_verbosity(g_ctx, 0);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (g_ctx == NULL) {
    return 0;
  }
  /* xkb_keymap_new_from_string takes a NUL-terminated C string;
   * skip inputs that contain embedded NULs so the harness does
   * not unintentionally truncate the parser's view of the
   * input. */
  if (memchr(data, '\0', size) != NULL) {
    return 0;
  }

  char *buf = malloc(size + 1U);
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, data, size);
  buf[size] = '\0';

  /* xkbcommon caches atom strings in the context for the entire
   * lifetime of the context object. Reusing g_ctx across fuzz
   * iterations grows that table monotonically and ASan reports
   * the accumulation as a leak. Use a fresh per-iteration
   * context so every parse runs against a clean atom table.
   * Slight overhead vs. global context (~50us per init); fine
   * at ~hundreds of thousands of execs/sec. */
  struct xkb_context *ctx = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES);
  if (ctx == NULL) {
    free(buf);
    return 0;
  }
  xkb_context_set_log_fn(ctx, silent_log_fn);
  xkb_context_set_log_verbosity(ctx, 0);

  struct xkb_keymap *keymap = xkb_keymap_new_from_string(
    ctx, buf, XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS);
  if (keymap != NULL) {
    /* Mirror kloak's downstream call so the fuzzer reaches the
     * xkb_state_new path too. */
    struct xkb_state *state = xkb_state_new(keymap);
    if (state != NULL) {
      xkb_state_unref(state);
    }
    xkb_keymap_unref(keymap);
  }
  xkb_context_unref(ctx);

  free(buf);
  return 0;
}
