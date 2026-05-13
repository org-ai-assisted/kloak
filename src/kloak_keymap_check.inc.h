/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure pre-xkb keymap-buffer validation, factored out of
 * kb_handle_keymap() in kloak.c so fuzz/fuzz_keymap_check.c
 * can drive the format-validation + NUL-terminator-within-
 * bounds check that protects xkbcommon from a malicious /
 * malformed compositor-supplied keymap string.
 *
 * Production kb_handle_keymap() then mmaps the fd, calls this
 * validator on the mapping, and only hands the buffer to
 * xkb_keymap_new_from_string() when both checks pass. The xkb
 * call itself remains a libxkbcommon black box and is not
 * fuzzed here (see CFLite #145 / #146 - blocked on the run-
 * fuzzers container being upgraded off Ubuntu 20.04 which has
 * xkbcommon 0.10 with its own parser bugs).
 */

#ifndef KLOAK_KEYMAP_CHECK_INC_H
#define KLOAK_KEYMAP_CHECK_INC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef KLOAK_KEYMAP_XKB_V1_FORMAT
/* Same constant as WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 from
 * wayland-client-protocol.h (=1). Defining it locally keeps
 * this header free of wayland linkage so the fuzz harness can
 * include it without dragging libwayland in. */
#define KLOAK_KEYMAP_XKB_V1_FORMAT 1u
#endif

struct kloak_keymap_check_result {
  bool format_supported;   /* format == XKB_V1 */
  bool null_terminated;    /* memchr found '\0' within 'size' bytes */
};

/*
 * Validate a Wayland-supplied keymap buffer before it is
 * handed to xkb_keymap_new_from_string. The buffer must be
 * NUL-terminated (XKB v1 spec) AND the format identifier must
 * match XKB v1. A NULL buffer with size > 0 is a kernel /
 * compositor bug; treat it as not-NUL-terminated.
 *
 * The harness sweeps (format, buf, size) tuples; production
 * passes the wl_keyboard 'format' integer + the mmap'd region.
 */
static __attribute__((unused))
struct kloak_keymap_check_result check_keymap_buf_pure(
  uint32_t format, const char *buf, size_t size) {
  struct kloak_keymap_check_result out = { false, false };

  out.format_supported = (format == KLOAK_KEYMAP_XKB_V1_FORMAT);
  if (buf == NULL || size == 0U) {
    return out;
  }
  if (memchr(buf, '\0', size) != NULL) {
    out.null_terminated = true;
  }
  return out;
}

#endif /* KLOAK_KEYMAP_CHECK_INC_H */
