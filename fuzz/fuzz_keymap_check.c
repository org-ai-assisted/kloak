/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for check_keymap_buf_pure() - the format-
 * and NUL-terminator-within-bounds check kloak's kb_handle_
 * keymap() runs over a compositor-supplied keymap buffer before
 * handing it to xkb_keymap_new_from_string(). Production
 * callers see a uint32 format identifier from the Wayland
 * wire-protocol and a mmap'd fd whose contents are entirely
 * compositor-controlled. The harness drives the full uint32
 * range of formats and adversarial buffer contents / sizes.
 *
 * The xkb_keymap_new_from_string() call itself stays a
 * libxkbcommon black box for now - see CFLite #145 / #146,
 * blocked on the run-fuzzers container being upgraded off
 * Ubuntu 20.04 (xkbcommon 0.10 has its own parser bugs that
 * fuzzing finds in seconds).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../src/kloak_keymap_check.inc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint32_t format = 0;
  struct kloak_keymap_check_result r;

  /* Wire format:
   *   4 bytes  format (uint32 LE)
   *   rest     keymap buffer bytes (size - 4)
   */
  if (size < 4U) {
    return 0;
  }
  memcpy(&format, data, sizeof(uint32_t));

  r = check_keymap_buf_pure(format, (const char *)(data + 4),
    size - 4U);
  asm volatile("" : :
    "r"(r.format_supported), "r"(r.null_terminated)
    : "memory");
  return 0;
}
