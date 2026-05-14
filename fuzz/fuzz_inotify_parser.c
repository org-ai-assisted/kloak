/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for parse_inotify_buffer(), the inotify-
 * event record-walker factored out of handle_inotify_events()
 * in kloak.c. The kernel guarantees these records are well-
 * formed, but defence-in-depth: a misbehaving kernel module or
 * a future change in inotify(7) semantics could land malformed
 * bytes in the read buffer, and the parser must not over-read
 * past rem_len.
 *
 * The dispatch callback is left NULL so the fuzzer exercises the
 * parser's bounds-check loop in isolation - no attach / detach
 * device calls, no libinput linkage. The production-side dispatch
 * handler (dispatch_inotify_event in kloak.c) is unit-checked
 * separately by the explicit ie->len >= strlen("event") + 1
 * guard the refactor introduced.
 */

#include <stddef.h>
#include <stdint.h>

/* The pure helpers we test live in src/kloak.c. KLOAK_
 * FUZZ carves out the production sections (wayland /
 * libinput dispatch, globals, main) so this translation
 * unit only compiles the helpers + the struct types they
 * need. See the kloak.c header for details. */
#define KLOAK_FUZZ
#include "../src/kloak.c"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  parse_inotify_buffer((const char *)data, (ssize_t)size, NULL);
  return 0;
}
