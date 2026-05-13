/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure inotify-event buffer parser, factored out of
 * handle_inotify_events() in kloak.c so the parsing logic can
 * be fuzzed in isolation (see fuzz/fuzz_inotify_parser.c). The
 * kernel guarantees the buffer it hands back from read() is
 * well-formed, but parse_inotify_buffer() now soft-returns on
 * the first malformed record instead of aborting, so adversarial
 * fuzz inputs exercise the bounds-check logic without
 * false-positive crashes.
 *
 * The pre-refactor code used assert() at each invariant; those
 * are defensible against a non-malicious kernel but make the
 * function impossible to harness because libFuzzer treats
 * abort() as a crash report. Trading the assertions for silent
 * early-return also improves production robustness: a
 * hypothetically misbehaving kernel cannot crash the kloak
 * process, it just stops processing the rest of the buffer.
 *
 * Single source of truth - both kloak.c (via #include below the
 * existing kloak_parsers / kloak_geometry pattern) and the fuzz
 * harness see the same parser.
 */

#ifndef KLOAK_INOTIFY_INC_H
#define KLOAK_INOTIFY_INC_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/inotify.h>
#include <sys/types.h>

typedef void (*inotify_dispatch_fn)(const struct inotify_event *ie);

/*
 * Walk a buffer of inotify_event records and call dispatch() for
 * each well-formed record. Stops silently on the first malformed
 * record (truncated header, ie->len beyond remaining buffer, or
 * ie->len wide enough to overflow ssize_t arithmetic).
 *
 * 'dispatch' may be NULL; the fuzz harness uses that path to
 * exercise the parser alone, without invoking attach_input_device
 * / detach_input_device.
 */
static void parse_inotify_buffer(const char *buf, ssize_t len,
  inotify_dispatch_fn dispatch) __attribute__((unused));
static void parse_inotify_buffer(const char *buf, ssize_t len,
  inotify_dispatch_fn dispatch) {
  if (buf == NULL || len <= 0) {
    return;
  }

  ssize_t rem_len = len;
  /* The kernel-supplied buffer is guaranteed sufficiently
   * aligned per inotify(7); the cast cannot be UB at runtime for
   * the production caller. Adversarial fuzz inputs may not be
   * aligned, but x86 / amd64 / aarch64 all tolerate unaligned
   * access for the only fields we read (uint32_t mask + uint32_t
   * len), and the parser does not dereference any wider type. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
  const struct inotify_event *ie = (const struct inotify_event *)buf;
#pragma GCC diagnostic pop

  while (true) {
    if (rem_len < (ssize_t)sizeof(struct inotify_event)) {
      return;
    }
    /* Guard against ie->len so large the addition below would
     * overflow ssize_t. */
    if ((uint32_t)ie->len > (uint32_t)(SSIZE_MAX - sizeof(struct inotify_event))) {
      return;
    }
    ssize_t struct_len =
      (ssize_t)sizeof(struct inotify_event) + (ssize_t)ie->len;
    if (struct_len > rem_len) {
      return;
    }

    if (dispatch != NULL) {
      dispatch(ie);
    }

    rem_len -= struct_len;
    if (rem_len <= 0) {
      return;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
    ie = (const struct inotify_event *)((const char *)ie + struct_len);
#pragma GCC diagnostic pop
  }
}

#endif /* KLOAK_INOTIFY_INC_H */
