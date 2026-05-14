/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's update_mouse_scroll(). End-to-end
 * exercises the scroll accumulator state machine:
 *   1. drain whole ticks from vert_scroll_accum and
 *      horiz_scroll_accum via get_ticks_from_scroll_accum (already
 *      covered by a dedicated harness, but here it runs in context),
 *   2. if any ticks were extracted, either merge them into a
 *      trailing MOUSESCROLL packet on evq_head, or allocate a new
 *      MOUSESCROLL packet,
 *   3. return the new packet (or NULL on merge / no-ticks).
 *
 * Worth fuzzing for:
 *   - the `+= vert_scroll_ticks` / `+= horiz_scroll_ticks` updates
 *     to an existing trailing packet (-ftrapv on signed overflow
 *     when both old and new ticks have the same sign and large
 *     magnitude),
 *   - safe_calloc -> input_packet sizing,
 *   - the tail-queue branch: TAILQ_LAST(&evq_head) returning a
 *     non-NULL non-MOUSESCROLL packet falls through to the alloc
 *     branch.
 *
 * The harness owns evq_head: it TAILQ_INITs once, drains any
 * leftover packets at the top of every iteration, then optionally
 * seeds the queue with a leading non-scroll packet and/or a
 * trailing MOUSESCROLL packet under a fuzzer-controlled mode byte
 * so all three merge/alloc branches are reachable. The vert and
 * horiz accumulators are sanitised the same way as in
 * fuzz_get_ticks_from_scroll_accum to honour the assert contract
 * on the transitive call.
 */

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void fuzz_drain_evq(void) {
  struct input_packet *pkt = NULL;

  while ((pkt = TAILQ_FIRST(&evq_head)) != NULL) {
    TAILQ_REMOVE(&evq_head, pkt, entries);
    free(pkt);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool initialized = false;
  uint8_t mode = 0;
  double v_accum = 0.0;
  double h_accum = 0.0;
  struct input_packet *seed_other = NULL;
  struct input_packet *seed_scroll = NULL;
  struct input_packet *result = NULL;

  if (!initialized) {
    TAILQ_INIT(&evq_head);
    initialized = true;
  }
  fuzz_drain_evq();

  if (size < 1U + 2U * sizeof(double)) {
    return 0;
  }
  mode = data[0];
  memcpy(&v_accum, data + 1U, sizeof(double));
  memcpy(&h_accum, data + 1U + sizeof(double), sizeof(double));

  /* Same contract sanitisation as fuzz_get_ticks_from_scroll_accum:
     the assertions inside get_ticks_from_scroll_accum require
     finite values in the integer-truncated INT32_MIN/MAX/120 band;
     clamp generously to 1e9. */
  if (!isfinite(v_accum) || !isfinite(h_accum)) {
    return 0;
  }
  if (v_accum > 1.0e9) {
    v_accum = 1.0e9;
  } else if (v_accum < -1.0e9) {
    v_accum = -1.0e9;
  }
  if (h_accum > 1.0e9) {
    h_accum = 1.0e9;
  } else if (h_accum < -1.0e9) {
    h_accum = -1.0e9;
  }
  vert_scroll_accum = v_accum;
  horiz_scroll_accum = h_accum;

  /* mode bit 0: prepend a non-scroll packet to force the
     TAILQ_LAST check to fall through to the alloc branch.
     mode bit 1: append a MOUSESCROLL packet to exercise the
     merge branch. */
  if ((mode & 0x1U) != 0U) {
    seed_other = calloc(1, sizeof(*seed_other));
    if (seed_other == NULL) {
      return 0;
    }
    seed_other->packet_type = KLOAK_PACKET_TYPE_MOUSEMOVE;
    TAILQ_INSERT_TAIL(&evq_head, seed_other, entries);
  }
  if ((mode & 0x2U) != 0U) {
    seed_scroll = calloc(1, sizeof(*seed_scroll));
    if (seed_scroll == NULL) {
      fuzz_drain_evq();
      return 0;
    }
    seed_scroll->packet_type = KLOAK_PACKET_TYPE_MOUSESCROLL;
    seed_scroll->data.mousescroll.vert_scroll_ticks = 0;
    seed_scroll->data.mousescroll.horiz_scroll_ticks = 0;
    TAILQ_INSERT_TAIL(&evq_head, seed_scroll, entries);
  }

  result = update_mouse_scroll();
  if (result != NULL) {
    TAILQ_INSERT_TAIL(&evq_head, result, entries);
  }

  fuzz_drain_evq();
  return 0;
}
