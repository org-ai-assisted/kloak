/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for compute_layer_dims_pure() - the
 * Wayland-layer-surface dimension validator extracted from
 * layer_surface_configure() in kloak.c. Production callers see
 * real compositor (width, height) pairs from a 'configure' event
 * (always well under INT32_MAX); the harness sweeps the full
 * uint32 range so the int64-promoted overflow guards stay
 * honest. The pre-refactor code did 'stride * height' in int32_t
 * and only asserted the bounds afterwards; under -ftrapv the
 * multiplication would trap before the assertion could fire.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../src/kloak_layer_dims.inc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint32_t width = 0;
  uint32_t height = 0;
  struct kloak_layer_dims dims = { 0 };

  if (size < 8U) {
    return 0;
  }

  memcpy(&width,  data + 0, sizeof(uint32_t));
  memcpy(&height, data + 4, sizeof(uint32_t));

  dims = compute_layer_dims_pure(width, height);
  asm volatile("" : :
    "r"(dims.width), "r"(dims.height), "r"(dims.stride), "r"(dims.size),
    "r"(dims.valid)
    : "memory");
  return 0;
}
