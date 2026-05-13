/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * Pure layer-dimension validator for the (width, height) pair
 * that a Wayland layer_surface_v1 'configure' event carries.
 * Factored out of layer_surface_configure() in kloak.c so
 * fuzz/fuzz_layer_dims.c can exercise the integer-overflow
 * arithmetic without having to bring in libwayland / shm /
 * mmap.
 *
 * Returns four int32_t derivatives (width, height, stride, size)
 * + a 'valid' flag. All four arithmetic sites are performed in
 * int64_t and the result is rejected before assignment if it
 * would overflow int32_t - the original inline code did the
 * multiplication in int32_t and *then* asserted the bounds,
 * which means under -ftrapv the multiplication would trap before
 * the assertion could fire.
 *
 * Production wrapper in kloak.c still treats an invalid result
 * as a fatal compositor error (the assertions previously did
 * the same thing for the precondition pair). The pure variant
 * just returns valid=false.
 */

#ifndef KLOAK_LAYER_DIMS_INC_H
#define KLOAK_LAYER_DIMS_INC_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef KLOAK_LAYER_DIMS_MAX_UNRELEASED_FRAMES
#define KLOAK_LAYER_DIMS_MAX_UNRELEASED_FRAMES 3
#endif

struct kloak_layer_dims {
  int32_t width;
  int32_t height;
  int32_t stride;
  int32_t size;
  bool valid;
};

/*
 * Wayland sends width/height as uint32_t; check that each one
 * fits in our int32_t derivative space, and that the cascading
 * 'stride = width * 4' and 'size = stride * height * frame_count'
 * arithmetic do not overflow int32_t. Production callers see
 * sub-megapixel dimensions; the harness sweeps the full uint32
 * range.
 */
static __attribute__((unused))
struct kloak_layer_dims compute_layer_dims_pure(uint32_t width,
  uint32_t height) {
  struct kloak_layer_dims out = { 0 };
  int64_t stride64 = 0;
  int64_t size64 = 0;
  int64_t total64 = 0;

  /* width must fit after multiplying by 4 (stride is bytes per
   * row at 4 BPP), and height must fit in int32 directly. */
  if (width > (uint32_t)(INT32_MAX / 4)) {
    return out;
  }
  if (height > (uint32_t)INT32_MAX) {
    return out;
  }

  stride64 = (int64_t)width * 4;
  size64 = stride64 * (int64_t)height;
  total64 = size64 * KLOAK_LAYER_DIMS_MAX_UNRELEASED_FRAMES;

  if (size64 < 0 || size64 > INT32_MAX) {
    return out;
  }
  if (total64 < 0 || total64 > INT32_MAX) {
    return out;
  }

  out.width  = (int32_t)width;
  out.height = (int32_t)height;
  out.stride = (int32_t)stride64;
  out.size   = (int32_t)size64;
  out.valid  = true;
  return out;
}

#endif /* KLOAK_LAYER_DIMS_INC_H */
