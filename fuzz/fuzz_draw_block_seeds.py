#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_draw_block. 17-byte input:
#   1 byte    flags: bit0 crosshair, bits1-2 frame_slot
#   4 bytes   x   (LE int32)
#   4 bytes   y   (LE int32)
#   4 bytes   rad (LE int32)
#   4 bytes   cursor_color (LE uint32)
"""Emit fuzz_draw_block seeds into the directory given on argv[1]."""
import os
import struct
import sys

INT32_MIN = -(1 << 31)


def seed(flags: int, x: int, y: int, rad: int, color: int) -> bytes:
    return (struct.pack("<B", flags & 0xFF)
            + struct.pack("<i", x)
            + struct.pack("<i", y)
            + struct.pack("<i", rad)
            + struct.pack("<I", color))


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "centered_small":  seed(0x01, 128, 128, 5, 0xFFFFFFFF),
        "centered_clear":  seed(0x00, 128, 128, 5, 0),
        "corner_topleft":  seed(0x01, 0, 0, 3, 0xFF00FF00),
        "corner_bottomrt": seed(0x01, 255, 255, 3, 0xFF00FF00),
        "negative_xy":     seed(0x01, -100, -100, 5, 0xFF00FF00),
        "huge_rad":        seed(0x01, 128, 128, 1024, 0xFF00FF00),
        "negative_rad":    seed(0x01, 128, 128, -5, 0xFF00FF00),
        "beyond_layer":    seed(0x01, 500, 500, 5, 0xFF00FF00),
        "frame_slot_3":    seed(0x01 | (3 << 1), 128, 128, 5, 0xFF00FF00),
        # CFLite-found bug: INT32_MIN rad makes 'x - rad' overflow
        # int32 and then wrap negative under the post-cast.
        "regression_intmin_rad":
                           seed(0x01, 251658495, -2147418112, INT32_MIN, 0xFF00FF00),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
