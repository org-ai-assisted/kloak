#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_layer_dims. 8-byte input: two LE
# uint32 values (width, height) that Wayland's layer-surface
# 'configure' event delivers.
"""Emit fuzz_layer_dims seeds into the directory given on argv[1]."""
import os
import struct
import sys


def seed(w: int, h: int) -> bytes:
    return struct.pack("<II", w, h)


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "fhd_1080":         seed(1920, 1080),
        "uhd_4k":           seed(3840, 2160),
        "vga":              seed(640, 480),
        "max_quarter":      seed(0x1FFFFFFF, 1),
        "over_quarter":     seed(0x20000000, 1),
        "huge_height":      seed(100, 0x80000001),
        "both_max":         seed(0x1FFFFFFF, 0x7FFFFFFF),
        "zero":             seed(0, 0),
        "zero_w":           seed(0, 1080),
        "stride_intmax":    seed(0x1FFFFFFF, 1),
        # CFLite-found regression: size64 * 3 overflowed int64
        "regression_int64_total_overflow":
                            seed(0x1FFFFFFF, 0x7FFFFFFF),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
