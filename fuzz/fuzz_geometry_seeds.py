#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_geometry. The harness pulls 6 +
# 4 + 4 = 14 little-endian int32 values via take_int32, in
# this order:
#   point check:  x, y, rect_x, rect_y, rect_width, rect_height
#   screen touch: a.x, a.y, a.width, a.height
#                 b.x, b.y, b.width, b.height
"""Emit fuzz_geometry seeds into the directory given on argv[1]."""
import os
import struct
import sys


def pack(*vals: int) -> bytes:
    return b"".join(struct.pack("<i", v) for v in vals)


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        # point inside, simple touching pair
        "inside_touching": pack(
            50, 50, 0, 0, 100, 100,           # point inside
            0, 0, 100, 100,                   # screen a
            100, 0, 100, 100),                # screen b touches a
        # point outside, screens overlap
        "outside_overlap": pack(
            500, 500, 0, 0, 100, 100,
            0, 0, 100, 100,
            50, 50, 100, 100),
        # screens disjoint
        "disjoint": pack(
            0, 0, 0, 0, 0, 0,
            0, 0, 100, 100,
            500, 500, 100, 100),
        # INT32_MAX boundary (was the original overflow trigger)
        "intmax_edge": pack(
            0x7FFFFFFE, 0x7FFFFFFE, 0, 0, 0x7FFFFFFF, 0x7FFFFFFF,
            0, 0, 0x7FFFFFFF, 1,
            0, 0, 1, 0x7FFFFFFF),
        # zero-size geometry
        "zero_size": pack(
            0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0),
        # negative coords (rejected)
        "negative": pack(
            -1, -1, -1, -1, -1, -1,
            -1, -1, 100, 100,
            -1, -1, 100, 100),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
