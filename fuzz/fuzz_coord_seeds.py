#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_coord. Wire format:
#   1 byte    header: low 3 bits = geom_count (0..7),
#                     bit 3 = also-call-local-to-abs flag
#   4 bytes   x  (LE int32)
#   4 bytes   y  (LE int32)
#   1 byte    output_idx_byte (low 3 bits used; also doubles as
#                              NULL-slot mask)
#   geom_count * 16 bytes (x, y, w, h - 4 x LE int32 per geom)
"""Emit fuzz_coord seeds into the directory given on argv[1]."""
import os
import struct
import sys


def pack_geom(x: int, y: int, w: int, h: int) -> bytes:
    return struct.pack("<iiii", x, y, w, h)


def seed(hdr: int, x: int, y: int, idx_byte: int,
         geoms: list[tuple[int, int, int, int]]) -> bytes:
    data = bytes([hdr & 0xFF]) + struct.pack("<ii", x, y) + bytes([idx_byte & 0xFF])
    for g in geoms:
        data += pack_geom(*g)
    return data


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "single_inside":    seed(0x01 | 0x08, 50, 50, 0x00, [(0, 0, 100, 100)]),
        "single_neg_y":     seed(0x01 | 0x08, 50, -1, 0x00, [(0, 0, 100, 100)]),
        "two_side_by_side": seed(0x02 | 0x08, 150, 50, 0x00,
                                 [(0, 0, 100, 100), (100, 0, 100, 100)]),
        "overflow_geom":    seed(0x01 | 0x08, 100, 100, 0x00,
                                 [(0x7FFFFFF0, 0x7FFFFFF0, 1024, 1024)]),
        "null_slot":        seed(0x02 | 0x08, 50, 50, 0x01,
                                 [(0, 0, 100, 100), (100, 0, 100, 100)]),
        "no_geoms":         seed(0x00, 50, 50, 0x00, []),
        "huge_xy":          seed(0x01 | 0x08, 2147483640, 2147483640, 0x00,
                                 [(0, 0, 100, 100)]),
        "neg_geom":         seed(0x01 | 0x08, 50, 50, 0x00, [(-10, -10, 100, 100)]),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
