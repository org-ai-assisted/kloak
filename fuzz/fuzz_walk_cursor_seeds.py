#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_walk_cursor. Wire format:
#   1 byte    hdr (low 3 bits: geom_count)
#   1 byte    slot_byte (NULL-slot mask)
#   4 bytes   start.x (LE int32)
#   4 bytes   start.y
#   4 bytes   end.x
#   4 bytes   end.y
#   geom_count * 16 bytes (x, y, w, h)
"""Emit fuzz_walk_cursor seeds into the directory given on argv[1]."""
import os
import struct
import sys


def pack_geom(x: int, y: int, w: int, h: int) -> bytes:
    return struct.pack("<iiii", x, y, w, h)


def seed(hdr: int, slot: int, sx: int, sy: int, ex: int, ey: int,
         geoms: list[tuple[int, int, int, int]]) -> bytes:
    data = bytes([hdr & 0xFF, slot & 0xFF]) + struct.pack("<iiii", sx, sy, ex, ey)
    for g in geoms:
        data += pack_geom(*g)
    return data


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "horiz_straight":  seed(0x01, 0x00, 100, 100, 800, 100,
                                 [(0, 0, 1920, 1080)]),
        "diag":            seed(0x01, 0x00, 100, 100, 800, 800,
                                 [(0, 0, 1920, 1080)]),
        "two_side_walk":   seed(0x02, 0x00, 100, 100, 2000, 100,
                                 [(0, 0, 1920, 1080), (1920, 0, 1920, 1080)]),
        "off_start":       seed(0x01, 0x00, -100, -100, 50, 50,
                                 [(0, 0, 100, 100)]),
        "end_off":         seed(0x01, 0x00, 50, 50, 200, 200,
                                 [(0, 0, 100, 100)]),
        "diag_off_void":   seed(0x01, 0x00, 50, 50, 5000, 5000,
                                 [(0, 0, 100, 100)]),
        "all_null":        seed(0x07, 0x7F, 0, 0, 100, 100, []),
        "no_geoms":        seed(0x00, 0x00, 0, 0, 100, 100, []),
        "intmax_walk":     seed(0x01, 0x00, 2147483640, 2147483640,
                                 2147483647, 2147483647,
                                 [(0, 0, 2147483647, 1)]),
        "disjoint_walk":   seed(0x02, 0x00, 100, 100, 6000, 100,
                                 [(0, 0, 1920, 1080), (4000, 0, 1920, 1080)]),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
