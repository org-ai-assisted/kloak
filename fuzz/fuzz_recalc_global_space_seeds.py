#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_recalc_global_space. Wire format:
#   1 byte   header (low 3 bits: geom_count 0..7)
#   1 byte   slot_byte (NULL-slot mask)
#   geom_count * 16 bytes (x, y, w, h)
"""Emit fuzz_recalc_global_space seeds into the directory given on argv[1]."""
import os
import struct
import sys


def pack(x: int, y: int, w: int, h: int) -> bytes:
    return struct.pack("<iiii", x, y, w, h)


def seed(hdr: int, slot: int,
         geoms: list[tuple[int, int, int, int]]) -> bytes:
    data = bytes([hdr & 0xFF, slot & 0xFF])
    for g in geoms:
        data += pack(*g)
    return data


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "one_screen":   seed(0x01, 0x00, [(0, 0, 1920, 1080)]),
        "two_side":     seed(0x02, 0x00, [(0, 0, 1920, 1080),
                                          (1920, 0, 1920, 1080)]),
        # Gap between the two screens triggers KLOAK_RECALC_GAP
        "two_gap":      seed(0x02, 0x00, [(0, 0, 1920, 1080),
                                          (3001, 0, 1920, 1080)]),
        "three_l":      seed(0x03, 0x00, [(0, 0, 1920, 1080),
                                          (1920, 0, 1920, 1080),
                                          (0, 1080, 1920, 1080)]),
        "null_slot":    seed(0x02, 0x01, [(0, 0, 100, 100),
                                          (100, 0, 100, 100)]),
        "zero_size":    seed(0x01, 0x00, [(0, 0, 0, 0)]),
        "neg_geom":     seed(0x01, 0x00, [(-10, 0, 100, 100)]),
        "intmax":       seed(0x01, 0x00, [(2147483640, 2147483640, 1024, 1024)]),
        "none":         seed(0x00, 0x00, []),
        "all_null":     seed(0x07, 0x7F, []),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
