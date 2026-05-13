#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_traverse_line. 20-byte input:
#   4 bytes  start.x  (LE int32)
#   4 bytes  start.y
#   4 bytes  end.x
#   4 bytes  end.y
#   4 bytes  pos
"""Emit fuzz_traverse_line seeds into the directory given on argv[1]."""
import os
import struct
import sys


def seed(sx: int, sy: int, ex: int, ey: int, pos: int) -> bytes:
    return struct.pack("<iiiii", sx, sy, ex, ey, pos)


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "horiz_short":   seed(0, 0, 100, 0, 50),
        "vert_short":    seed(0, 0, 0, 100, 50),
        "diag45":        seed(0, 0, 100, 100, 50),
        "pos_zero":      seed(5, 5, 100, 100, 0),
        "start_eq_end":  seed(42, 42, 42, 42, 10),
        "negative_xy":   seed(-100, -100, 100, 100, 50),
        "intmax_edge":   seed(2147483640, 2147483640, 2147483647, 2147483647, 1),
        "steep_gt_1":    seed(0, 0, 1, 100, 25),
        "steep_lt_1":    seed(0, 0, 100, 1, 25),
        "negative_pos":  seed(0, 0, 100, 100, -50),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
