#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_parse_uint32. Base selector byte (low
# 2 bits -> {16, 10, 8, 2}) plus an ASCII integer string. Cursor
# color is the production caller's main use case, so hex bases
# get the most seed budget.
"""Emit fuzz_parse_uint32 seeds into the directory given on argv[1]."""
import os
import sys


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "hex_zero":         b"\x00" + b"0",
        "hex_color_red":    b"\x00" + b"ffff0000",
        "hex_uint32_max":   b"\x00" + b"ffffffff",
        "hex_overflow":     b"\x00" + b"100000000",
        "hex_invalid":      b"\x00" + b"xyz",
        "hex_negative":     b"\x00" + b"-1",
        "dec_zero":         b"\x01" + b"0",
        "dec_uint32_max":   b"\x01" + b"4294967295",
        "oct_777":          b"\x02" + b"777",
        "bin_0000_0001":    b"\x03" + b"00000001",
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
