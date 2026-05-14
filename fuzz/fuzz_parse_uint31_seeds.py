#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_parse_uint31. The harness consumes one
# base-selector byte (low 2 bits index into {10, 16, 8, 2}) plus
# a NUL-trimmed ASCII representation of an integer.
"""Emit fuzz_parse_uint31 seeds into the directory given on argv[1]."""
import os
import sys


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    # base byte 0 -> base 10, 1 -> 16, 2 -> 8, 3 -> 2
    seeds: dict[str, bytes] = {
        "dec_zero":        b"\x00" + b"0",
        "dec_one":         b"\x00" + b"1",
        "dec_intmax":      b"\x00" + str(2**31 - 1).encode(),
        "dec_overflow":    b"\x00" + b"2147483648",
        "dec_negative":    b"\x00" + b"-1",
        "dec_empty":       b"\x00",
        "hex_ff":          b"\x01" + b"ff",
        "hex_int31_max":   b"\x01" + b"7fffffff",
        "oct_777":         b"\x02" + b"777",
        "bin_1010":        b"\x03" + b"1010",
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
