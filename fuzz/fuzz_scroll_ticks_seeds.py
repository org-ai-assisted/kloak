#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_scroll_ticks. 8-byte input: one LE
# IEEE-754 double (the scroll accumulator value).
"""Emit fuzz_scroll_ticks seeds into the directory given on argv[1]."""
import math
import os
import struct
import sys


def seed(v: float) -> bytes:
    return struct.pack("<d", v)


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "zero":         seed(0.0),
        "one_tick":     seed(120.0),
        "ten_ticks":    seed(1200.0),
        "frac":         seed(60.0),
        "negative":     seed(-120.0),
        "inf":          seed(math.inf),
        "ninf":         seed(-math.inf),
        "nan":          seed(math.nan),
        "dbl_max":      seed(1.7976931348623157e308),
        "at_int32_max": seed(120.0 * (2**31 - 1) / 120),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
