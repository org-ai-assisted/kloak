#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_poll_timeout. 16-byte input: two LE
# int64 values (sched_time, current_time).
"""Emit fuzz_poll_timeout seeds into the directory given on argv[1]."""
import os
import struct
import sys

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


def seed(sched: int, current: int) -> bytes:
    return struct.pack("<qq", sched, current)


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "zero_zero":      seed(0, 0),
        "normal_100ms":   seed(1700000100, 1700000000),
        "past":           seed(1700000000, 1700000100),
        "intmax_min":     seed(INT64_MAX, 0),
        "min_intmax":     seed(INT64_MIN, INT64_MAX),
        "both_intmax":    seed(INT64_MAX, INT64_MAX),
        "both_intmin":    seed(INT64_MIN, INT64_MIN),
        "pos_overflow":   seed(INT64_MAX, -1),
        "neg_overflow":   seed(INT64_MIN, 1),
        "over_intmax_ms": seed(1_000_000_000_000, 999_999_000_000),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
