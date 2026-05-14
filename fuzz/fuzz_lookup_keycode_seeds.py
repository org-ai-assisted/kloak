#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_lookup_keycode. The harness feeds the
# raw bytes as a C string to lookup_keycode(); seeds give the
# canonical KEY_* names so libFuzzer mutators have something to
# adjacent-mutate against.
"""Emit fuzz_lookup_keycode seeds into the directory given on argv[1]."""
import os
import sys


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "KEY_ESC":         b"KEY_ESC",
        "KEY_LEFTSHIFT":   b"KEY_LEFTSHIFT",
        "KEY_A":           b"KEY_A",
        "KEY_1":           b"KEY_1",
        "KEY_F1":          b"KEY_F1",
        "unknown":         b"KEY_NOPE",
        "empty":           b"",
        "lowercase":       b"key_esc",
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
