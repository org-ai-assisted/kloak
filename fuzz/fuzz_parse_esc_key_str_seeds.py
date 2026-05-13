#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_parse_esc_key_str. The harness treats
# its input as the CLI string passed to --esc-key-combo;
# comma-separates tokens, pipe-separates alt keys within a
# token. The harness rejects inputs containing internal NULs.
"""Emit fuzz_parse_esc_key_str seeds into the directory given on argv[1]."""
import os
import sys


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "single_key":       b"KEY_ESC",
        "two_keys":         b"KEY_LEFTSHIFT,KEY_ESC",
        "alt_keys":         b"KEY_LEFTSHIFT|KEY_RIGHTSHIFT,KEY_ESC",
        "three_alt_three":  b"KEY_A|KEY_B|KEY_C,KEY_D,KEY_E",
        "unknown_key":      b"KEY_NOPE",
        "empty":            b"",
        "trailing_comma":   b"KEY_A,",
        "double_pipe":      b"KEY_A||KEY_B",
        "stray_chars":      b"KEY_A?,KEY_B",
        "many_commas":      b",,,,,,",
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
