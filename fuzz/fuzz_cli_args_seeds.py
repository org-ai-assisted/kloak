#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_cli_args. The harness splits the
# input on internal NUL bytes into argv tokens (argv[0] is
# hard-coded to 'kloak'). Each seed is a NUL-separated list of
# CLI arguments the production parser should handle.
"""Emit fuzz_cli_args seeds into the directory given on argv[1]."""
import os
import sys


def seed(*args: str) -> bytes:
    return b"\x00".join(arg.encode() for arg in args)


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "delay_100":          seed("-d", "100"),
        "startup_500":        seed("-s", "500"),
        "color_red":          seed("-c", "FF0000FF"),
        "color_transparent":  seed("-c", "00000000"),
        "nat_true":           seed("-n", "true"),
        "nat_false":          seed("-n", "false"),
        "esc_combo":          seed("-k", "KEY_LEFTSHIFT,KEY_ESC"),
        "help":               seed("-h"),
        "long_delay":         seed("--delay=42"),
        "multi":              seed("-d", "10", "-s", "20", "-c", "abcdef12"),
        "unknown_opt":        seed("-z"),
        "missing_arg":        seed("-d"),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
