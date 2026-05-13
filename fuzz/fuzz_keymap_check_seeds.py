#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_keymap_check. 4 bytes format
# identifier (LE uint32) + buffer bytes.
"""Emit fuzz_keymap_check seeds into the directory given on argv[1]."""
import os
import struct
import sys


def seed(fmt: int, payload: bytes) -> bytes:
    return struct.pack("<I", fmt) + payload


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "valid_xkb_v1":   seed(1, b"xkb_keymap {};\x00"),
        "wrong_format":   seed(0, b"xkb_keymap {};\x00"),
        "format_max":     seed(0xFFFFFFFF, b"xkb_keymap {};\x00"),
        "no_nul":         seed(1, b"xkb_keymap {}"),
        "empty":          seed(1, b""),
        "only_nul":       seed(1, b"\x00"),
        "nul_at_end":     seed(1, b"x" * 100 + b"\x00"),
        "nul_mid":        seed(1, b"x" * 10 + b"\x00" + b"y" * 100),
        "big_no_nul":     seed(1, b"a" * 4000),
        "big_with_nul":   seed(1, b"a" * 3999 + b"\x00"),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
