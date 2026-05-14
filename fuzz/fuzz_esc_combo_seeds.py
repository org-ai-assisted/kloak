#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_esc_combo. The first byte selects one
# of four pre-configured combos; remaining bytes are (uint32_t
# key, uint8_t pressed_byte) pairs replayed against the
# selected combo. Pre-built combos are mapped to the same shapes
# the harness's LLVMFuzzerInitialize builds:
#   0: KEY_ESC
#   1: KEY_RIGHTSHIFT,KEY_ESC
#   2: KEY_LEFTSHIFT|KEY_RIGHTSHIFT,KEY_ESC
#   3: KEY_A|KEY_B|KEY_C,KEY_D,KEY_E
"""Emit fuzz_esc_combo seeds into the directory given on argv[1]."""
import os
import struct
import sys

# evdev key codes referenced by the seeds below. Values match
# linux/input-event-codes.h.
KEY_ESC, KEY_A, KEY_B, KEY_C, KEY_D, KEY_E = 1, 30, 48, 46, 32, 18
KEY_LEFTSHIFT, KEY_RIGHTSHIFT = 42, 54
KEY_F1 = 59


def pair(key: int, pressed: bool) -> bytes:
    return struct.pack("<I", key) + (b"\x01" if pressed else b"\x00")


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "c0_press_esc":          bytes([0]) + pair(KEY_ESC, True),
        "c0_press_release_esc":  bytes([0]) + pair(KEY_ESC, True) + pair(KEY_ESC, False),
        "c0_irrelevant_press":   bytes([0]) + pair(KEY_F1, True),
        "c1_full_combo":         bytes([1]) + pair(KEY_RIGHTSHIFT, True) + pair(KEY_ESC, True),
        "c1_reverse":            bytes([1]) + pair(KEY_ESC, True) + pair(KEY_RIGHTSHIFT, True),
        "c2_left_then_esc":      bytes([2]) + pair(KEY_LEFTSHIFT, True) + pair(KEY_ESC, True),
        "c2_right_then_esc":     bytes([2]) + pair(KEY_RIGHTSHIFT, True) + pair(KEY_ESC, True),
        "c3_a_d_e":              bytes([3]) + pair(KEY_A, True) + pair(KEY_D, True) + pair(KEY_E, True),
        "c3_b_d_e":              bytes([3]) + pair(KEY_B, True) + pair(KEY_D, True) + pair(KEY_E, True),
        "c3_c_d_e":              bytes([3]) + pair(KEY_C, True) + pair(KEY_D, True) + pair(KEY_E, True),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
