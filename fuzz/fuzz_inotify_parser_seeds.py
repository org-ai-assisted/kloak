#!/usr/bin/env python3
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
#
# AI-Assisted
#
# Seed generator for fuzz_inotify_parser. The harness feeds the
# raw bytes to parse_inotify_buffer() which treats them as a
# linux/inotify.h byte stream:
#   struct inotify_event { int wd; uint32_t mask, cookie, len;
#                          char name[len]; };
"""Emit fuzz_inotify_parser seeds into the directory given on argv[1]."""
import os
import struct
import sys

# Linux inotify_event header is: int wd, uint32 mask, uint32
# cookie, uint32 len. 16 bytes total then 'len' bytes of name.
IN_CREATE = 0x100
IN_DELETE = 0x200


def event(wd: int, mask: int, cookie: int, name: bytes) -> bytes:
    # name is NUL-terminated AND NUL-padded to 16-byte alignment
    name_terminated = name + b"\x00"
    pad = (-len(name_terminated)) & 0xF
    name_field = name_terminated + (b"\x00" * pad)
    return (struct.pack("<iIII", wd, mask, cookie, len(name_field))
            + name_field)


def main(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seeds: dict[str, bytes] = {
        "create_event0":        event(1, IN_CREATE, 0, b"event0"),
        "delete_event1":        event(1, IN_DELETE, 0, b"event1"),
        "create_unrelated":     event(1, IN_CREATE, 0, b"mouse0"),
        "two_events":           event(1, IN_CREATE, 0, b"event0")
                                  + event(1, IN_DELETE, 0, b"event0"),
        # ie->len = 0 (no name field) - was the OOB case @ArrayBolt3 caught
        "len_zero":             struct.pack("<iIII", 1, IN_CREATE, 0, 0),
        # Short name (NUL-terminated but < strlen("event") + 1)
        "short_name":           event(1, IN_CREATE, 0, b"ev"),
        # Empty buffer
        "empty":                b"",
        # Truncated header
        "truncated":            b"\x01\x00\x00\x00",
        # Huge ie->len (rejected by the SSIZE_MAX guard)
        "huge_len":             struct.pack("<iIII",
                                            1, IN_CREATE, 0, 0xFFFFFFFF),
        # Internal NUL in name (name is whatever; only the prefix matters)
        "embedded_nul":         event(1, IN_CREATE, 0, b"ev\x00ent0"),
    }
    for name, payload in seeds.items():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(payload)


if __name__ == "__main__":
    main(sys.argv[1])
