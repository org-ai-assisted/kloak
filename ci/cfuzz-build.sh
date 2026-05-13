#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Build script for kloak libFuzzer harnesses.
##
## Two entry contexts:
##
## 1. Invoked by .clusterfuzzlite/build.sh inside the OSS-Fuzz
##    base-builder container. $SRC / $OUT / $CC / $CFLAGS /
##    $LIB_FUZZING_ENGINE are pre-set by the container (clang +
##    sanitizer wiring + -O1 / -fno-omit-frame-pointer).
##
## 2. Invoked by ci/cfuzz-run.sh on the host (no Docker, no
##    sanitizer-aware $CC). Picks sensible defaults: clang +
##    -fsanitize=fuzzer,address,undefined. Useful for local
##    developer iteration without spinning up Docker.
##
## In both modes the kloak upstream hardening flags from the
## Makefile (WARN_CFLAGS + FORTIFY_CFLAGS + BIN_CFLAGS, and the
## LDFLAGS too) are APPENDED to whatever $CFLAGS / $LDFLAGS the
## caller supplied. Keep this list in sync with the Makefile if
## upstream tightens hardening further. We append rather than
## replace so libFuzzer's sanitizer wiring (-fsanitize=fuzzer-no-
## link,address,undefined and -fno-omit-frame-pointer) survives.
##
## The harnesses include only kloak's pure parser / geometry /
## coord / inotify / pixbuf / traverse / esc_combo surfaces. No
## libinput / wayland / libevdev / xkbcommon linkage, no wayland-
## scanner codegen, no rpath / library bundling - the resulting
## binaries launch in any libc-class environment, including OSS-
## Fuzz's minimal run-fuzzers container.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd -- "${REPO_ROOT}"

## --- Mode detection -------------------------------------------------

if [ -z "${OUT:-}" ]; then
  OUT="${REPO_ROOT}/out"
  mkdir -p -- "${OUT}"
fi
if [ -z "${CC:-}" ]; then
  CC="clang"
fi
if [ -z "${CFLAGS:-}" ]; then
  CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined"
fi
if [ -z "${LDFLAGS:-}" ]; then
  LDFLAGS=""
fi
if [ -z "${LIB_FUZZING_ENGINE:-}" ]; then
  LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
fi

## --- kloak upstream hardening flags (mirrors Makefile) --------------
##
## Source of truth: ../Makefile WARN_CFLAGS / FORTIFY_CFLAGS /
## BIN_CFLAGS / LDFLAGS. Re-checked against Makefile at the time
## these comments were written; if you edit one place, edit the
## other.
##
## Reference: https://www.kicksecure.com/wiki/Dev/compiler_hardening

KLOAK_WARN_CFLAGS="-Wall -Wextra -Wformat -Wformat=2 -Wconversion \
-Wimplicit-fallthrough -Werror=format-security -Werror=implicit \
-Werror=int-conversion -Werror=incompatible-pointer-types \
-Wformat-overflow -Wformat-signedness -Wformat-truncation \
-Wnull-dereference -Winit-self -Wmissing-include-dirs \
-Wshift-negative-value -Wshift-overflow -Wswitch-default \
-Wuninitialized -Walloca -Warray-bounds -Wfloat-equal -Wshadow \
-Wpointer-arith -Wundef -Wunused-macros -Wbad-function-cast -Wcast-qual \
-Wcast-align -Wwrite-strings -Wdate-time -Wstrict-prototypes \
-Wold-style-definition -Wredundant-decls -Winvalid-utf8 -Wvla \
-Wdisabled-optimization -Wstack-protector -Wdeclaration-after-statement"

## Non-clang-only warnings - clang as of 19.1 does not recognise
## several of the GCC-specific -W flags. Matches the Makefile
## guard.
case "$(${CC} --version 2>/dev/null || true)" in
  *clang*) ;;
  *)
    KLOAK_WARN_CFLAGS="${KLOAK_WARN_CFLAGS} \
-Wtrampolines -Wbidi-chars=any,ucn -Wformat-overflow=2 \
-Wformat-truncation=2 -Wshift-overflow=2 -Wtrivial-auto-var-init \
-Wstringop-overflow=3 -Wstrict-flex-arrays -Walloc-zero \
-Warray-bounds=2 -Wattribute-alias=2 \
-Wduplicated-branches -Wduplicated-cond -Wcast-align=strict \
-Wjump-misses-init -Wlogical-op"
  ;;
esac

## CRITICAL: -ftrapv must come AFTER -fno-strict-overflow because
## -fno-strict-overflow implies -fwrapv and -ftrapv must override
## -fwrapv. See Makefile comment of the same shape.
KLOAK_FORTIFY_CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
-fstack-clash-protection -fstack-protector-all \
-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing \
-fstrict-flex-arrays=3 -ftrapv -ftrivial-auto-var-init=pattern"

## Architecture-specific hardening. CFLite runs on x86_64; gating
## here keeps the local build portable.
TARGETARCH="$(${CC} -dumpmachine 2>/dev/null || true)"
case "${TARGETARCH}" in
  x86_64*-linux-gnu*)
    KLOAK_FORTIFY_CFLAGS="${KLOAK_FORTIFY_CFLAGS} -fcf-protection=full -fzero-call-used-regs=all"
  ;;
  aarch64*-linux-gnu*)
    KLOAK_FORTIFY_CFLAGS="${KLOAK_FORTIFY_CFLAGS} -mbranch-protection=standard -fzero-call-used-regs=all"
  ;;
esac

KLOAK_BIN_CFLAGS="-fPIE"

KLOAK_LDFLAGS="-Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now \
-Wl,-z,separate-code -Wl,--as-needed -Wl,--no-copy-dt-needed-entries -pie"

CFLAGS="${CFLAGS} ${KLOAK_WARN_CFLAGS} ${KLOAK_FORTIFY_CFLAGS} ${KLOAK_BIN_CFLAGS}"
LDFLAGS="${LDFLAGS} ${KLOAK_LDFLAGS}"

## --- Harness compile loop -------------------------------------------
##
## All current harnesses are libc-only (no pkg-config libs, no
## rpath). A previous iteration linked fuzz_xkb_keymap against
## libxkbcommon and used the per-harness extra-flags pattern; the
## harness was dropped because xkbcommon 0.10 (Ubuntu 20.04) had
## parser bugs that fuzzing discovered immediately. The per-
## harness extra-flags machinery is gone with it; restore it the
## same shape if a future harness needs a non-libc dep.

for harness in fuzz/fuzz_*.c; do
  name="$(basename -- "${harness}" .c)"

  printf 'building %s\n' "${name}"

  # shellcheck disable=SC2086
  ${CC} ${CFLAGS} \
    "${harness}" \
    -o "${OUT}/${name}" \
    ${LIB_FUZZING_ENGINE} \
    ${LDFLAGS}

  printf 'compiled %s -> %s\n' "${name}" "${OUT}/${name}"

  ## OSS-Fuzz / ClusterFuzzLite convention: a seed corpus for
  ## fuzzer 'X' is packaged as $OUT/X_seed_corpus.zip. CFLite
  ## auto-extracts it before the run and uses it to bootstrap
  ## libFuzzer's coverage exploration. Files we check into
  ## fuzz/corpus/<name>/ are pre-built inputs that exercise
  ## specific branches the random byte stream would take a long
  ## time to discover on its own (e.g. valid KEY_* names, a
  ## minimal-but-parseable xkb keymap, geometry-edge cases).
  if [ -d "fuzz/corpus/${name}" ] \
    && [ -n "$(ls -A "fuzz/corpus/${name}" 2>/dev/null)" ]; then
    # shellcheck disable=SC2164
    (cd "fuzz/corpus/${name}" && zip -q -r "${OUT}/${name}_seed_corpus.zip" .)
    printf 'packaged seed corpus -> %s_seed_corpus.zip (%d files)\n' \
      "${name}" "$(ls -1 "fuzz/corpus/${name}" | wc -l)"
  fi
done

## Bundle non-system shared libs alongside each harness so the
## OSS-Fuzz ClusterFuzzLite run-fuzzers:v1 container - which ships
## only libc-class runtime libs - can launch them. Walk every
## binary's ldd output and copy anything not in the run image's
## guaranteed set into $OUT/. For libc-only harnesses (the four
## simple parsers), the loop is a no-op.
##
## libc / libm / libpthread / libdl / libresolv / libgcc_s /
## libstdc++ / librt / ld-* are part of the run container's base
## image and intentionally NOT bundled - copying them risks ABI
## skew on the loader side.
for binary in "${OUT}"/fuzz_*; do
  [ -x "${binary}" ] || continue
  ldd "${binary}" 2>/dev/null | awk '/=> \// {print $3}' | while read -r so; do
    case "${so}" in
      /lib/x86_64-linux-gnu/libc.* | \
      /lib/x86_64-linux-gnu/libm.* | \
      /lib/x86_64-linux-gnu/libpthread.* | \
      /lib/x86_64-linux-gnu/libdl.* | \
      /lib/x86_64-linux-gnu/libresolv.* | \
      /lib/x86_64-linux-gnu/libgcc_s.* | \
      /lib/x86_64-linux-gnu/libstdc++.* | \
      /lib/x86_64-linux-gnu/librt.* | \
      /lib/x86_64-linux-gnu/ld-* | \
      /lib64/*)
        ;;  # system - leave to the run container's loader
      *)
        dest="${OUT}/$(basename -- "${so}")"
        if [ ! -e "${dest}" ]; then
          cp -L "${so}" "${dest}"
        fi
        ;;
    esac
  done
done
ls -1 "${OUT}/" | grep -E '\.so' || true
