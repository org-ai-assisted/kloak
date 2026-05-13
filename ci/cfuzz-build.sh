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
##    $LIB_FUZZING_ENGINE are pre-set by the container.
##
## 2. Invoked by ci/cfuzz-run.sh on the host (no Docker, no
##    sanitizer-aware $CC). Picks sensible defaults: clang +
##    -fsanitize=fuzzer,address,undefined. Useful for local
##    developer iteration without spinning up Docker.
##
## The harnesses include only src/kloak_parsers.inc.h - the
## pure-parser surface factored out of kloak.c. No libinput /
## wayland / libevdev / xkbcommon linkage, no wayland-scanner
## codegen, no rpath / library bundling - the resulting binaries
## launch in any libc-class environment, including OSS-Fuzz's
## minimal run-fuzzers container.

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
if [ -z "${LIB_FUZZING_ENGINE:-}" ]; then
  LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
fi

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
    ${LIB_FUZZING_ENGINE}

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
