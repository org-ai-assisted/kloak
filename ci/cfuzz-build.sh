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
## Per-harness extra flags / libs. fuzz_xkb_keymap links against
## libxkbcommon (the parser surface kloak feeds with compositor-
## supplied keymap strings); the other harnesses are libc-only.
##
## We do not use a global '-lxkbcommon -Wl,--as-needed' because
## CFLite's run-fuzzers:v1 container is not guaranteed to ship
## libxkbcommon.so; keeping the dep local to the one harness that
## needs it makes it obvious where to focus if a future bump of
## the runtime container breaks library resolution.

for harness in fuzz/fuzz_*.c; do
  name="$(basename -- "${harness}" .c)"

  extra_cflags=""
  extra_libs=""
  case "${name}" in
    fuzz_xkb_keymap)
      extra_cflags="$(pkg-config --cflags xkbcommon)"
      extra_libs="$(pkg-config --libs xkbcommon)"
      ;;
  esac

  printf 'building %s\n' "${name}"

  # shellcheck disable=SC2086
  ${CC} ${CFLAGS} \
    ${extra_cflags} \
    "${harness}" \
    -o "${OUT}/${name}" \
    ${LIB_FUZZING_ENGINE} \
    ${extra_libs}

  printf 'compiled %s -> %s\n' "${name}" "${OUT}/${name}"
done
