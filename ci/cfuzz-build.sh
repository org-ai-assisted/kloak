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
##    $LIB_FUZZING_ENGINE are pre-set by the container. Build deps
##    are pre-installed in the Dockerfile.
##
## 2. Invoked by ci/cfuzz-run.sh on the host (no Docker, no
##    sanitizer-aware $CC). Picks sensible defaults: clang +
##    -fsanitize=fuzzer,address,undefined. Useful for local
##    developer iteration without spinning up Docker.
##
## Both modes hand off to `make fuzz` so the Makefile is the single
## source of truth for the kloak compile flags and harness build
## rule. Variables are exported into make's environment (not passed
## on the command line) so the Makefile's
##   CFLAGS := <hardening> $(CFLAGS)
## composition step runs. A command-line `make CFLAGS=...` would
## override that step and the fuzz binaries would lose hardening.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

export OUT="${OUT:-${REPO_ROOT}/out}"
export CC="${CC:-clang}"
export CFLAGS="${CFLAGS:--O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined}"
export LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
export LDFLAGS="${LDFLAGS:-}"

mkdir --parents -- "${OUT}"
"${MAKE:-make}" --directory="${REPO_ROOT}" fuzz

## --- Runtime shared library copy ------------------------------------
##
## After the build, OSS-Fuzz copies $OUT into a stripped deploy
## container for bad_build_check and fuzzing. That deploy env has
## no -dev libraries, so any .so we link against dynamically must
## travel with the binary. The Makefile fuzz rule sets
## RPATH=$ORIGIN; this step populates $ORIGIN (i.e. $OUT) with
## every non-system .so each fuzz binary depends on.
##
## ldd output is parsed in the binary's own deploy-container; we
## run it here against the build-container libraries, which is the
## same root tree because of how OSS-Fuzz layers its images on
## base-builder. System libs (libc, libm, ld-linux, libgcc, ...)
## are filtered out - they exist in every deploy env.

shopt -s nullglob
for fuzzer in "${OUT}"/fuzz_*; do
  [ -x "${fuzzer}" ] || continue
  case "${fuzzer}" in
    *.zip|*.dict|*_seed_corpus*) continue ;;
  esac
  ldd -- "${fuzzer}" 2>/dev/null \
    | awk '/=> \//{print $3}' \
    | while IFS= read -r lib; do
        base=$(basename -- "${lib}")
        case "${base}" in
          libc.so.*|libc-*.so|ld-linux-*.so*|libm.so.*|librt.so.*|libpthread.so.*|libdl.so.*|libresolv.so.*|libnsl.so.*) ;;
          linux-vdso.so.*|linux-gate.so.*) ;;
          libgcc_s.so.*|libstdc++.so.*) ;;
          *)
            dest="${OUT}/${base}"
            [ -e "${dest}" ] || cp --dereference -- "${lib}" "${dest}"
            ;;
        esac
      done
done

## Each copied .so also needs RUNPATH=$ORIGIN so its OWN transitive
## deps resolve to siblings in $OUT. RUNPATH does not propagate
## through the loader - libinput.so.10's RUNPATH controls how
## libinput finds libmtdev.so.1, not the binary's RUNPATH. Without
## this step, OSS-Fuzz's bad_build_check rejects every fuzzer with
## 'libmtdev.so.1: cannot open shared object file' even though
## libmtdev is sitting right next to libinput in $OUT.
for lib in "${OUT}"/lib*.so*; do
  [ -f "${lib}" ] || continue
  patchelf --set-rpath '$ORIGIN' "${lib}"
done
