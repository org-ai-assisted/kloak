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

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

export OUT="${OUT:-${REPO_ROOT}/out}"
export CC="${CC:-clang}"
export CFLAGS="${CFLAGS:--O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined}"
export LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
export LDFLAGS="${LDFLAGS:-}"

mkdir -p -- "${OUT}"
exec "${MAKE:-make}" -C "${REPO_ROOT}" fuzz
