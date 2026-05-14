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

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

## Resolve repo root regardless of caller's cwd.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd -- "${REPO_ROOT}"

## --- Mode detection -------------------------------------------------

## ClusterFuzzLite path: $OUT is set, $CC / $CFLAGS /
## $LIB_FUZZING_ENGINE pre-baked by base-builder.
## Local-dev path: nothing pre-set, fall back to clang + libFuzzer.
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

## --- Kloak hardening flags (mirror Makefile) ------------------------
##
## Mirror the compiler hardening that the production Makefile applies
## to kloak so the fuzz binaries exercise the same -ftrapv signed
## arithmetic, FORTIFY_SOURCE, stack protector, and warning surface
## as the binary that ships. Appended to ${CFLAGS} so OSS-Fuzz's
## sanitizer flags (set in the base-builder container) and the
## hardening flags compose; in local-dev mode ${CFLAGS} starts from
## our libFuzzer baseline above.
##
## WARN_CFLAGS / FORTIFY_CFLAGS / BIN_CFLAGS / LDFLAGS structure
## intentionally tracks Makefile lines 23-75 so a diff stays small.

CC_VERSION_OUT="$("${CC}" --version 2>/dev/null || true)"
TARGETARCH="$("${CC}" -dumpmachine 2>/dev/null || true)"

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

case "${CC_VERSION_OUT}" in
  *clang*)
    ## clang as of 19.1.0 does not support the gcc-only warnings
    ## below; gate them out of the clang build the same way the
    ## Makefile does.
    : ;;
  *)
    KLOAK_WARN_CFLAGS="${KLOAK_WARN_CFLAGS} \
-Wtrampolines -Wbidi-chars=any,ucn -Wformat-overflow=2 \
-Wformat-truncation=2 -Wshift-overflow=2 -Wtrivial-auto-var-init \
-Wstringop-overflow=3 -Wstrict-flex-arrays -Walloc-zero \
-Warray-bounds=2 -Wattribute-alias=2 \
-Wduplicated-branches -Wduplicated-cond -Wcast-align=strict \
-Wjump-misses-init -Wlogical-op" ;;
esac

## IMPORTANT: keep -ftrapv after -fno-strict-overflow; the latter
## implies -fwrapv, which -ftrapv must override. (Same caveat as
## the Makefile.)
KLOAK_FORTIFY_CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
-fstack-clash-protection -fstack-protector-all \
-fno-delete-null-pointer-checks -fno-strict-overflow -fno-strict-aliasing \
-fstrict-flex-arrays=3 -ftrapv -ftrivial-auto-var-init=pattern"

case "${TARGETARCH}" in
  x86_64*-linux-gnu)
    KLOAK_FORTIFY_CFLAGS="${KLOAK_FORTIFY_CFLAGS} \
-fcf-protection=full -fzero-call-used-regs=all" ;;
  aarch64*-linux-gnu)
    KLOAK_FORTIFY_CFLAGS="${KLOAK_FORTIFY_CFLAGS} \
-mbranch-protection=standard -fzero-call-used-regs=all" ;;
esac

KLOAK_BIN_CFLAGS="-fPIE"

CFLAGS="${CFLAGS} ${KLOAK_WARN_CFLAGS} ${KLOAK_FORTIFY_CFLAGS} ${KLOAK_BIN_CFLAGS}"

KLOAK_LDFLAGS="-Wl,-z,nodlopen -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now \
-Wl,-z,separate-code -Wl,--as-needed -Wl,--no-copy-dt-needed-entries -pie"
LDFLAGS="${LDFLAGS:-} ${KLOAK_LDFLAGS}"

## --- Wayland protocol codegen ---------------------------------------
##
## kloak.c #include's the generated protocol headers, so we need
## wayland-scanner to produce them before compiling any harness.
## Mirror the Makefile's targets.

PROTO_SRC=()
for proto_pair in \
  "xdg-shell.xml:src/xdg-shell-protocol" \
  "xdg-output-unstable-v1.xml:src/xdg-output-protocol" \
  "wlr-layer-shell-unstable-v1.xml:src/wlr-layer-shell" \
  "wlr-virtual-pointer-unstable-v1.xml:src/wlr-virtual-pointer" \
  "virtual-keyboard-unstable-v1.xml:src/virtual-keyboard" ; do
  xml="${proto_pair%%:*}"
  base="${proto_pair##*:}"
  wayland-scanner client-header < "protocol/${xml}" > "${base}.h"
  wayland-scanner private-code  < "protocol/${xml}" > "${base}.c"
  PROTO_SRC+=("${base}.c")
done

## --- Harness compile loop -------------------------------------------
##
## Each harness #include's src/kloak.c with -DKLOAK_FUZZING so
## main() is excluded; the harness file itself supplies
## LLVMFuzzerTestOneInput. We compile the protocol .c files into
## the same binary because kloak.c's body references their
## interface symbols even when those code paths are dead.
##
## pkg-config provides cflags/libs for libinput, libevdev,
## wayland-client, xkbcommon - the same set kloak's main Makefile
## consumes.

PKG_LIBS="libinput libevdev wayland-client xkbcommon"
PKG_CFLAGS_VALUE="$(pkg-config --cflags ${PKG_LIBS})"
PKG_LIBS_VALUE="$(pkg-config --libs ${PKG_LIBS})"

for harness in fuzz/fuzz_*.c; do
  name="$(basename -- "${harness}" .c)"
  printf 'building %s\n' "${name}"

  # shellcheck disable=SC2086
  ${CC} ${CFLAGS} \
    -DKLOAK_FUZZING \
    ${PKG_CFLAGS_VALUE} \
    "${harness}" \
    "${PROTO_SRC[@]}" \
    -o "${OUT}/${name}" \
    ${LIB_FUZZING_ENGINE} \
    ${LDFLAGS} \
    -lm -lrt \
    ${PKG_LIBS_VALUE}

  printf 'compiled %s -> %s\n' "${name}" "${OUT}/${name}"
done
