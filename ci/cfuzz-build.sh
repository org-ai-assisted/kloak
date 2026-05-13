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

## Dead-strip unreachable code so the harness binary does not
## carry an NEEDED entry on libinput.so / libwayland-client.so /
## etc. The fuzz harnesses target pure parsers and never reach
## handle_libinput_event, applayer_wayland_init, or the other
## libinput/wayland-dependent functions in kloak.c. With
## -ffunction-sections + -Wl,--gc-sections the linker drops those
## sections entirely; --as-needed then prunes the shared libs from
## NEEDED. Without this, ClusterFuzzLite's run-fuzzers container
## (which only has libc) cannot launch the binary - "error while
## loading shared libraries: libinput.so.10".
SECTION_CFLAGS="-ffunction-sections -fdata-sections"
## $ORIGIN in single-quotes survives shell expansion and reaches
## the linker literally; at runtime the dynamic loader replaces it
## with the directory containing the binary, so .so files bundled
## next to the binary in $OUT/ are found without setting
## LD_LIBRARY_PATH.
GC_LDFLAGS="-Wl,--gc-sections -Wl,--as-needed -Wl,-rpath,\$ORIGIN"

for harness in fuzz/fuzz_*.c; do
  name="$(basename -- "${harness}" .c)"
  printf 'building %s\n' "${name}"

  # shellcheck disable=SC2086
  ${CC} ${CFLAGS} ${SECTION_CFLAGS} \
    -DKLOAK_FUZZING \
    ${PKG_CFLAGS_VALUE} \
    "${harness}" \
    "${PROTO_SRC[@]}" \
    -o "${OUT}/${name}" \
    ${LIB_FUZZING_ENGINE} \
    ${GC_LDFLAGS} \
    -lm -lrt \
    ${PKG_LIBS_VALUE}

  printf 'compiled %s -> %s\n' "${name}" "${OUT}/${name}"
done

## Bundle non-system shared libs alongside the binaries. The
## OSS-Fuzz ClusterFuzzLite run-fuzzers container ships only the
## libc-class base, so libraries the build container's apt
## installed (libwayland-client, etc.) must travel with the
## artifacts.
##
## The wayland-scanner-generated protocol .c files (xdg-shell-
## protocol.c, etc.) reference wl_output_interface /
## wl_seat_interface / wl_surface_interface from libwayland-client;
## those references survive --gc-sections because they live in
## static interface tables transitively reached from kloak.c's
## globals. Bundling is simpler than the alternative of source-
## level guards across ~1000 lines of wayland-handling code in
## kloak.c.
##
## libc / libm / libpthread / libdl / libresolv / libgcc_s /
## libstdc++ are part of the run container's base image and
## should NOT be copied (would risk ABI skew).
printf 'bundling non-system shared libs into %s/\n' "${OUT}"
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
        ## Multiple harnesses share .so deps; skip if already
        ## copied. Avoids both wasted IO and 'cp -n' deprecation
        ## warnings from coreutils 9+.
        dest="${OUT}/$(basename -- "${so}")"
        if [ ! -e "${dest}" ]; then
          cp -L "${so}" "${dest}"
        fi
        ;;
    esac
  done
done
ls -1 "${OUT}/" | grep -E '\.so' || true
