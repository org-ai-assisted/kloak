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
## In both modes we pull kloak's upstream hardening flag set
## (WARN_CFLAGS + FORTIFY_CFLAGS + BIN_CFLAGS + KLOAK_LDFLAGS)
## directly from the Makefile via the print-kloak-cflags /
## print-kloak-ldflags targets, then APPEND them to whatever
## $CFLAGS / $LDFLAGS the caller already supplied. Append rather
## than replace so libFuzzer's sanitizer wiring stays intact, and
## query-the-Makefile rather than re-spelling the flag list so
## there's a single source of truth - if upstream tightens
## hardening, the fuzz harnesses get it for free.
##
## The harnesses include only kloak's pure parser / geometry /
## inotify / esc_combo surfaces. No libinput / wayland / libevdev
## / xkbcommon linkage, no wayland-scanner codegen, no rpath /
## library bundling - the resulting binaries launch in any libc-
## class environment, including OSS-Fuzz's minimal run-fuzzers
## container.

## R-010 strict-mode quintet. inherit_errexit makes '$()' subshells
## honour errexit; shift_verbose logs when shift runs past argv end.
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## R-040 / R-110: this script runs inside the OSS-Fuzz base-
## builder container, which does NOT ship helper-scripts, so
## 'log' / 'die' are not available. printf with the fixed
## '%s\n' format from R-030 is the closest we can get without
## sourcing files that do not exist in the build environment.
##
## R-120: 'rm -rf -- ...' on a mktemp -d path further below is
## marked '## style-ok: no-safe-rm' for the same reason; safe-rm
## is not installed in the OSS-Fuzz container either, and the
## paths we delete are confined to a fresh mktemp dir we own.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd -- "${REPO_ROOT}"

## --- Mode detection -------------------------------------------------

if [ -z "${OUT:-}" ]; then
  OUT="${REPO_ROOT}/out"
  mkdir --parents -- "${OUT}"
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

## --- Pull kloak upstream hardening flags from the Makefile ----------
##
## Single source of truth: ../Makefile. The print-kloak-cflags /
## print-kloak-ldflags targets already handle the gcc-vs-clang and
## x86_64-vs-aarch64 conditionals; we just append the result.

KLOAK_CFLAGS_FROM_MAKEFILE="$(make --silent --directory "${REPO_ROOT}" CC="${CC}" print-kloak-cflags)"
KLOAK_LDFLAGS_FROM_MAKEFILE="$(make --silent --directory "${REPO_ROOT}" CC="${CC}" print-kloak-ldflags)"
CFLAGS="${CFLAGS} ${KLOAK_CFLAGS_FROM_MAKEFILE}"
LDFLAGS="${LDFLAGS} ${KLOAK_LDFLAGS_FROM_MAKEFILE}"

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

  printf '%s\n' "building ${name}"

  # shellcheck disable=SC2086
  ${CC} ${CFLAGS} \
    "${harness}" \
    -o "${OUT}/${name}" \
    ${LIB_FUZZING_ENGINE} \
    ${LDFLAGS}

  printf '%s\n' "compiled ${name} -> ${OUT}/${name}"

  ## OSS-Fuzz / ClusterFuzzLite convention: a seed corpus for
  ## fuzzer 'X' is packaged as $OUT/X_seed_corpus.zip. CFLite
  ## auto-extracts it before the run and uses it to bootstrap
  ## libFuzzer's coverage exploration.
  ##
  ## Seed bytes are GENERATED at build time from per-harness
  ## Python scripts at fuzz/<name>_seeds.py. The script receives
  ## one argument - the output directory - and is responsible
  ## for writing each seed as a separate file there. Keeping the
  ## generator source-controlled (instead of the binary blobs)
  ## means the wire-format intent is reviewable as code, the
  ## tree stays free of binary noise, and a contributor can
  ## tweak a seed by editing a few lines of Python rather than
  ## crafting bytes by hand. The generator is optional - a
  ## harness without one ships an empty corpus and libFuzzer
  ## starts from random bytes.
  if [ -f "fuzz/${name}_seeds.py" ]; then
    seed_tmpdir="$(mktemp -d)"
    if python3 "fuzz/${name}_seeds.py" "${seed_tmpdir}" \
      && [ -n "$(ls --almost-all "${seed_tmpdir}" 2>/dev/null)" ]; then
      # shellcheck disable=SC2164
      (cd "${seed_tmpdir}" && zip --quiet --recurse-paths "${OUT}/${name}_seed_corpus.zip" .)
      seed_count="$(ls --format=single-column "${seed_tmpdir}" | wc --lines)"
      printf '%s\n' "packaged seed corpus -> ${name}_seed_corpus.zip (${seed_count} files)"
    fi
    ## style-ok: no-safe-rm - safe-rm not present in OSS-Fuzz
    ## base-builder container; path is a fresh mktemp -d we own.
    rm --recursive --force -- "${seed_tmpdir}"
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
        ## system - leave to the run container's loader
        true
        ;;
      *)
        dest="${OUT}/$(basename -- "${so}")"
        if [ ! -e "${dest}" ]; then
          cp --dereference -- "${so}" "${dest}"
        fi
        ;;
    esac
  done
done
ls --format=single-column "${OUT}/" | grep --extended-regexp '\.so' || true
