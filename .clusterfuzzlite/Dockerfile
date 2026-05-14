## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ClusterFuzzLite C/C++ Dockerfile.
## https://google.github.io/clusterfuzzlite/build-integration/c-cpp-lang/
##
## Image: gcr.io/oss-fuzz-base/base-builder, :latest tag.
##
## Trust root - this image path is the canonical C/C++ base for
## OSS-Fuzz / ClusterFuzzLite, published by Google's OSS-Fuzz
## project:
##   https://github.com/google/oss-fuzz/tree/master/infra/base-images/base-builder
##
## We pin :latest (currently sha256:5ca8fa8b...) rather than the
## ubuntu-24-04 tag. CFLite's run-fuzzers container is hardcoded
## to clusterfuzzlite-run-fuzzers:v1 (the run_fuzzers GitHub
## Action exposes no input to override the image), and that v1 tag
## ships Ubuntu 20.04 / glibc 2.31. A binary built against the
## ubuntu-24-04 base-builder (glibc 2.39) cannot load there - the
## loader rejects it with "GLIBC_2.38 not found". OSS-Fuzz keeps
## :latest matched to the run-fuzzers :v1 ABI for this reason.
##
## Upstream tracking:
##   https://github.com/google/clusterfuzzlite/issues/145 - asks
##     for Ubuntu 20.04 -> 24.04 migration (open, June 2025).
##   https://github.com/google/clusterfuzzlite/pull/146 - proposes
##     flipping the build + run actions to :ubuntu-24-04-v1 tags
##     (not merged; reviewer blocked on missing opt-in / backward-
##     compat path for existing users).
##
## When that work lands and OSS-Fuzz republishes :latest pointing
## at the new ABI, this pin can be refreshed in a single digest
## swap - no source-level changes expected.
##
## Digest sha256:5ca8fa8b... resolved from the :latest tag via the
## registry manifest API docker-content-digest header (verification
## step, not trust source):
##   https://gcr.io/v2/oss-fuzz-base/base-builder/manifests/latest
FROM gcr.io/oss-fuzz-base/base-builder@sha256:5ca8fa8bd9f933429af8f4df2d2e268e0d1e2a4fc6fd6e0aa5c6b3f53dfc99c5

## The current harness set is libc-only and does not need any
## apt installs. A previous iteration linked fuzz_xkb_keymap
## against libxkbcommon, but xkbcommon 0.10 (Ubuntu 20.04, what
## the OSS-Fuzz base ships) has parser bugs that fuzzing
## discovers in seconds - NULL deref + memory leak both
## reproducible from the seed corpus. Those findings are
## xkbcommon-side, not kloak-side, and the apt sources are
## frozen until CFLite #146 lands. Re-enable the xkb harness +
## libxkbcommon-dev + pkg-config install once the run-fuzzers
## image is bumped to a modern Ubuntu.

COPY . $SRC/kloak
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/kloak
