## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ClusterFuzzLite C/C++ Dockerfile.
## https://google.github.io/clusterfuzzlite/build-integration/c-cpp-lang/
##
## Image: gcr.io/oss-fuzz-base/base-builder, ubuntu-24-04 tag.
##
## Trust root - this image path is the canonical C/C++ base for
## OSS-Fuzz / ClusterFuzzLite, published by Google's OSS-Fuzz
## project:
##   https://github.com/google/oss-fuzz/tree/master/infra/base-images/base-builder
##
## We pin the ubuntu-24-04 tag rather than 'latest' (still Ubuntu
## 20.04) so the build environment matches the modern wayland +
## libinput versions kloak.c is written against. Without this,
## kloak's references to wl_output v4 events (wayland 1.20+) and
## the libinput 1.19+ high-resolution scroll API would force
## per-symbol #ifdef guards across kloak.c just to build the fuzz
## image - dead complexity in production code. The harnesses
## themselves do not link libinput / wayland (parsers-only
## refactor; see fuzz/fuzz_*.c), but a modern build base keeps
## the door open for future harnesses that DO want to compile
## kloak.c against the real APIs without conditional gates.
##
## Digest sha256:375d1e42... resolved from the 'ubuntu-24-04' tag
## via the registry manifest API docker-content-digest header
## (verification step, not trust source):
##   https://gcr.io/v2/oss-fuzz-base/base-builder/manifests/ubuntu-24-04
FROM gcr.io/oss-fuzz-base/base-builder@sha256:375d1e426c0bbbcc7fb347fa175cab40c5646216c5fd522f9f2b6d5c8cb70629

COPY . $SRC/kloak
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/kloak
