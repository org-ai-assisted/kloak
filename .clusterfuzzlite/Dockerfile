## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ClusterFuzzLite C/C++ Dockerfile.
## https://google.github.io/clusterfuzzlite/build-integration/c-cpp-lang/
##
## Image: gcr.io/oss-fuzz-base/base-builder.
##
## Trust root - this image path is the canonical C/C++ base for
## OSS-Fuzz / ClusterFuzzLite, published by Google's OSS-Fuzz
## project. The Dockerfile that produces this image lives in the
## OSS-Fuzz repo; the language-specific guide tells integrators to
## use this exact path:
##   https://github.com/google/oss-fuzz/tree/master/infra/base-images/base-builder
##   https://google.github.io/oss-fuzz/getting-started/new-project-guide/
##
## Digest resolved from the 'latest' tag via the registry manifest
## API docker-content-digest header (verification step, not trust
## source):
##   https://gcr.io/v2/oss-fuzz-base/base-builder/manifests/latest
##
## NB: the digest must be re-resolved when kloak's source uses
## a wayland-client / libinput API that has not yet landed in the
## previously-pinned image's Ubuntu base. The bootstrap pin
## (sha256:6dd7113e..., Ubuntu 20.04, libinput 1.15.5,
## wayland-client 1.18) was too old for kloak's use of
## wl_output_listener.name / .description (wayland-client 1.20+)
## and LIBINPUT_EVENT_POINTER_SCROLL_WHEEL / _FINGER / _CONTINUOUS
## (libinput 1.19+); upstream OSS-Fuzz has since moved
## base-builder to Ubuntu 24.04 (libinput 1.25, wayland-client
## 1.22). Re-resolve via the URL above if the build breaks on a
## newer kloak source API.
FROM gcr.io/oss-fuzz-base/base-builder@sha256:58d7be505745c0aecafe174b5d3a967ca0660cc892452dc6d90944cd32985d5d

## Install kloak's build deps. The base image is Ubuntu-based, so
## apt works. wayland-protocols + libwayland-bin are needed for the
## wayland-scanner protocol codegen step the Makefile normally
## performs; see ci/cfuzz-build.sh for the codegen invocation.
RUN apt-get update && \
    apt-get install --yes --no-install-recommends \
      libinput-dev \
      libevdev-dev \
      libwayland-dev \
      libxkbcommon-dev \
      libwayland-bin \
      wayland-protocols \
      pkg-config && \
    rm -rf /var/lib/apt/lists/*

COPY . $SRC/kloak
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/kloak
