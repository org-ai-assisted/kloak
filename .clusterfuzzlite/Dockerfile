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
## Digest resolved from the 'ubuntu-24-04' tag via the registry
## manifest API docker-content-digest header (verification step,
## not trust source):
##   https://gcr.io/v2/oss-fuzz-base/base-builder/manifests/ubuntu-24-04
##
## kloak's source uses APIs that require:
##   - wayland-client >= 1.20 (wl_output_listener.name / .description)
##   - libinput >= 1.19 (LIBINPUT_EVENT_POINTER_SCROLL_WHEEL /
##     _FINGER / _CONTINUOUS, libinput_event_pointer_get_scroll_value{,_v120})
## The default :latest base-builder tag is still Ubuntu 20.04 with
## libinput 1.15.5 / wayland-client 1.18, which is too old. OSS-Fuzz
## publishes an :ubuntu-24-04 variant (libinput 1.25,
## wayland-client 1.22) - use that. Re-resolve the digest via the
## URL above when bumping.
FROM gcr.io/oss-fuzz-base/base-builder@sha256:f3807db09c7e544ab8376e6a551a1c541cc752b4022bf38c94b16f2cc2f80f00

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
      patchelf \
      pkg-config && \
    rm -rf /var/lib/apt/lists/*

COPY . $SRC/kloak
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/kloak
