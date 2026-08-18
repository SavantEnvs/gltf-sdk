# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) -- builds ON TOP of the org C/C++ base image
# (ghcr.io/savantenvs/base). glTF-SDK is a C++14 library for parsing/serializing glTF 2.0
# JSON documents and GLB binary containers.
#
# Extra deps beyond the base:
#   libgtest-dev  -- apt (1.16.0-1 on trixie): the ORACLE build's GLTFSDK.Test suite, a plain,
#                    modern gtest release with no API surprises.
#   RapidJSON     -- built from glTF-SDK's OWN pinned commit (see mayhem/build.sh's header
#                    comment, quirk 2) instead of apt's rapidjson-dev: Debian ships release 1.1.0,
#                    whose rapidjson::SchemaDocument constructor is missing a parameter
#                    GLTFSDK/Source/SchemaValidation.cpp requires. Cloning + patching (the same
#                    CWE-476 fix upstream's own ExternalProject_Add applies) + installing it here,
#                    ONCE, ONLINE, means mayhem/build.sh's air-gapped re-run only ever CONSUMES
#                    this baked prefix (/opt/toolchains/gltf-sdk-deps/rapidjson) -- no network,
#                    and upstream's own network-touching External/RapidJSON ExternalProject path
#                    is never entered (find_package(RapidJSON CONFIG) succeeds immediately).
#
# Build (from the repo root, on the `mayhem` branch):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t mytag .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); an empty value breaks clang, so it
# is never baked as ENV -- build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# Declared WITHOUT a default so an unset arg lets the base ENV flow through to build.sh, while
# an explicit --build-arg (including an EMPTY one, for a no-sanitizer build) overrides it.
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# RapidJSON, pinned to the exact commit External/RapidJSON/CMakeRapidJSONDownload.txt.in fetches
# (232389d4f1012dddec4ef84861face2d2ba85709), patched with the project's OWN CWE-476 fix (a null
# rapidjson::Pointer allocator dereference in schema.h -- External/RapidJSON/patches). Header-only;
# `cmake --install` just stages the headers + a RapidJSONConfig.cmake at a fixed prefix. See the
# top-of-file comment and mayhem/build.sh's header comment (quirk 2) for why apt's rapidjson-dev
# cannot be used instead. Needs the repo's own patch script, so this runs AFTER the source COPY.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

USER root
RUN set -eux; \
    git clone --quiet https://github.com/Tencent/rapidjson.git /tmp/rapidjson-src; \
    git -C /tmp/rapidjson-src checkout --quiet 232389d4f1012dddec4ef84861face2d2ba85709; \
    cmake -DSOURCE_DIR=/tmp/rapidjson-src -P /mayhem/External/RapidJSON/patches/fix-null-allocator-deref.cmake; \
    cmake -S /tmp/rapidjson-src -B /tmp/rapidjson-build -G Ninja \
        -DRAPIDJSON_BUILD_DOC=OFF -DRAPIDJSON_BUILD_EXAMPLES=OFF -DRAPIDJSON_BUILD_TESTS=OFF \
        -DCMAKE_INSTALL_PREFIX=/opt/toolchains/gltf-sdk-deps/rapidjson; \
    cmake --build /tmp/rapidjson-build --target install; \
    rm -rf /tmp/rapidjson-src /tmp/rapidjson-build

# libgtest-dev for the (separate, non-sanitized) oracle build's GTest::gtest_main dependency.
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends libgtest-dev \
 && rm -rf /var/lib/apt/lists/*
USER mayhem

RUN bash mayhem/build.sh

# glTF-SDK's own upstream gtest suite (GLTFSDK.Test, built above with NORMAL flags against the
# real GLTFSDK.Test/Resources fixtures) -- a failing suite fails the image.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
