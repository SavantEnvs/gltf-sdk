#!/usr/bin/env bash
#
# mayhem/build.sh -- build glTF-SDK's two libFuzzer harnesses (+ standalone reproducers), AND
# glTF-SDK's own upstream GLTFSDK.Test suite (356 gtest cases, built via the project's NORMAL
# CMake flags) for mayhem/test.sh.
#
#   fuzz_gltf -- Deserialize() an untrusted glTF JSON document into a Document, then walk a
#                bounded slice of it (meshes/primitives, accessors, bufferViews, images),
#                exercising the RapidJSON-schema validator, the base64 data-URI decoder, and the
#                bounds-checked binary accessor readers.
#   fuzz_glb  -- same, but the input is a full GLB container: GLBResourceReader first parses the
#                12-byte header + length-prefixed JSON/BIN chunk framing (GLBResourceReader.cpp
#                Init(), including the 64-bit chunk-length-sum overflow guards) before handing
#                off to the same Deserialize()+walk path -- reaching the "read straight from the
#                embedded BIN chunk" accessor path fuzz_gltf's plain-JSON input cannot.
#
# See mayhem/harnesses/fuzz_common.h for why the harnesses take bytes only from the fuzzer (a
# NullStreamReader that fails every external-URI resolution -- there is no companion .bin/.png
# file on disk, and the image is read-only during coverage collection: SPEC 6.2 item 13) and why
# the object-graph walk is bounded to flat, non-recursive containers.
#
# -------------------------------------------------------------------------------------------
# Two build-system quirks this script works around, NEITHER by editing an upstream file:
#
# 1. GLTFSDK/CMakeLists.txt auto-generates GLTFSDK/Source's SchemaJson.h (the glTF JSON schema
#    text, baked in as C++ string literals) via a pre-build add_custom_command that shells out to
#    `pwsh`/`powershell` (GenerateSchemaJsonHeader.ps1). The base image ships no PowerShell.
#    mayhem/toolshim/pwsh is a fake `pwsh` that CMake's find_program(POWERSHELL_PATH NAMES pwsh
#    powershell ...) discovers via PATH (prepended below) -- it ignores the real PowerShell
#    arguments and calls mayhem/gen_schema_json.py, a small Python script that emits the
#    byte-for-byte-equivalent header content (see that script's header comment for exactly why).
#
# 2. GLTFSDK/Source/SchemaValidation.cpp calls a 4-argument rapidjson::SchemaDocument
#    constructor that only exists on a commit AFTER the 1.1.0 release -- Debian's rapidjson-dev
#    (1.1.0+dfsg2-7.4) is too old and fails to compile. RapidJSON is what
#    External/RapidJSON/CMakeRapidJSONDownload.txt.in's ExternalProject_Add pins
#    (232389d4f1012dddec4ef84861face2d2ba85709, with a local patch for CWE-476 in schema.h --
#    External/RapidJSON/patches/fix-null-allocator-deref.cmake); building that exact commit
#    ourselves is what mayhem/Dockerfile does (root, ONLINE, once), installing it to
#    /opt/toolchains/gltf-sdk-deps/rapidjson. Every cmake configure below points
#    CMAKE_PREFIX_PATH there, so `find_package(RapidJSON CONFIG)` (root CMakeLists.txt) succeeds
#    immediately and upstream's own add_subdirectory(External/RapidJSON) -- and the repeated,
#    network-touching git ExternalProject it would otherwise perform on every reconfigure (CMake
#    re-runs its own configure step on every single ninja invocation for this project, a stock
#    Ninja-generator behavior around a few "always dirty" phony dependency edges -- not something
#    this repo does specially) -- is never entered, online OR offline.
# -------------------------------------------------------------------------------------------
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) -- must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# Always ensure the LIBRARY gets SanitizerCoverage instrumentation, regardless of the base
# image's default or an empty override -- otherwise Mayhem would see 0 edges from the parser
# despite the harness translation unit itself being instrumented via $LIB_FUZZING_ENGINE.
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) ;;  # already present
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac
# DWARF <= 3 (SPEC 6.2 item 10): clang-19's plain -g emits DWARF-5; be explicit.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS
: "${SRC:=/mayhem}"
cd "$SRC"

# See quirk (1) above: the fake `pwsh` must be found before any real one.
export PATH="$SRC/mayhem/toolshim:$PATH"

# See quirk (2) above: baked ONLINE by mayhem/Dockerfile; every configure below consumes it.
RAPIDJSON_PREFIX=/opt/toolchains/gltf-sdk-deps/rapidjson
[ -f "$RAPIDJSON_PREFIX/include/rapidjson/document.h" ] || {
  echo "FATAL: $RAPIDJSON_PREFIX not populated -- mayhem/Dockerfile's RapidJSON install step did not run" >&2
  exit 1
}

CMAKE_COMMON=(
  -G Ninja
  -DCMAKE_C_COMPILER="$CC"
  -DCMAKE_CXX_COMPILER="$CXX"
  -DBUILD_SHARED_LIBS=OFF
  -DENABLE_SAMPLES=OFF
  -DCMAKE_PREFIX_PATH="$RAPIDJSON_PREFIX"
)

BUILD_ROOT="$SRC/mayhem-build"
mkdir -p "$BUILD_ROOT"

# ── 1) Sanitized library + harnesses (SanCov + ASan/UBSan + DWARF-3). ENABLE_UNIT_TESTS=OFF: the
#       fuzz build has no business pulling in GTest at all. ─────────────────────────────────────
FUZZ_BUILD="$BUILD_ROOT/fuzz"
cmake -S "$SRC" -B "$FUZZ_BUILD" "${CMAKE_COMMON[@]}" \
  -DENABLE_UNIT_TESTS=OFF \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
cmake --build "$FUZZ_BUILD" --target GLTFSDK -j"$MAYHEM_JOBS"

FUZZ_LIB="$FUZZ_BUILD/GLTFSDK/libGLTFSDK.a"
[ -f "$FUZZ_LIB" ] || { echo "FATAL: $FUZZ_LIB was not produced" >&2; exit 1; }

INC="-I $SRC/GLTFSDK/Inc"

# Standalone driver object, built once, linked into every harness's -standalone binary.
# Compiled as C (-x c): a C++ harness otherwise mangles its LLVMFuzzerTestOneInput symbol.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$BUILD_ROOT/standalone_main.o"

HARNESS_DIR="$SRC/mayhem/harnesses"
for h in fuzz_gltf fuzz_glb; do
  $CXX -std=gnu++14 $SANITIZER_FLAGS $DEBUG_FLAGS $INC $LIB_FUZZING_ENGINE \
      "$HARNESS_DIR/$h.cpp" "$FUZZ_LIB" -o "/mayhem/$h"

  $CXX -std=gnu++14 $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
      "$HARNESS_DIR/$h.cpp" "$BUILD_ROOT/standalone_main.o" "$FUZZ_LIB" -o "/mayhem/$h-standalone"

  echo "built $h (+ standalone)"
done

# Ship the per-target libFuzzer dictionaries the Mayhemfiles reference -- a referenced-but-absent
# dict makes libFuzzer exit 1 at 0 edges.
cp -f "$SRC/mayhem/fuzz_gltf/fuzz_gltf.dict" /mayhem/fuzz_gltf.dict
cp -f "$SRC/mayhem/fuzz_glb/fuzz_glb.dict" /mayhem/fuzz_glb.dict

# ── 2) glTF-SDK's OWN upstream gtest suite (GLTFSDK.Test, 356 cases over 21 suites -- see
#       test/Source/*.cpp), a SEPARATE clean CMake tree, project NORMAL flags (Release, no
#       sanitizer, no DWARF override) -- an honest, non-triage functional oracle. Coexists fine
#       with step 1: separate build dir, no make-clean/stash dance needed. ENABLE_UNIT_TESTS=ON
#       pulls in GTest::gtest_main via find_package(GTest CONFIG) (libgtest-dev, apt -- a plain,
#       modern release with no API mismatch, unlike RapidJSON above). ─────────────────────────
TEST_BUILD="$BUILD_ROOT/oracle"
cmake -S "$SRC" -B "$TEST_BUILD" "${CMAKE_COMMON[@]}" \
  -DENABLE_UNIT_TESTS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  ${COVERAGE_FLAGS:+-DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" -DCMAKE_C_FLAGS="$COVERAGE_FLAGS"}
cmake --build "$TEST_BUILD" --target GLTFSDK.Test -j"$MAYHEM_JOBS"

UNIT_BIN="$TEST_BUILD/GLTFSDK.Test/GLTFSDK.Test"
# GLTFSDK.Test's own CMakeLists.txt POST_BUILDs a copy of Resources/ next to the binary under
# $<CONFIG> (here: Release/Resources/) -- TestUtils.h's relative "Resources/..." fixture paths
# only resolve when the binary is RUN from that directory (mayhem/test.sh cd's there).
RESOURCES_DIR="$TEST_BUILD/GLTFSDK.Test/Release/Resources"
[ -x "$UNIT_BIN" ] || { echo "FATAL: GLTFSDK.Test was not produced at $UNIT_BIN" >&2; exit 1; }
[ -d "$RESOURCES_DIR" ] || { echo "FATAL: $RESOURCES_DIR missing -- POST_BUILD resource copy did not run" >&2; exit 1; }

# GLTFSDK.Test MUST be dynamically linked so verify-repo's LD_PRELOAD sabotage shim can neuter
# it -- a statically-linked test binary would survive sabotage and make mayhem/test.sh a
# reward-hackable oracle (SPEC 6.3). Plain clang++ links dynamically by default; assert it so a
# toolchain change can't silently flip this.
if ! file "$UNIT_BIN" | grep -q 'dynamically linked'; then
  echo "FATAL: $UNIT_BIN is not dynamically linked -- the sabotage check could not neuter it," >&2
  echo "       which would make mayhem/test.sh a reward-hackable oracle." >&2
  file "$UNIT_BIN" >&2
  exit 1
fi

echo "built GLTFSDK.Test (dynamically linked gtest runner) at $UNIT_BIN, resources at $RESOURCES_DIR"

echo "build.sh complete:"
ls -la /mayhem/fuzz_gltf /mayhem/fuzz_glb /mayhem/fuzz_gltf-standalone /mayhem/fuzz_glb-standalone \
       /mayhem/fuzz_gltf.dict /mayhem/fuzz_glb.dict "$UNIT_BIN" 2>&1 || true
