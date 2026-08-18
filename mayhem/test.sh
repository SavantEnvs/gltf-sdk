#!/usr/bin/env bash
#
# mayhem/test.sh -- RUN glTF-SDK's own upstream gtest suite (GLTFSDK.Test, built by
# mayhem/build.sh via the project's normal CMake flags against the real glTF/GLB fixtures under
# GLTFSDK.Test/Resources/) and emit a CTRF summary. Exit 0 iff nothing failed.
#
# BEHAVIORAL oracle (SPEC 6.3 anti-reward-hacking). GLTFSDK.Test is glTF-SDK's own upstream test
# aggregator (test/Source/*.cpp, 356 individual test cases across 21 gtest suites, driven through
# the GLTFSDK_TEST_CLASS/GLTFSDK_TEST_METHOD macros in GLTFSDK.TestUtils/UnitTestBridge.h -- see
# that header for why these are NOT the VS CppUnitTest framework on this platform: USE_GOOGLE_TEST
# defaults to 1, so on Linux the whole suite compiles straight to ordinary gtest TEST()/TEST_F()
# cases, no shim/bridge/CppUnitTest port needed). It deserializes real glTF/GLB fixtures and
# asserts exact VALUES (accessor data, extension flags, validation exceptions, round-tripped
# scalars, ...), not just "did not crash" -- a no-op/exit(0) patch to the library would make
# individual EXPECT_/ASSERT_ macros fail their comparisons, which gtest counts and reports in its
# JUnit-style XML -- not a stub that survives.
#
# GLTFSDK.Test is a plain, dynamically-linked clang++ executable (asserted by build.sh) -- unlike
# a statically-linked `go test`/`cargo test` binary, the verify-repo LD_PRELOAD sabotage shim CAN
# neuter it (constructor _exit(0)s it before main() runs, and therefore before gtest ever writes
# its XML report) -- the "no XML produced" check below then fails outright, so this oracle is
# caught by the mechanical sabotage check without a separate KAT probe.
#
# This script does NOT compile -- mayhem/build.sh already built GLTFSDK.Test.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/mayhem-build/oracle/GLTFSDK.Test/GLTFSDK.Test"
RUN_DIR="$SRC/mayhem-build/oracle/GLTFSDK.Test/Release"
if [ ! -x "$BIN" ]; then
  echo "missing $BIN -- run mayhem/build.sh first" >&2
  emit_ctrf "gltfsdk-gtest" 0 1 0
  exit 2
fi
if [ ! -d "$RUN_DIR/Resources" ]; then
  echo "missing $RUN_DIR/Resources -- run mayhem/build.sh first" >&2
  emit_ctrf "gltfsdk-gtest" 0 1 0
  exit 2
fi

XML_OUT="$(mktemp /tmp/gltfsdk-test-XXXXXX.xml)"
trap 'rm -f "$XML_OUT"' EXIT

# MUST run from RUN_DIR: TestUtils.h resolves fixture paths as the relative "Resources/..."
# (see GetAbsolutePath()), which only exist next to the binary's own $<CONFIG> directory.
echo "=== running: (cd $RUN_DIR && ../GLTFSDK.Test --gtest_output=xml:$XML_OUT) ==="
STDOUT_LOG="$(cd "$RUN_DIR" && "$BIN" --gtest_output="xml:$XML_OUT" 2>&1)"; rc=$?
printf '%s\n' "$STDOUT_LOG" | tail -60

# UNCONDITIONAL: a missing/empty XML report is a FAILURE, never a skip -- this is exactly what a
# neutered (exit(0)'d before main/gtest ever runs), crashed, or missing binary produces.
if [ ! -s "$XML_OUT" ]; then
  echo "FAIL: GLTFSDK.Test produced no XML report (neutered, crashed, or missing binary) -- rc=$rc" >&2
  emit_ctrf "gltfsdk-gtest" 0 1 0
  exit 1
fi

read -r TESTS FAILURES DISABLED ERRORS < <(python3 - "$XML_OUT" <<'PY'
import sys
import xml.etree.ElementTree as ET

def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0

try:
    root = ET.parse(sys.argv[1]).getroot()
except ET.ParseError:
    print(0, 0, 0, 0)
    sys.exit(0)

# gtest's top-level <testsuites> element already carries the aggregate counts.
tests = to_int(root.get('tests'))
failures = to_int(root.get('failures'))
disabled = to_int(root.get('disabled'))
errors = to_int(root.get('errors'))
print(tests, failures, disabled, errors)
PY
)
: "${TESTS:=0}" "${FAILURES:=0}" "${DISABLED:=0}" "${ERRORS:=0}"

if [ "$TESTS" -eq 0 ]; then
  echo "FAIL: gtest XML report shows 0 test cases -- the suite did not execute" >&2
  emit_ctrf "gltfsdk-gtest" 0 1 0
  exit 1
fi

FAILED=$(( FAILURES + ERRORS ))
PASSED=$(( TESTS - FAILED - DISABLED ))
if [ "$PASSED" -lt 0 ]; then PASSED=0; fi

# A nonzero exit with a clean-looking report (e.g. a crash AFTER the XML was written, or a
# signal) is inconsistent -- stay honest rather than silently reporting green.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then
  echo "FAIL: GLTFSDK.Test exited $rc despite the XML report showing 0 failures -- treating as a failure" >&2
  FAILED=1
  PASSED=$(( PASSED > 0 ? PASSED - 1 : 0 ))
fi

echo "=== results: $TESTS test cases, $PASSED passed, $FAILED failed, $DISABLED disabled ==="
emit_ctrf "gltfsdk-gtest" "$PASSED" "$FAILED" "$DISABLED"
