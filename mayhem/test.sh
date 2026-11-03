#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# Functional oracle: the PREVAIL verifier CLI (built by build.sh with NORMAL flags, no sanitizers)
# is run over eBPF samples shipped in the external/ebpf-verifier submodule, and its verdict AND
# its first diagnostic must match the known answer. A neutered/no-op program prints nothing and
# fails every case.
PREVAIL="$SRC/mayhem/build/prevail"
[ -x "$PREVAIL" ] || { echo "missing $PREVAIL: mayhem/build.sh must build it" >&2; emit_ctrf "prevail-cli" 0 1 0; exit 1; }
cd "$SRC/external/ebpf-verifier"

passed=0; failed=0
# check <name> <expected-exit> <expected-first-lines> <prevail args...>
check() {
  local name="$1" want_rc="$2" want_out="$3"; shift 3
  local out rc
  out=$("$PREVAIL" "$@" 2>&1 | sed -n '1,2p'); rc=${PIPESTATUS[0]}
  rc=$("$PREVAIL" -q "$@" >/dev/null 2>&1; echo $?)
  if [ "$rc" = "$want_rc" ] && [ "$out" = "$want_out" ]; then
    passed=$((passed+1)); echo "ok   $name"
  else
    failed=$((failed+1)); echo "FAIL $name: rc=$rc (want $want_rc)"; echo "--- got:"; echo "$out"; echo "--- want:"; echo "$want_out"
  fi
}
nl=$'\n'
B=ebpf-samples/build
check badhelpercall   1 "FAIL: .text/func${nl}3: Upper bound must be at most total_stack_size (valid_access(r1.offset, width=r2) for write)" $B/badhelpercall.o .text
check bounded_loop    0 "PASS: test/test_bounded_loop" $B/bounded_loop.o test
check bounded_loop_termination 1 "FAIL: test/test_bounded_loop${nl}7 (counter): Loop counter is too large (pc[7] < 100000)" --termination $B/bounded_loop.o test
check divzero_allowed 0 "PASS: test/test_divzero" $B/divzero.o test
check divzero_strict  1 "FAIL: test/test_divzero${nl}12: Possible division by zero (r1 != 0)" --no-division-by-zero $B/divzero.o test
check badmapptr       1 "FAIL: test/test_repro${nl}4: Invalid type (r1.type in {number, ctx, stack, packet, shared})" $B/badmapptr.o test
check byteswap        0 "PASS: .text/func" $B/byteswap.o .text
check exposeptr       1 "FAIL: .text/func${nl}10: Illegal map update with a non-numerical value [4088-4096) (within(r3:value_size(r1)))" $B/exposeptr.o .text
check dependent_read  1 "FAIL: xdp/dependent_read${nl}10: Upper bound must be at most packet_size (valid_access(r1.offset, width=4) for read)" $B/dependent_read.o xdp
check ctxoffset       1 "FAIL: sockops/func${nl}8: Nonzero context offset (r1.ctx_offset == 0)" $B/ctxoffset.o sockops

emit_ctrf "prevail-cli" "$passed" "$failed" 0
