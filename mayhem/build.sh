#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# eBPF for Windows itself is Windows-only (MSBuild, WDK, usersim); none of its in-tree libFuzzer
# harnesses build on Linux. The portable, fuzzable core in this tree is the PREVAIL eBPF verifier
# vendored as the external/ebpf-verifier submodule, which is what this layer builds and fuzzes.
PV="$SRC/external/ebpf-verifier"
[ -f "$PV/src/ebpf_verifier.hpp" ] && [ -f "$PV/external/libbtf/libbtf/btf_parse.cpp" ] \
  || { echo "external/ebpf-verifier submodule (recursive) is missing" >&2; exit 1; }

BUILD="$SRC/mayhem/build"
mkdir -p "$BUILD"

# System headers/libs come from apt (installed by mayhem/Dockerfile), never the network:
# Boost (headers), Microsoft GSL. CLI11, elfio, libbtf, bpf_conformance are in the submodule.
INCS="-I$PV/src -I$PV/external -I$PV/external/CLI11 -I$PV/external/bpf_conformance/external/elfio \
 -I$PV/external/bpf_conformance/lib/include -I$PV/external/libbtf -I$PV/external/libbtf/libbtf"
DEFS="-DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8"
STD="-std=c++23"

# Library sources: PREVAIL core (same list as external/ebpf-verifier/CMakeLists.txt) + libbtf.
LIB_SRCS=$(cd "$PV" && ls \
  src/cfg/wto.cpp src/crab/array_domain.cpp src/crab/bitset_domain.cpp src/crab/ebpf_checker.cpp \
  src/crab/ebpf_domain.cpp src/crab/ebpf_transformer.cpp src/crab/finite_domain.cpp \
  src/crab/interval.cpp src/crab/region_semantics.cpp src/crab/splitdbm/split_dbm.cpp \
  src/crab/type_domain.cpp src/crab/type_to_num.cpp src/crab/var_registry.cpp src/crab/zone_domain.cpp \
  src/crab_utils/debug.cpp src/crab/extrapolator.cpp src/fwd_analyzer.cpp src/io/elf_core_reloc.cpp \
  src/io/elf_extern_resolve.cpp src/io/elf_loader.cpp src/io/elf_map_parser.cpp src/io/elf_reader.cpp \
  src/ir/assertions.cpp src/ir/call_resolver.cpp src/ir/cfg_builder.cpp src/ir/unmarshal.cpp \
  src/linux/gpl/spec_prototypes.cpp src/linux/kfunc.cpp src/linux/linux_platform.cpp src/printing.cpp \
  src/result.cpp src/string_constraints.cpp \
  external/libbtf/libbtf/btf_json.cpp external/libbtf/libbtf/btf_map.cpp external/libbtf/libbtf/btf_parse.cpp \
  external/libbtf/libbtf/btf_type_data.cpp external/libbtf/libbtf/btf_write.cpp)

# build_lib <outdir> <flags...>: compile every library source into <outdir>/*.o (incremental, parallel).
build_lib() {
  local out="$1"; shift
  mkdir -p "$out"
  local flags="$*"
  for s in $LIB_SRCS; do
    local o="$out/$(echo "$s" | tr '/' '_').o"
    if [ ! -f "$o" ] || [ "$PV/$s" -nt "$o" ]; then echo "$s|$o"; fi
  done | xargs -P "$MAYHEM_JOBS" -I{} bash -c '
      IFS="|" read -r s o <<< "{}"
      '"$CXX"' '"$STD"' '"$INCS"' '"$DEFS"' '"$flags"' -c "'"$PV"'/$s" -o "$o"'
}

# 1) The fuzz build: sanitized, DWARF<=3, coverage-instrumented (fuzzer-no-link: every library object, not
#    just the harness, must carry libFuzzer coverage), leak detection compiled out (docs/rules/c.md).
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
build_lib "$BUILD/fuzz" $FUZZ_FLAGS
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$BUILD/fuzz/lsan_off.o"
$CXX $STD $INCS $DEFS $FUZZ_FLAGS -c "$SRC/mayhem/prevail_elf_fuzzer.cpp" -o "$BUILD/fuzz/prevail_elf_fuzzer.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/fuzz/standalone_main.o"

LIB_OBJS=$(ls "$BUILD"/fuzz/src_*.o "$BUILD"/fuzz/external_*.o)
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$BUILD/fuzz/prevail_elf_fuzzer.o" "$BUILD/fuzz/lsan_off.o" \
  $LIB_OBJS -o "$SRC/prevail_elf_fuzzer"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$BUILD/fuzz/prevail_elf_fuzzer.o" "$BUILD/fuzz/standalone_main.o" \
  "$BUILD/fuzz/lsan_off.o" $LIB_OBJS -o "$SRC/prevail_elf_fuzzer-standalone"

# 2) The test build: the same verifier with the project's NORMAL flags (no sanitizers), as the
#    `prevail` CLI that mayhem/test.sh drives against samples with known verdicts.
TEST_FLAGS="-O2 $COVERAGE_FLAGS"
build_lib "$BUILD/test" $TEST_FLAGS
$CXX $STD $INCS $DEFS $TEST_FLAGS -DPREVAIL_VERSION_STRING='"mayhem"' -c "$PV/src/main.cpp" -o "$BUILD/test/main.o"
$CXX $TEST_FLAGS "$BUILD/test/main.o" $(ls "$BUILD"/test/src_*.o "$BUILD"/test/external_*.o) -ldl -o "$BUILD/prevail"
