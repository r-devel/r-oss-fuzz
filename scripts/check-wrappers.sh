#!/bin/bash
# Run each target's seeds once with R's errors printed, and fail if any
# call names a function R cannot find.  A slot whose closure cannot see
# the package it calls into fails on every input, and fuzz_eval_silent
# hides that: colors and readtable fuzzed nothing for weeks this way
# (see fuzz_make_wrapper in harnesses/common.h).
#
# Usage: scripts/check-wrappers.sh [target...]
#
# The default is every target except eval, whose inputs are R code that
# may call any name.  Needs a clang with libFuzzer as CC (Apple's clang
# has none) and an R install, R_BIN (default R); the harnesses link
# against that R and run with its R_HOME.  Extra link flags go in
# LDFLAGS.  Some seeds hang or crash an R without this repo's patches/
# (encoding's do in R 4.6.1); libFuzzer stops at the first one, and the
# target is reported INCOMPLETE rather than checked.
set -euo pipefail

wrappers_repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
wrappers_r=${R_BIN:-R}
wrappers_r_home=$("$wrappers_r" RHOME)
wrappers_build=$(mktemp -d "${TMPDIR:-/tmp}/r-wrappers-check.XXXXXX")
trap 'rm -rf "$wrappers_build"' EXIT

if [ $# -eq 0 ]; then
    for src in "$wrappers_repo"/harnesses/*.c; do
        name=$(basename "$src" .c)
        [ "$name" = eval ] || set -- "$@" "$name"
    done
fi

wrappers_status=0
for name in "$@"; do
    # Intentional word splitting for compiler and R-config flag lists,
    # matching the convention used by ossfuzz.sh.
    ${CC:-clang} ${CFLAGS:-} -fsanitize=fuzzer -DFUZZ_PRINT_ERRORS \
        $("$wrappers_r" CMD config --cppflags) \
        "$wrappers_repo/harnesses/$name.c" \
        $("$wrappers_r" CMD config --ldflags) ${LDFLAGS:-} \
        -o "$wrappers_build/$name"

    # A copy, so libFuzzer cannot add files to the tracked seeds.
    corpus="$wrappers_build/corpus-$name"
    mkdir -p "$corpus"
    if [ -d "$wrappers_repo/seeds/$name" ]; then
        cp "$wrappers_repo/seeds/$name/"* "$corpus/"
    fi

    log="$wrappers_build/$name.log"
    R_HOME="$wrappers_r_home" \
        LD_LIBRARY_PATH="$wrappers_r_home/lib:${LD_LIBRARY_PATH:-}" \
        DYLD_FALLBACK_LIBRARY_PATH="$wrappers_r_home/lib" \
        "$wrappers_build/$name" -runs=0 -timeout=10 \
        -artifact_prefix="$wrappers_build/" "$corpus" > "$log" 2>&1 || true

    if grep -q "could not find function" "$log"; then
        echo "check-wrappers.sh: $name: FAIL"
        grep -o 'could not find function "[^"]*"' "$log" | sort | uniq -c
        wrappers_status=1
    elif ! grep -q "INITED" "$log"; then
        echo "check-wrappers.sh: $name: INCOMPLETE, stopped before running every seed:"
        grep -m 3 -E "ERROR|ALARM|Fatal|abort" "$log" || tail -3 "$log"
        wrappers_status=1
    else
        echo "check-wrappers.sh: $name: ok"
    fi
done
exit $wrappers_status
