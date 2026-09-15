#!/bin/bash
set -euo pipefail

# Use an R install matching the compiler/sanitizers in CFLAGS and LDFLAGS.
eval_repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
eval_r=${R_BIN:-R}
eval_r_home=$("$eval_r" RHOME)
eval_build=$(mktemp -d "${TMPDIR:-/tmp}/r-eval-check.XXXXXX")
trap 'rm -rf "$eval_build"' EXIT

# Intentional word splitting for compiler and R-config flag lists, matching
# the convention used by ossfuzz.sh.
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Wno-unused-function \
    $("$eval_r" CMD config --cppflags) \
    "$eval_repo/tests/eval.c" \
    $("$eval_r" CMD config --ldflags) ${LDFLAGS:-} \
    -o "$eval_build/check-eval"

R_HOME="$eval_r_home" R_MAX_VSIZE=64Mb \
    LD_LIBRARY_PATH="$eval_r_home/lib:${LD_LIBRARY_PATH:-}" \
    "$eval_build/check-eval"
