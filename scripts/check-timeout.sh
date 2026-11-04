#!/bin/bash
set -euo pipefail

# Use an R install matching the compiler/sanitizers in CFLAGS and LDFLAGS.
check_repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
check_r=${R_BIN:-R}
check_r_home=$("$check_r" RHOME)
check_build=$(mktemp -d "${TMPDIR:-/tmp}/r-timeout-check.XXXXXX")
trap 'rm -rf "$check_build"' EXIT

# Intentional word splitting for compiler and R-config flag lists, matching
# the convention used by ossfuzz.sh.
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Wno-unused-function \
    $("$check_r" CMD config --cppflags) \
    "$check_repo/tests/timeout.c" \
    $("$check_r" CMD config --ldflags) ${LDFLAGS:-} \
    -o "$check_build/check-timeout"

R_HOME="$check_r_home" \
    LD_LIBRARY_PATH="$check_r_home/lib:${LD_LIBRARY_PATH:-}" \
    "$check_build/check-timeout"
