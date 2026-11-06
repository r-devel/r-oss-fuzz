#!/bin/bash
set -euo pipefail

# Use an R install matching the compiler/sanitizers in CFLAGS and LDFLAGS.
dt_repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dt_r=${R_BIN:-R}
dt_r_home=$("$dt_r" RHOME)
dt_build=$(mktemp -d "${TMPDIR:-/tmp}/r-datetime-check.XXXXXX")
trap 'rm -rf "$dt_build"' EXIT

# Intentional word splitting for compiler and R-config flag lists, matching
# the convention used by ossfuzz.sh.
${CC:-cc} ${CFLAGS:-} -std=gnu11 -Wall -Wextra -Wno-unused-function \
    $("$dt_r" CMD config --cppflags) \
    "$dt_repo/tests/datetime.c" \
    $("$dt_r" CMD config --ldflags) ${LDFLAGS:-} \
    -o "$dt_build/check-datetime"

R_HOME="$dt_r_home" \
    LD_LIBRARY_PATH="$dt_r_home/lib:${LD_LIBRARY_PATH:-}" \
    "$dt_build/check-datetime"
