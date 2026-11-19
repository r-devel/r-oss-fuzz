#!/bin/bash
# Build one harness on macOS against a static ASAN + libFuzzer R, for
# fast local edit/build/run loops (an OSS-Fuzz build takes an hour).
#
# Usage:
#   scripts/build-local-macos.sh <name> [extra compiler flags...]
#
# Environment:
#   RB=<dir>         the static R build tree (required)
#   OUT_SUFFIX=<s>   name the binary out/<name><s> (e.g. -known)
#
# README.md ("Building natively on macOS") gives the configure line for
# that build: --enable-R-static-lib and CC='<clang>
# -fsanitize=address,fuzzer-no-link', using Homebrew LLVM, because
# Apple clang ships no libFuzzer runtime.  Run the result with R_HOME
# pointing at the same tree (common.h derives R_HOME from /proc/self/exe,
# which macOS lacks) and R's lib directory on the fallback library path,
# which the R front-end script would otherwise set: package .so files
# such as stats.so name libRlapack.dylib without a path.
#
#   R_HOME=$RB DYLD_FALLBACK_LIBRARY_PATH=$RB/lib out/<name> [libFuzzer flags] [corpus dirs]
#
# The link line is spelled out because `R CMD config --ldflags` is
# incomplete for a static libR on macOS.
set -euo pipefail

name=${1:?usage: build-local-macos.sh <name> [extra compiler flags...]}
shift

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RB="${RB:?set RB to the static R build tree}"
CC="${CC:-/opt/homebrew/opt/llvm/bin/clang}"
src="$REPO/harnesses/$name.c"
out="$REPO/out/$name${OUT_SUFFIX:-}"

if [ ! -f "$src" ]; then
    echo "build-local-macos.sh: no harness $src" >&2
    exit 1
fi
if [ ! -f "$RB/lib/libR.a" ]; then
    echo "build-local-macos.sh: no static libR at $RB/lib/libR.a" >&2
    exit 1
fi

flibs=$(sed -n 's/^FLIBS *= *//p' "$RB/etc/Makeconf")
mkdir -p "$REPO/out"

# shellcheck disable=SC2086  # flibs is a word list
"$CC" -fsanitize=address,fuzzer -g -O1 -fno-omit-frame-pointer \
    -I"$RB/include" "$@" "$src" -o "$out" \
    -Wl,-force_load,"$RB/lib/libR.a" -Wl,-export_dynamic \
    -L"$RB/lib" -lRblas $flibs -lreadline \
    -L/opt/homebrew/lib -lintl -lpcre2-8 -ldeflate -lzstd -llzma -lbz2 -lz \
    -licucore -ldl -lm -liconv -Wl,-framework,CoreFoundation \
    -Wl,-headerpad_max_install_names

# libRblas carries a bare install name; point the binary at the real file.
# The path replacing it is longer, and with a deep $RB the default header
# padding cannot hold it ("larger updated load commands do not fit"),
# hence -headerpad_max_install_names above.
install_name_tool -change libRblas.dylib "$RB/lib/libRblas.dylib" "$out"

echo "build-local-macos.sh: built $out against $RB"
