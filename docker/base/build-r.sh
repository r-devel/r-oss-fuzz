#!/bin/bash -eu
#
# Build an instrumented R into the base image.
#
# OSS-Fuzz normally derives the final compiler flags in its `compile` script
# (infra/base-images/base-builder/compile) before invoking a project's
# build.sh.  Here R is built directly from a Dockerfile RUN step, so that
# derivation is replicated: the sanitizer flags for $SANITIZER plus the
# coverage instrumentation flags are appended to the image's base flags.
#
# Getting this wrong is silent and costly -- an R built without
# $COVERAGE_FLAGS still works, but libFuzzer sees no coverage from inside R,
# which is the entire point.  ossfuzz.sh's own configure invocation is reused
# (via R_BUILD_ONLY) so the prebuilt R is configured identically to the R that
# the OSS-Fuzz build produces.

FLAGS_VAR="SANITIZER_FLAGS_${SANITIZER}"
SANITIZER_FLAGS="${!FLAGS_VAR-}"
if [ -z "$SANITIZER_FLAGS" ]; then
    echo "build-r.sh: no flags known for SANITIZER=$SANITIZER" >&2
    exit 1
fi

export CFLAGS="$CFLAGS $SANITIZER_FLAGS $COVERAGE_FLAGS"
export CXXFLAGS="$CXXFLAGS $SANITIZER_FLAGS $COVERAGE_FLAGS"

export R_BUILD_ONLY=1
export R_PREFIX="${R_PREFIX:-/opt/r-prebuilt}"

/opt/ossfuzz.sh

# Stamp the tree with what it was built for.  A prebuilt R is only valid for
# the sanitizer/engine it was instrumented with; .clusterfuzzlite/build.sh
# refuses to use a mismatched one rather than silently producing a build with
# no coverage feedback.
cat > "$R_PREFIX/.fuzz-build-info" <<EOF
sanitizer=$SANITIZER
engine=$FUZZING_ENGINE
EOF
