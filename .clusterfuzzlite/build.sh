#!/bin/bash -eu
#
# ClusterFuzzLite build script.
#
# R is already compiled into the base image (see docker/base/), so this only
# has to build the harnesses -- which is the difference between a CI run that
# takes minutes and one that takes over an hour.

R_PREBUILT="${R_PREBUILT:-/opt/r-prebuilt}"
INFO="$R_PREBUILT/.fuzz-build-info"

if [ ! -f "$INFO" ]; then
    echo "build.sh: $INFO is missing -- the base image is malformed or" >&2
    echo "          predates the build stamp.  Rebuild it." >&2
    exit 1
fi

# The prebuilt R is instrumented for exactly one sanitizer/engine pair.  Built
# against any other combination, the harnesses would still compile, link, and
# run -- while reporting no coverage at all from inside R, which is the entire
# point of the exercise.  That failure is invisible at runtime, so refuse it
# here instead.
built_sanitizer=$(sed -n 's/^sanitizer=//p' "$INFO")
built_engine=$(sed -n 's/^engine=//p' "$INFO")

if [ "$built_sanitizer" != "$SANITIZER" ] || [ "$built_engine" != "$FUZZING_ENGINE" ]; then
    echo "build.sh: base image contains R built for" >&2
    echo "            sanitizer=$built_sanitizer engine=$built_engine" >&2
    echo "          but this build requests" >&2
    echo "            sanitizer=$SANITIZER engine=$FUZZING_ENGINE" >&2
    echo "          Rebuild the base image for that combination first." >&2
    exit 1
fi

export R_PREBUILT
exec "$SRC/r-oss-fuzz/ossfuzz.sh"
