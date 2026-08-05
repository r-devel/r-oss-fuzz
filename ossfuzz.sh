#!/bin/bash -eu
#
# OSS-Fuzz build script for the R language fuzz targets.
#
# This repository holds the fuzz harnesses and build logic for R's
# integration into OSS-Fuzz (https://github.com/google/oss-fuzz, project
# "r").  The OSS-Fuzz project clones this repo into $SRC/r-oss-fuzz and
# delegates its build.sh to this script.
#
# Expected environment (provided by the OSS-Fuzz base-builder image):
#   $CC, $CXX, $CFLAGS, $CXXFLAGS   compiler + sanitizer flags
#   $LIB_FUZZING_ENGINE             the fuzzing engine to link against
#   $SRC, $WORK, $OUT               source / scratch / output directories
#
# The R source tree is expected at $SRC/r-source (checked out by the
# OSS-Fuzz Dockerfile).  Override with $R_SOURCE for local runs.

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
R_SOURCE="${R_SOURCE:-$SRC/r-source}"

# Where R gets installed.  Two optional knobs let the expensive R build be
# hoisted out of the per-run build, which is what the ClusterFuzzLite setup
# does (see docker/base/): a base image runs this script with $R_BUILD_ONLY
# to bake an instrumented R into the image, and each CI run then re-runs it
# with $R_PREBUILT pointing at that tree, so only the harnesses compile.
#
#   R_PREBUILT=<dir>   use an already-installed R at <dir>, skip the R build
#   R_BUILD_ONLY=1     build and install R, then stop (no harnesses, no $OUT)
#
# Both are unset in the OSS-Fuzz build, which builds R from source as usual.
R_PREFIX="${R_PREFIX:-$WORK/r-install}"

########################################################################
# 1. Build and install R
########################################################################
if [ -n "${R_PREBUILT:-}" ]; then
    echo "ossfuzz.sh: using prebuilt R at $R_PREBUILT"
    R_PREFIX="$R_PREBUILT"
    if [ ! -x "$R_PREFIX/bin/Rscript" ]; then
        echo "ossfuzz.sh: no R install found at $R_PREFIX" >&2
        exit 1
    fi
else
    cd "$R_SOURCE"

    ####################################################################
    # Local patches
    ####################################################################
    # patches/ carries fixes that have not landed in R yet, applied in
    # filename order (hence the numeric prefixes -- one patch may depend
    # on an earlier one).
    #
    # These are not cosmetic.  Fuzzing an R with a known crash is worse
    # than it sounds: libFuzzer replays the entire stored corpus at
    # startup, so a single crashing input stops a target from fuzzing at
    # all, and no amount of CI configuration changes that.  Patching the
    # crash out restores forward progress until the real fix lands.
    #
    # A patch that no longer applies is reported but does NOT fail the
    # build.  R trunk moves daily and one stale patch should not take
    # down all eight targets.  Two failure modes are worth telling apart
    # in the log:
    #
    #   "already applied"  the fix landed upstream -- delete the patch
    #   "does not apply"   context drifted -- the bug is probably still
    #                      live, so the patch needs rebasing
    if [ -d "$REPO/patches" ]; then
        n_applied=0; n_already=0; n_failed=0
        for p in "$REPO"/patches/*.patch; do
            [ -e "$p" ] || continue
            name=$(basename "$p")
            if patch -p1 --dry-run --force --silent < "$p" >/dev/null 2>&1; then
                patch -p1 --force --silent < "$p" >/dev/null
                echo "ossfuzz.sh: patch $name: applied"
                n_applied=$((n_applied + 1))
            elif patch -p1 -R --dry-run --force --silent < "$p" >/dev/null 2>&1; then
                echo "ossfuzz.sh: patch $name: ALREADY APPLIED -- fixed upstream? delete it" >&2
                n_already=$((n_already + 1))
            else
                echo "ossfuzz.sh: patch $name: DOES NOT APPLY -- skipping, needs rebasing" >&2
                n_failed=$((n_failed + 1))
            fi
        done
        echo "ossfuzz.sh: patches: $n_applied applied, $n_already already applied, $n_failed failed"
    fi

    # Don't pass sanitizer flags to Fortran -- gfortran doesn't understand
    # them.  The C/C++ compiler links the sanitizer runtime.
    ./configure \
        CC="$CC" \
        CXX="$CXX" \
        CFLAGS="$CFLAGS -fno-omit-frame-pointer" \
        CXXFLAGS="$CXXFLAGS -fno-omit-frame-pointer" \
        CPPFLAGS="" \
        FFLAGS="" \
        FCFLAGS="" \
        LDFLAGS="$CFLAGS -lgfortran" \
        --prefix="$R_PREFIX" \
        --enable-R-shlib \
        --with-x=no \
        --disable-java \
        --enable-strict-barrier \
        --without-recommended-packages

    make -j"$(nproc)"
    make install
fi

R_HOME="$R_PREFIX/lib/R"
R_INCLUDE="$R_HOME/include"
R_LIB_DIR="$R_HOME/lib"

# Copy the Fortran runtime libraries into the R lib directory.  The runner
# image (base-runner) has no gfortran, so these must ship alongside libR.so
# and be found via rpath.  Only the versioned .so files are needed at
# runtime (not the linker-script symlinks).
for lib in libgfortran.so.5 libquadmath.so.0; do
    src=$(find /usr -name "$lib" -type l -o -name "$lib" -type f 2>/dev/null | head -1)
    if [ -n "$src" ]; then
        cp "$(readlink -f "$src")" "$R_LIB_DIR/$lib"
    fi
done

# Base-image mode: R is built and staged, and there is nothing else to do.
if [ -n "${R_BUILD_ONLY:-}" ]; then
    echo "ossfuzz.sh: R_BUILD_ONLY set -- R installed at $R_PREFIX, stopping"
    exit 0
fi

# Bundle R_HOME into $OUT so the runner can find it: Rf_initEmbeddedR needs
# it for base package data, encodings, etc.
rm -rf "$OUT/r-install"
cp -a "$R_PREFIX" "$OUT/r-install"

########################################################################
# 2. Stage seed corpora
########################################################################
# Static seeds live in this repo under seeds/<target>/.  RDS seeds for the
# unserialize target are generated below using the R we just built, and
# staged into the same seeds/<target>/ layout so the packaging loop treats
# every target uniformly.
SEED_STAGE="$WORK/seeds"
rm -rf "$SEED_STAGE"
mkdir -p "$SEED_STAGE"
if [ -d "$REPO/seeds" ]; then
    cp -a "$REPO/seeds/." "$SEED_STAGE/"
fi

# Generate minimal valid RDS files for the unserialize target.  The harness
# passes bytes straight to unserialize(), which expects the raw serialization
# stream, so the seeds must be written with compress = FALSE (saveRDS
# gzip-compresses by default, and unserialize() rejects gzip data outright).
# Emit binary v3, binary v2, and ASCII variants to seed those format branches.
export R_HOME
export LD_LIBRARY_PATH="$R_LIB_DIR:${LD_LIBRARY_PATH:-}"
mkdir -p "$SEED_STAGE/unserialize"
( cd "$SEED_STAGE/unserialize" && \
  "$R_PREFIX/bin/Rscript" --vanilla -e '
    objs <- list(
      null      = NULL,
      integer   = 1L,
      real      = 3.14,
      string    = "hello",
      logical   = TRUE,
      intvec    = 1:10,
      list      = list(a = 1, b = "x"),
      raw       = as.raw(0:255),
      complex   = 1+2i,
      dataframe = data.frame(x = 1:3)
    )
    for (nm in names(objs)) {
      saveRDS(objs[[nm]], paste0(nm, ".rds"), compress = FALSE)
      saveRDS(objs[[nm]], paste0(nm, "_v2.rds"), version = 2, compress = FALSE)
      saveRDS(objs[[nm]], paste0(nm, "_ascii.rds"), ascii = TRUE, compress = FALSE)
    }
  ' 2>/dev/null ) || true

########################################################################
# 3. Compile, link, and package each fuzz target
########################################################################
# Convention: each harnesses/<name>.c is built into a target named
# <name>.  Optional sibling files, all keyed on that same name, are
# picked up automatically -- no per-target wiring:
#
#   dictionaries/<name>.dict  ->  $OUT/<name>.dict
#   options/<name>.options    ->  $OUT/<name>.options
#   seeds/<name>/             ->  $OUT/<name>_seed_corpus.zip
#
# To add a target: drop a harnesses/<name>.c (plus any of the above).
for src in "$REPO"/harnesses/*.c; do
    name=$(basename "$src" .c)

    $CC $CFLAGS -fno-omit-frame-pointer \
        -I"$R_INCLUDE" \
        -c "$src" -o "$WORK/${name}.o"

    # Link with $CXX so the sanitizer C++ runtime is pulled in.  rpath is
    # set to $ORIGIN so the binary finds the bundled libR.so under $OUT.
    $CXX $CXXFLAGS -fno-omit-frame-pointer \
        "$WORK/${name}.o" \
        -o "$OUT/$name" \
        $LIB_FUZZING_ENGINE \
        -L"$R_LIB_DIR" -lR \
        -Wl,--disable-new-dtags \
        -Wl,-rpath,\$ORIGIN/r-install/lib/R/lib \
        -Wl,-rpath-link,"$R_LIB_DIR" \
        -rdynamic \
        -lm -lpthread -ldl

    if [ -f "$REPO/dictionaries/${name}.dict" ]; then
        cp "$REPO/dictionaries/${name}.dict" "$OUT/${name}.dict"
    fi

    if [ -f "$REPO/options/${name}.options" ]; then
        cp "$REPO/options/${name}.options" "$OUT/${name}.options"
    fi

    if [ -d "$SEED_STAGE/${name}" ] && [ -n "$(ls -A "$SEED_STAGE/${name}" 2>/dev/null)" ]; then
        ( cd "$SEED_STAGE/${name}" && zip -q -j "$OUT/${name}_seed_corpus.zip" ./* )
    fi
done
