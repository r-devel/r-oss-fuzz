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

########################################################################
# 1. Build and install R
########################################################################
cd "$R_SOURCE"

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
    --prefix="$WORK/r-install" \
    --enable-R-shlib \
    --with-x=no \
    --disable-java \
    --enable-strict-barrier \
    --without-recommended-packages

make -j"$(nproc)"
make install

R_HOME="$WORK/r-install/lib/R"
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

# Bundle R_HOME into $OUT so the runner can find it: Rf_initEmbeddedR needs
# it for base package data, encodings, etc.
rm -rf "$OUT/r-install"
cp -a "$WORK/r-install" "$OUT/r-install"

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

# Generate minimal valid RDS files for the unserialize target.
export R_HOME
export LD_LIBRARY_PATH="$R_LIB_DIR:${LD_LIBRARY_PATH:-}"
mkdir -p "$SEED_STAGE/unserialize"
( cd "$SEED_STAGE/unserialize" && \
  "$WORK/r-install/bin/Rscript" --vanilla -e '
    saveRDS(NULL, "null.rds")
    saveRDS(1L, "integer.rds")
    saveRDS(3.14, "real.rds")
    saveRDS("hello", "string.rds")
    saveRDS(TRUE, "logical.rds")
    saveRDS(1:10, "intvec.rds")
    saveRDS(list(a=1, b="x"), "list.rds")
    saveRDS(as.raw(0:255), "raw.rds")
    saveRDS(1+2i, "complex.rds")
    saveRDS(data.frame(x=1:3), "dataframe.rds")
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
