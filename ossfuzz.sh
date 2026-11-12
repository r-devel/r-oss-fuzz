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

# libdeflate and libzstd are built from source here rather than installed
# from apt (see the "Dependencies built from source" step below).  Pinned to
# release tags so builds are reproducible; bump deliberately.  (Not named
# ZSTD_VERSION: zstd's Makefile reads that from the environment.)
LIBDEFLATE_VERSION="${LIBDEFLATE_VERSION:-1.26}"
LIBZSTD_VERSION="${LIBZSTD_VERSION:-1.5.7}"

# Where R gets installed.  Two optional knobs let the expensive R build be
# hoisted out of the per-run build, which is what the ClusterFuzzLite setup
# does (see docker/base/): a base image runs this script with $R_BUILD_ONLY
# to bake an instrumented R into the image, and each CI run then re-runs it
# with $R_PREBUILT pointing at that tree, so only the harnesses compile.
#
#   R_PREBUILT=<dir>   use an already-installed R at <dir>, skip the R build
#   R_BUILD_ONLY=1     build and install R, then stop (no harnesses, no $OUT)
#
# Two more serve the CI checks on patches/ (.github/workflows/patches-apply.yml
# and the pull-request runs of base-image.yml):
#
#   R_PATCH_STRICT=1   a patch (patches/ or instrumentation/) that does not
#                      apply, or is already applied, fails the build instead
#                      of being reported and skipped
#   R_PATCH_ONLY=1     apply the patches, then stop before configuring R
#
# All four are unset in the OSS-Fuzz build, which builds R from source as usual.
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
    # Local patches and instrumentation
    ####################################################################
    # Two directories of patches are applied to the R source, in filename
    # order within each (hence the numeric prefixes -- one patch may
    # depend on an earlier one), patches/ first:
    #
    #   patches/          fixes for defects in R that have not landed yet.
    #                     Temporary by nature: delete each one once the
    #                     fix is in trunk.
    #   instrumentation/  changes that make R easier to fuzz but fix
    #                     nothing -- poll intervals, limits, hooks.
    #                     Permanent, never for upstream, and may assume
    #                     the fixes above are in place.
    #
    # The fixes are not cosmetic.  Fuzzing an R with a known crash is
    # worse than it sounds: libFuzzer replays the entire stored corpus at
    # startup, so a single crashing input stops a target from fuzzing at
    # all, and no amount of CI configuration changes that.  Patching the
    # crash out restores forward progress until the real fix lands.
    #
    # A patch that no longer applies is reported but does NOT fail the
    # build (unless $R_PATCH_STRICT asks for that, which only the CI
    # checks do).  R trunk moves daily and one stale patch should not
    # take down every target.  Two failure modes are worth telling apart
    # in the log:
    #
    #   "already applied"  the fix landed upstream -- delete the patch
    #                      (for instrumentation/ this cannot legitimately
    #                      happen, and is reported as such)
    #   "does not apply"   context drifted -- the bug is probably still
    #                      live, so the patch needs rebasing
    apply_patch_dir() {
        local dir="$1" kind="$2"
        [ -d "$dir" ] || return 0

        local n_applied=0 n_already=0 n_failed=0 p name
        for p in "$dir"/*.patch; do
            [ -e "$p" ] || continue
            name=$(basename "$p")
            if patch -p1 --dry-run --force --silent < "$p" >/dev/null 2>&1; then
                patch -p1 --force --silent < "$p" >/dev/null
                echo "ossfuzz.sh: $kind $name: applied"
                n_applied=$((n_applied + 1))
            elif patch -p1 -R --dry-run --force --silent < "$p" >/dev/null 2>&1; then
                if [ "$kind" = patch ]; then
                    echo "ossfuzz.sh: $kind $name: ALREADY APPLIED -- fixed upstream? delete it" >&2
                else
                    echo "ossfuzz.sh: $kind $name: ALREADY APPLIED -- did trunk adopt it? check" >&2
                fi
                n_already=$((n_already + 1))
            else
                echo "ossfuzz.sh: $kind $name: DOES NOT APPLY -- skipping, needs rebasing" >&2
                n_failed=$((n_failed + 1))
            fi
        done
        echo "ossfuzz.sh: $(basename "$dir")/: $n_applied applied, $n_already already applied, $n_failed failed"

        # The CI checks want the opposite of the tolerance above: a patch
        # that no longer applies, or has landed upstream, must fail there
        # so it gets rebased or deleted before it reaches a real build.
        if [ -n "${R_PATCH_STRICT:-}" ] && [ $((n_already + n_failed)) -gt 0 ]; then
            echo "ossfuzz.sh: R_PATCH_STRICT set -- failing on the $((n_already + n_failed)) $kind(es) above" >&2
            exit 1
        fi
    }

    apply_patch_dir "$REPO/patches" patch
    apply_patch_dir "$REPO/instrumentation" instrumentation

    if [ -n "${R_PATCH_ONLY:-}" ]; then
        echo "ossfuzz.sh: R_PATCH_ONLY set -- patches and instrumentation applied, stopping before the R build"
        exit 0
    fi

    ####################################################################
    # Dependencies built from source
    ####################################################################
    # R's configure uses libdeflate for memCompress()/memDecompress() and
    # for lazy-load databases whenever the headers and library are found,
    # which is how CRAN's macOS and Windows builds are configured.  The
    # OSS-Fuzz image has no libdeflate, so without this step R silently
    # takes its zlib fallback and the libdeflate branches of R's own code
    # are never fuzzed.
    #
    # Built here, rather than apt-installed in the OSS-Fuzz Dockerfile,
    # for three reasons: the fuzzers run in a different image
    # (base-runner) that has no libdeflate.so, and a static library needs
    # nothing shipped alongside libR.so; the library gets the same
    # sanitizer and coverage instrumentation as R; and it keeps the
    # project definition in google/oss-fuzz untouched.
    LIBDEFLATE_PREFIX="$WORK/libdeflate"
    if [ ! -f "$LIBDEFLATE_PREFIX/lib/libdeflate.a" ]; then
        rm -rf "$WORK/libdeflate-src"
        git -c advice.detachedHead=false clone -q --depth 1 \
            --branch "v$LIBDEFLATE_VERSION" \
            https://github.com/ebiggers/libdeflate.git "$WORK/libdeflate-src"
        # No CMAKE_BUILD_TYPE: the only flags are $CFLAGS, so the library
        # is instrumented exactly like R.  Static library only; the
        # gzip program and tests are not needed.  PIC, because the
        # archive is linked into the shared libR.so.
        cmake -S "$WORK/libdeflate-src" -B "$WORK/libdeflate-src/build" \
            -DCMAKE_C_COMPILER="$CC" \
            -DCMAKE_C_FLAGS="$CFLAGS -fno-omit-frame-pointer" \
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
            -DCMAKE_INSTALL_PREFIX="$LIBDEFLATE_PREFIX" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
            -DLIBDEFLATE_BUILD_GZIP=OFF \
            -DLIBDEFLATE_BUILD_TESTS=OFF \
            > /dev/null
        cmake --build "$WORK/libdeflate-src/build" -j"$(nproc)" > /dev/null
        cmake --install "$WORK/libdeflate-src/build" > /dev/null
    fi
    echo "ossfuzz.sh: libdeflate $LIBDEFLATE_VERSION (static) at $LIBDEFLATE_PREFIX"

    # libzstd (zstdfile(), memCompress(type = "zstd"), zstd-compressed
    # save files) is required by R's configure as of R 4.7.0, and the
    # OSS-Fuzz image has none.  Built from source for the same reasons
    # as libdeflate.
    LIBZSTD_PREFIX="$WORK/libzstd"
    if [ ! -f "$LIBZSTD_PREFIX/lib/libzstd.a" ]; then
        rm -rf "$WORK/libzstd-src"
        git -c advice.detachedHead=false clone -q --depth 1 \
            --branch "v$LIBZSTD_VERSION" \
            https://github.com/facebook/zstd.git "$WORK/libzstd-src"
        # zstd's Makefile rather than its CMake build, which forces
        # CMAKE_BUILD_TYPE=Release: CFLAGS given on the command line
        # replace the Makefile's own, so again only $CFLAGS apply.  PIC
        # for libR.so, as above.  ZSTD_NO_ASM drops the x86-64 assembly
        # Huffman decoder, which ASAN and coverage cannot see into, in
        # favour of the C one.  The static library is single-threaded,
        # which is all R uses.
        make -C "$WORK/libzstd-src/lib" -j"$(nproc)" libzstd.a \
            CC="$CC" \
            CFLAGS="$CFLAGS -fno-omit-frame-pointer -fPIC" \
            ZSTD_NO_ASM=1 \
            > /dev/null
        make -C "$WORK/libzstd-src/lib" install-static install-includes \
            PREFIX="$LIBZSTD_PREFIX" \
            > /dev/null
    fi
    echo "ossfuzz.sh: libzstd $LIBZSTD_VERSION (static) at $LIBZSTD_PREFIX"

    # Fuzz Introspector's static analysis is an LTO pass that runs as each
    # fuzzer is linked, and sees only the code linked into that binary.
    # Against a shared libR.so it sees the harness and nothing of R, so the
    # introspector build makes a static libR.a instead and links it into
    # every harness (step 3).  All other builds keep libR.so: one shared
    # copy of R in $OUT rather than one per target.
    if [ "${SANITIZER:-}" = introspector ]; then
        R_LIBRARY_FLAG=--enable-R-static-lib
    else
        R_LIBRARY_FLAG=--enable-R-shlib
    fi

    # Don't pass sanitizer flags to Fortran -- gfortran doesn't understand
    # them.  The C/C++ compiler links the sanitizer runtime.  configure
    # finds the static libdeflate and libzstd through CPPFLAGS/LDFLAGS and
    # links them into libR, so neither ships to the runner.
    ./configure \
        CC="$CC" \
        CXX="$CXX" \
        CFLAGS="$CFLAGS -fno-omit-frame-pointer" \
        CXXFLAGS="$CXXFLAGS -fno-omit-frame-pointer" \
        CPPFLAGS="-I$LIBDEFLATE_PREFIX/include -I$LIBZSTD_PREFIX/include" \
        FFLAGS="" \
        FCFLAGS="" \
        LDFLAGS="$CFLAGS -lgfortran -L$LIBDEFLATE_PREFIX/lib -L$LIBZSTD_PREFIX/lib" \
        --prefix="$R_PREFIX" \
        "$R_LIBRARY_FLAG" \
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

# No target should reach the network, and a fuzzer that did would produce
# nondeterministic coverage, DNS-timeout "hangs" and outbound traffic to
# arbitrary hosts.  Every network entry point (url(), download.file(),
# socketConnection(), curlGetHeaders(), the internal HTTP server) lives in
# the loadable internet module, so dropping it from the bundled R_HOME turns
# all of them into an ordinary R error ("unable to load shared object").
#
# The sockets target is the one exception: it drives socket connections
# over the loopback interface, where instrumentation/0006 keeps R's server
# sockets.  So the module is not deleted but moved to
# where R does not look, and that harness alone points R at it
# (sockets_load_module in harnesses/sockets.c).
mkdir -p "$OUT/r-install/lib/R/fuzz-internet/modules"
mv "$OUT/r-install/lib/R/modules/internet.so" \
    "$OUT/r-install/lib/R/fuzz-internet/modules/internet.so"

########################################################################
# 2. Stage seed corpora
########################################################################
# Static seeds live in this repo under seeds/<target>/.  Seeds that require
# actual binary encodings are generated below using the R we just built, and
# staged into the same seeds/<target>/ layout so the packaging loop treats
# every target uniformly.
SEED_STAGE="$WORK/seeds"
rm -rf "$SEED_STAGE"
mkdir -p "$SEED_STAGE"
if [ -d "$REPO/seeds" ]; then
    cp -a "$REPO/seeds/." "$SEED_STAGE/"
fi

export R_HOME
export LD_LIBRARY_PATH="$R_LIB_DIR:${LD_LIBRARY_PATH:-}"

# Generate typed binary streams for the io target. Keeping this here rather
# than spelling bytes as text in seeds/io ensures the corpus contains real
# NUL terminators and platform-independent numeric encodings.
mkdir -p "$SEED_STAGE/io"
( cd "$SEED_STAGE/io" && \
  "$R_PREFIX/bin/Rscript" --vanilla -e '
    seed <- function(name, selector, payload)
      writeBin(c(charToRaw(selector), payload), name)
    seed("raw.bin",       "0", charToRaw("abcdefghijklmno"))
    seed("integer8.bin",  "1",
         writeBin(c(0L, 1L, 127L, -128L, -1L), raw(),
                  size = 1, endian = "big"))
    seed("integer32.bin", "2",
         writeBin(c(0L, 1L, -1L, .Machine$integer.max), raw(),
                  size = 4, endian = "little"))
    seed("real32.bin",    "3",
         writeBin(c(0, 1, -1, Inf, NaN), raw(), size = 4, endian = "big"))
    seed("real64.bin",    "4",
         writeBin(c(0, 1, -1, Inf, NaN), raw(), size = 8, endian = "little"))
    seed("complex.bin",   "5",
         writeBin(c(0+0i, 1-2i, Inf+NaN*1i), raw(),
                  size = 16, endian = "big"))
    seed("character.bin", "6", writeBin(c("first", "second"), raw()))
    seed("logical.bin",   "7",
         writeBin(c(FALSE, TRUE, NA), raw(), size = 4, endian = "little"))
  ' 2>/dev/null )

# Generate minimal valid RDS files for the unserialize target.  The harness
# passes bytes straight to unserialize(), which expects the raw serialization
# stream, so the seeds must be written with compress = FALSE (saveRDS
# gzip-compresses by default, and unserialize() rejects gzip data outright).
# Emit binary v3, binary v2, and ASCII variants to seed those format branches.
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
#
# DEFERRED_TARGETS holds names back from the OSS-Fuzz build.  The initial
# OSS-Fuzz scope is deliberately narrow: every finding lands in the public
# tracker with a 90-day disclosure clock, and the regex targets mostly
# surface bugs in the bundled TRE engine, whose dormant upstream means
# each fix must be hand-patched into R.  That triage load should be opted
# into deliberately, once the initial targets have settled -- promoting a
# target is just deleting its name here.  rd waits on two R bugs its first
# runs hit that have no carried fix yet: the iconv() leak of Bugzilla 19134
# (reached through \encoding{}) and parse_Rd() never returning on an
# unterminated \Sexpr.
# ClusterFuzzLite is not so constrained (findings stay within this
# repository's CI), so .clusterfuzzlite/build.sh clears the list and keeps
# fuzzing everything.
DEFERRED_TARGETS="${DEFERRED_TARGETS-agrep grep rd}"

# How each harness links R.  Normally that is the bundled libR.so.  The
# introspector build (see step 1) links the whole static libR.a instead,
# using R's own recipe for embedding a static R: --whole-archive, symbols
# exported for the packages R dlopen()s, plus BLAS, Fortran and system
# libraries.  The recipe quotes the libR.a path, and $WORK has no spaces.
if [ "${SANITIZER:-}" = introspector ]; then
    R_LINK_FLAGS=$("$R_PREFIX/bin/R" CMD config --ldflags | tr -d '"')
    # A bitcode archive the size of R; nothing in $OUT needs it.
    rm -f "$OUT/r-install/lib/R/lib/libR.a"
else
    R_LINK_FLAGS="-L$R_LIB_DIR -lR"
fi

for src in "$REPO"/harnesses/*.c; do
    name=$(basename "$src" .c)

    case " $DEFERRED_TARGETS " in
        *" $name "*)
            echo "ossfuzz.sh: target $name: deferred -- skipping"
            continue
            ;;
    esac

    $CC $CFLAGS -fno-omit-frame-pointer \
        -I"$R_INCLUDE" \
        -c "$src" -o "$WORK/${name}.o"

    # Link with $CXX so the sanitizer C++ runtime is pulled in.  rpath is
    # set to $ORIGIN so the binary finds the bundled libR.so (or, with a
    # static libR.a, libRblas.so) under $OUT.
    $CXX $CXXFLAGS -fno-omit-frame-pointer \
        "$WORK/${name}.o" \
        -o "$OUT/$name" \
        $LIB_FUZZING_ENGINE \
        $R_LINK_FLAGS \
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
