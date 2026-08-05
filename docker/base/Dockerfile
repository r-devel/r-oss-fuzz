# Base image for the ClusterFuzzLite setup: an OSS-Fuzz builder image with an
# instrumented R already compiled into /opt/r-prebuilt.
#
# Building R takes the better part of an hour, which is far too slow to repeat
# on every pull request.  This image pays that cost on a schedule; each CI run
# then only compiles the eight harnesses against the R baked in here.
#
# Build from the repository root -- the context must include ossfuzz.sh:
#
#   docker build -f docker/base/Dockerfile -t ghcr.io/r-devel/r-oss-fuzz/r-base:address .
#
# The R installed here is instrumented for one specific sanitizer/engine pair
# (address/libfuzzer by default).  Which pair is recorded in
# /opt/r-prebuilt/.fuzz-build-info, and .clusterfuzzlite/build.sh refuses to
# build against a mismatched image.
#
# Note this pins R to whatever trunk looked like when the image was built, so
# ClusterFuzzLite fuzzes a snapshot rather than live trunk.  The scheduled
# rebuild in .github/workflows/base-image.yml bounds how stale that gets.
# (OSS-Fuzz proper is unaffected: it checks out trunk on every daily build.)

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gfortran \
        libbz2-dev \
        libcurl4-openssl-dev \
        liblzma-dev \
        libpcre2-dev \
        libreadline-dev \
        subversion \
        texinfo \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# R's canonical source is SVN trunk, matching the OSS-Fuzz project definition.
RUN svn checkout --depth=infinity https://svn.r-project.org/R/trunk $SRC/r-source \
    && svnversion $SRC/r-source > /opt/r-svn-revision

# ossfuzz.sh performs the actual R build (via R_BUILD_ONLY), so the R baked in
# here is configured identically to the R that the OSS-Fuzz build produces --
# the two setups cannot drift apart in how R itself is built.
COPY ossfuzz.sh /opt/ossfuzz.sh
COPY docker/base/build-r.sh /opt/build-r.sh
RUN /opt/build-r.sh && rm -rf $SRC/r-source/.svn
