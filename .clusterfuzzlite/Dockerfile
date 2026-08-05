# ClusterFuzzLite build image.
#
# Everything expensive (R itself) lives in the base image, which is rebuilt on
# a schedule by .github/workflows/base-image.yml.  This layer only adds the
# current checkout of the harnesses, so it builds in seconds.

FROM ghcr.io/r-devel/r-oss-fuzz/r-base:address

COPY . $SRC/r-oss-fuzz
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/r-oss-fuzz
