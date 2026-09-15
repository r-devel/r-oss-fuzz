#!/bin/bash
set -euo pipefail

# Run the packaged target directly, bypassing OSS-Fuzz's privileged helper
# and its runner entrypoint. The image must contain GNU timeout and the
# runtime libraries needed by the packaged R installation.
if [ "$#" -lt 2 ]; then
    echo "usage: $0 OUT_DIRECTORY STATE_DIRECTORY [libFuzzer arguments...]" >&2
    exit 2
fi
eval_out=$(cd "$1" && pwd -P)
mkdir -p "$2/corpus" "$2/artifacts"
eval_state=$(cd "$2" && pwd -P)
shift 2

if [ ! -x "$eval_out/eval" ]; then
    echo "missing executable: $eval_out/eval (build with ENABLE_EVAL_FUZZER=1)" >&2
    exit 2
fi
if [ "$(id -u)" -eq 0 ]; then
    echo "run this launcher as an unprivileged user" >&2
    exit 2
fi
eval_seconds=${EVAL_SECONDS:-60}
case "$eval_seconds" in
    ''|*[!0-9]*) echo "EVAL_SECONDS must be an integer from 10 to 3600" >&2; exit 2 ;;
esac
if [ "$eval_seconds" -lt 10 ] || [ "$eval_seconds" -gt 3600 ]; then
    echo "EVAL_SECONDS must be an integer from 10 to 3600" >&2
    exit 2
fi

exec docker run --rm --init \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" \
    --pids-limit 64 \
    --memory 2g --memory-swap 2g --cpus 1 \
    --ulimit core=0 --ulimit nofile=1024:1024 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
    --mount "type=bind,src=$eval_out,dst=/out,readonly" \
    --mount "type=bind,src=$eval_state,dst=/work" \
    --workdir /work \
    --env HOME=/tmp \
    --env R_HOME=/out/r-install/lib/R \
    --env R_MAX_VSIZE=64Mb \
    --entrypoint /usr/bin/timeout \
    "${EVAL_RUNNER_IMAGE:-gcr.io/oss-fuzz-base/base-runner}" \
    --signal=KILL "$eval_seconds" \
    /out/eval /work/corpus \
    -artifact_prefix=/work/artifacts/ \
    -max_total_time="$((eval_seconds - 5))" -timeout=5 -rss_limit_mb=1024 \
    "$@"
