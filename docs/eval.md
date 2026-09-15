# Experimental evaluation target

`eval` parses UTF-8 R source and evaluates the expressions in order. It covers
interpreted evaluation, lazy arguments, closures and lexical scoping, control
flow, vector operations, and indexing/replacement. It discards results without
printing them. Ordinary R errors terminate that input; sanitizer failures still
terminate the process normally.

The target is **opt-in**. Set `ENABLE_EVAL_FUZZER=1` when running `ossfuzz.sh`
or pass it into the OSS-Fuzz builder:

```sh
python3 infra/helper.py build_fuzzers -e ENABLE_EVAL_FUZZER=1 r
```

As with other targets, the builder must use the checkout containing this change.
The dictionary, options, and eight seeds are packaged by the existing build loop.
ClusterFuzzLite clearing `DEFERRED_TARGETS` does not enable this target.

## Restrictions and limits

Each input gets a new environment. Its parent is a locked environment containing
only the primitives listed in `harnesses/eval.c`, with `emptyenv()` as its parent.
The harness verifies that every imported binding really is a primitive; importing
a base closure would also import its enclosing namespace. Input-created closures
inherit the restricted environment. Primitive names can be shadowed locally,
but the parent bindings are locked and the next input gets a fresh environment.

There are no bindings for filesystem/network access, shell execution, native
calls, namespace/package loading, environment reflection, `eval`, `quote`,
attribute/class setters, `<<-`, global options, or time-limit controls. These are
capability restrictions, not a blacklist applied to source text. For example,
`base::system` fails because `::` is unavailable. User-defined functions work.
JIT compilation and default package attachment are disabled at initialization.

Inputs are limited to 8 KiB; malformed UTF-8 and embedded NULs are rejected. A
post-parse tree walk has depth and node budgets of 64 and 1024. R's parser can reject deeply nested
input before that walk. R's vector heap defaults to 64 MiB. A cooperative CPU
limit of 50 ms and elapsed limit of 100 ms cover evaluation of each input, and
the harness clears the limit after both success and error. These checks depend
on R interrupt points and cannot stop arbitrary native code. The fuzzer options
also specify a five-second timeout and a 1024 MiB RSS limit.

This does not reset the whole R runtime. Interned symbols and other internal
state can survive, and the vector cap does not bound every native allocation.
Periodically restart workers. This target deliberately excludes base closures,
packages, S3/S4 class construction, reflection, and bytecode/JIT coverage.

## Local isolation

The R restrictions are **not a security sandbox** and cannot contain interpreter
memory corruption. OSS-Fuzz's local helper currently starts privileged Docker
containers, so use the separate launcher for evaluation:

```sh
scripts/run-eval.sh /absolute/path/to/oss-fuzz/build/out/r /absolute/path/to/eval-state
```

Run as an unprivileged host user. The launcher starts the target directly in
the base-runner image, without its normal entrypoint. It uses a read-only root
filesystem and `/out`, no network, no capabilities, `no-new-privileges`, Docker's
default syscall restrictions, a non-root UID, 2 GiB memory, one CPU, 64 processes,
and a 256 MiB temporary filesystem. GNU `timeout` supervises the worker with a
60-second wall-clock deadline; the fuzzer normally finishes five seconds earlier.
`EVAL_SECONDS` selects a deadline from 10 to 3600 seconds. The launcher retains
Docker's default seccomp policy; do not disable it to work around a runtime error.

Only the dedicated state directory is mounted writable, for `corpus/` and
`artifacts/`. Copy the supplied seed files into `eval-state/corpus/` before the
first run. That directory is intentionally accessible to the evaluated process:
keep unrelated files out of it, and use a filesystem quota if disk growth needs
a hard limit. The memory limit and temporary-filesystem limit do not cap this
bind mount. Docker image pulls happen on the host before the isolated run.

`EVAL_RUNNER_IMAGE` can select a compatible image (or pinned digest) containing
`/usr/bin/timeout` and R's runtime dependencies. It must match the target's CPU
architecture; use `DOCKER_DEFAULT_PLATFORM` when appropriate. Only R built with
coverage instrumentation provides useful feedback from inside R; instrumenting
the harness alone is a smoke test. Containers share the Docker host's kernel;
use a dedicated VM for stronger isolation. Review the actual hosted job settings
before enabling this target in continuous OSS-Fuzz runs.

## Behavioral checks

```sh
scripts/check-eval.sh
# For an instrumented installation, choose matching flags, for example:
R_BIN=Rdevel CC=clang CFLAGS='-fsanitize=address,undefined' scripts/check-eval.sh
```

The standalone checks exercise closure results, lazy promises, lexical capture,
indexing, copy-on-modify, and loops; verify denied capabilities and per-input
state isolation; and check recovery after syntax errors, allocation limits,
recursion errors, and repeated timeouts. They use fixed, harmless inputs.
The default R vector limit is forced for these checks. Run them without
`-DNDEBUG`, since they use assertions.
