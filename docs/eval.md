# The `eval` target

`eval` parses UTF-8 R source and evaluates the expressions in order, in a
fresh environment whose locked parent holds a small allowlist of primitives.
Where `parse` stops at `R_ParseVector`, this target byte-compiles what was
parsed and runs it: the byte-code interpreter (`bcEval` in `eval.c`) with the
AST interpreter behind it, environments and promises (`envir.c`), closures
and argument matching, `[`/`[[`/`$` and their replacement forms (`subset.c`,
`subassign.c`), arithmetic and comparison (`arithmetic.c`, `relop.c`,
`logic.c`), coercion (`coerce.c`) and the `c()`/`list()` builders. Results are
discarded without printing. An ordinary R error ends that input; sanitizer
reports still terminate the process as usual.

## What the input can do

The parent environment contains exactly the primitives listed in
`eval_primitives` in [`harnesses/eval.c`](../harnesses/eval.c): control flow
and `function`, assignment with `<-` and `=`, arithmetic, comparison and
logical operators, `c`, `list`, the three subsetting operators and their
replacement forms, the `is.*`/`as.*` predicates and coercions, a few
elementwise maths functions, `sum`/`prod`/`min`/`max`/`any`/`all`, and
`invisible`. Its parent is `emptyenv()`. The harness checks at start-up that
every imported binding really is a primitive, because importing a base
closure would also import the base namespace it closes over, and everything
reachable from there.

`:` is the one exception: it is a closure, not the primitive. A compact
ALTREP sequence costs nothing to create at any length, and the reductions
without an ALTREP shortcut (`prod`, or `min`/`max`/`sum` with two arguments)
then walk a billion elements in C with no interrupt check: 8 to 18 seconds
under ASAN, invisible to the budget below and a certain timeout report. The
wrapper refuses sequences of a million elements or more and otherwise calls
the primitive. Its enclosure is a private environment holding only what its
body names, so it adds no capability.

There are no bindings for filesystem, network or process access, `.Internal`,
`.Call` and friends, namespace or package loading, `eval`/`quote`/`substitute`,
environment accessors or `<<-`, attribute and class setters, S3/S4 dispatch,
`options`, or time limits. These are capability restrictions, not a denylist
over the source text: `base::system` fails because `::` is unbound. Closures
the input defines inherit the restricted environment, and primitive names can
be shadowed only in the input's own environment, which the next input never
sees. No default packages are attached, so nothing could leak through a
method lookup; the JIT is off because the harness compiles explicitly, as
the next section describes.

The allowlist is not a security sandbox and cannot contain a bug in the
interpreter; the fuzzing host is disposable, so it does not need to. It
exists for two other reasons. Fuzzing cycles go to the evaluator instead of
to the filesystem and process table. And every finding is reachable from
ordinary R code: nothing here needs `.Internal`, `body<-`, `environment<-`
or any other entry point that R-core treats as "you asked for it", which is
what makes a report from this target unambiguous.

## Byte-code

Nearly all R code that runs in a session is byte-compiled: package code at
install time, everything else by the JIT after a call or two. The harness
therefore compiles each top-level expression with `compiler::compile()`
before evaluating it, with the execution budget paused. Closures the input
defines are created with compiled bodies (`MAKECLOSURE`), top-level loops are
compiled, and an expression the compiler declines runs through the AST
interpreter, which is also the JIT's fallback. The AST interpreter still
sees the `:` wrapper, promise code and whatever the compiler refuses, so
both interpreters are exercised, in roughly the proportion a session has.

The JIT itself is not used. It compiles on its own schedule (small closures
on their second call, top-level loops only in the global environment), keeps
a cache across inputs that would make one input's compilation depend on an
earlier one, and catches errors raised inside the compiler, which would
swallow a budget error and leave the budget switched off. Compiling from the
harness avoids all three and costs 1 to 5 ms per expression under ASAN.

The compiler needs two things from the sandbox, both in
`LLVMFuzzerInitialize`. It refuses an environment whose chain does not end
in a frame `topenv()` recognises, and it inlines base syntax and arithmetic
only for names it finds in a frame it classifies as base, going by the
frame's `name` attribute. The allowlist frame therefore carries the name of
base's package frame. Its bindings are base's own primitives, so the
`BASEGUARD` check compiled code makes before an inlined builtin call passes,
and a name the input rebinds is still looked up like any other. The `:`
wrapper lives in a separate frame below the allowlist, which the compiler
classifies as local and so calls rather than inlining; the `COLON`
instruction would bypass the cap. Finally, the compiler's `isBaseVar()`
compares frames by identity with `baseenv()`, which decides whether a
`break` or `next` inside a conditional compiles to a jump or to a loop
context; it is rebound in the compiler namespace to accept the named frame,
so loops compile the way a session's do. `tests/eval.c` checks all of this:
closures come back with byte-code bodies, a loop with a conditional break
has no `STARTLOOPCNTXT`, and every bound below holds on the compiled path.

The compiler's own code is byte-compiled base R and runs with the budget
paused, so its cost is bounded by the parsed-tree limits rather than by the
budget. Constant folding evaluates base functions on literals only, and a
warm-up input at start-up loads the compiler's internals before fuzzing
begins, so every input sees the same R.

## Limits

| Limit | Value | Enforced by |
|-------|-------|-------------|
| input size | 8 KiB, valid UTF-8, no embedded NUL | harness, before parsing |
| parsed tree | depth 64, 1024 nodes | post-parse walk (`eval_tree_within_budget`) |
| vector heap | 8 MiB (`R_VSIZE` and `R_MAX_VSIZE`) | R's allocator; an ordinary R error |
| compilation | outside the budget; bounded by the parsed-tree limits | harness (`eval_compile`) |
| execution | 20000 interrupt checks per input | `R_PolledEvents` hook (`eval_poll_budget`) |
| execution, backstop | 1 CPU second, checked at the same points | the same hook |
| recursion | R's `expressions` limit and C stack check | R; an ordinary R error |

The execution budget is counted in work, not time. R calls
`R_CheckUserInterrupt()` at a fixed interval of evaluations in the AST
interpreter, at byte-code loop back-edges, and from the long-running C loops
that poll for interrupts; each call reaches `R_PolledEvents()`, which the
harness points at a counter. That is the same path `setTimeLimit()` is
checked on, so the error unwinds exactly as a time limit would, but the
budget is the same on every machine: an input cut off on a slow bot under
ASAN is cut off at the same point in a local reproduction, and libFuzzer's
coverage signal does not depend on timing. The counter in `eval()` is static
and carries over between inputs, so the budget is exact to within one check
interval. Under ASAN, `repeat {}` is stopped in about 40 ms; a
20000-iteration counting loop completes.

The unit of that budget is an evaluation, and one evaluation can be a
vector operation over the whole heap. The first local fuzz run found
exactly that: `x <- !1:4E4; repeat !x` ran for 15 seconds, well past
ClusterFuzz's timeout threshold, with the budget none the wiser. Three
things bound it now.

- **The heap is 8 MiB**, which caps the work of any one evaluation. Base R
  needs about 1 MiB of it. R silently ignores an `R_MAX_VSIZE` below its
  64 MiB initial heap, so the harness lowers `R_VSIZE` as well.
- **The check interval is short.** Stock R polls once per 1000
  evaluations, so a thousand heap-sized operations fit between two checks.
  [`instrumentation/0001`](../instrumentation/0001-eval-poll-for-interrupts-more-often.patch)
  makes the fuzzed R poll every 10 evaluations and every 128 byte-code
  instructions. It stays for as long as this target needs it, and the
  harness still works without it, only slower to cut inputs off.
- **A CPU backstop** ends the input at the first check after one CPU
  second, whatever the budget says. It is the only timing-dependent limit
  left. It decides whether a vector-heavy input completes or errors, never
  whether it crashes, and it sits far enough below the timeout threshold
  that bot speed cannot turn the difference into a report.

With all three, the worst inputs found so far (`repeat !x` over a 4 MB
vector, `repeat as.character(x)` over 100k doubles) end in under half a
second under ASAN.

The budget cannot see C loops that never poll, which is why `:` is capped;
nothing else in the allowlist builds a long vector without allocating it.

Unbounded recursion is left to R. `f <- function() f(); f()` hits the
`expressions` limit (5000) long before the C stack under ASAN, where
`R_CheckStack()` in `eval()` would otherwise catch it; both are plain R
errors and both were checked against an ASAN build.

## Reproducing a finding

Every function the input can call is a base primitive, so the restricted
environment is not needed to reproduce a crash: run the testcase with

```sh
R_VSIZE=8Mb R_MAX_VSIZE=8Mb Rscript --vanilla testcase.R
```

If it crashes plain R, that is the report. `Rscript` runs the same compiler
through the JIT, so a byte-code finding normally reproduces there too; one
that depends on a top-level loop or a closure called only once being
compiled can be reproduced by wrapping the testcase in a function and
calling `compiler::cmpfun()` on it, or by compiling each top-level
expression with `compiler::compile()` before evaluating it. A testcase that
only errors outside the harness was relying on the budget or the heap cap,
which the exported variable and a `setTimeLimit()` call can stand in for.
The interrupt-check budget has no user-level equivalent, but an input that
needs it to crash would be a budget bug, not an R bug.

## What is deliberately left out, and what comes next

The current allowlist exercises the evaluator core and not much else. The
findings of the earlier AFL++ evaluation harness in `kevinushey/r-afl` are
instructive here: all eight of its bugs (`besselI(1, Inf)`,
`intToUtf8(-1L)`, `as.POSIXlt(-1e19)`, `all(quote(x))`, `x[1e300]`,
`file.choose(sum)`, and two more float-to-integer casts) came from handing
unusual argument types and magnitudes to C entry points, not from the
interpreter proper. Of those, only the subscript overflow is reachable
through this allowlist. The value of an evaluation target is argument-space
coverage of builtins that the string-driven targets cannot provide, so the
allowlist should widen once this target has run quietly:

1. **Inert language objects and attributes**: `quote`, `substitute`,
   `missing`, `nargs`, `switch`, `rep`, `seq_len`, `seq_along`, `names<-`,
   `dim<-`, `attr`, `attr<-`, `class<-`, `oldClass<-`, `unclass`,
   `attributes<-`, `levels<-`, `UseMethod`, `on.exit`. Language objects are
   inert without `eval`, and attributes plus `UseMethod` open up S3
   dispatch, where a good share of historical interpreter crashes live.
   `all(quote(x))` is in this tier. `seq_len` and `seq.int` build compact
   sequences like `:` and need the same wrapper, in the same wrappers frame:
   the compiler has instructions for both and would otherwise inline them.
2. **Every remaining computational primitive**: the full `names.c` table
   minus the capability set (`.Internal`, `.External*`, `.Call`, `.C`,
   `.Fortran`, `.Primitive`, `environment<-`, `as.environment`, `baseenv`,
   `globalenv`, `emptyenv`, `pos.to.env`, `lazyLoadDBfetch`, `browser`,
   `tracemem` and friends, `proc.time`, `gc.time`, `interactive`,
   `standardGeneric`). `is.*`, `log`/`exp`/trig/gamma, `cumsum`, `range`,
   complex accessors, `%*%`, `xtfrm`, `anyNA`, `as.call`, `call`.
3. **Pure base closures over `.Internal`**, imported one at a time behind
   a wrapper whose enclosure is a private environment (the `:` pattern), so
   the namespace is never reachable: `besselI`, `intToUtf8`, `utf8ToInt`,
   `strtoi`, `chartr`, `nchar`, `substr`, `rev`, `sort`, `order`, `paste`,
   `format`, `as.POSIXlt`, `Sys.time` is not one of them. Each of these
   has a string-driven target already; what eval adds is numeric and
   type-confused arguments.

A denylist over all of base, which is what r-afl did and what PHP's
`execute` fuzzer does, is not the plan: R has first-class environments, so
any closure imported from base hands the input `environment(f)` and the
whole namespace unless reflection is also denied, and that list never
closes. PHP can get away with a `disable_functions` list because its
function table is flat.

Prior art the design follows: QuickJS's `fuzz_eval` bounds the script with
an interrupt-handler counter (100 calls), a 64 MB memory limit and a fresh
runtime per input; PHP's `execute` fuzzer counts opcodes (1000 per run) and
caps inputs at 8 KiB; SQLite's `ossfuzz.c` uses a progress-handler step
limit. CPython's targets compile but never execute, so there is no Python
evaluator fuzzer to compare with. None of them use wall-clock limits.

## Behavioural checks

```sh
scripts/check-eval.sh
# For an instrumented installation, choose matching flags, for example:
R_BIN=Rdevel CC=clang CFLAGS='-fsanitize=address,undefined' scripts/check-eval.sh
```

[`tests/eval.c`](../tests/eval.c) includes the harness and checks results
of closures, promises, lexical capture, indexing, copy-on-modify and loops;
that capability probes fail and nothing survives an input; recovery after
syntax errors, the heap cap, unbounded recursion, the budget and the
vector-heavy loops above (three rounds each); that a loop within budget
runs to completion with the same answer every time; and the `:` cap,
including that its private environment is unreachable. They use fixed,
harmless inputs, force the 8 MiB heap, and need to be built without
`-DNDEBUG`. Against a stock R the budget checks still pass, just more
slowly, since the CPU backstop takes over from the poll interval.
