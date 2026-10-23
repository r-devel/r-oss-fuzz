/*
 * Evaluate R source in a fresh environment with selected primitives only.
 *
 * The parse target stops at R_ParseVector; this one runs what it parsed,
 * which is where the interpreter core lives (eval.c, envir.c, subset.c,
 * subassign.c, coerce.c, arithmetic.c).  Each input is evaluated in a new
 * environment whose locked parent holds a small allowlist of primitives,
 * so the input can define closures, build and index vectors, loop and
 * branch, but cannot reach I/O, native calls, namespaces, reflection or
 * process-global state.
 *
 * The allowlist is not a security sandbox -- it cannot contain a bug in
 * the interpreter -- and does not need to be: the fuzzing host is
 * disposable.  It exists so that fuzzing cycles go to the evaluator rather
 * than the filesystem, and so that every finding is a crash reachable from
 * ordinary R code.  That second property is what makes a report from this
 * target unambiguous: nothing here needs .Internal, body<- or any other
 * "you asked for it" entry point.
 *
 * Each top-level expression is byte-compiled before it runs, so what is
 * fuzzed is the byte-code interpreter with the AST interpreter behind it,
 * the same mix a session runs; see eval_compile.
 */

/* 8 MiB, not common.h's 1 GiB: the budget below is counted in evaluations,
 * and one evaluation can do a whole vector's worth of work, so the vector
 * heap is what caps the work of any one evaluation.  Base R itself needs
 * about 1 MiB of it.  R ignores a maximum below its initial heap (64 MiB),
 * so fuzz_target_init lowers R_VSIZE to match. */
#define FUZZ_R_MAX_VSIZE "8Mb"
#include "common.h"

#include <time.h>
#include <R_ext/eventloop.h>   /* R_PolledEvents */

#define FUZZ_MAX_INPUT 8192
#define FUZZ_MAX_DEPTH 64
#define FUZZ_MAX_NODES 1024

/* Interrupt checks one input may make before it is cut off.  eval() checks
 * for interrupts once per 10 evaluations (instrumentation/0001; stock R:
 * once per 1000) and C loops that call R_CheckUserInterrupt add
 * their own, so this is roughly 200k evaluations: well under a second even
 * with sanitizers, and deterministic, which a wall-clock limit is not.
 * See eval_poll_budget. */
#define FUZZ_EVAL_BUDGET 20000

/* CPU seconds an input may use before the next budget check cuts it off,
 * whatever the budget says.  A backstop for vector-heavy loops, where the
 * budget's unit of work is too coarse; see eval_poll_budget. */
#define FUZZ_EVAL_CPU_LIMIT 1.0

/* The allowlist frame, the wrappers frame below it, and compiler::compile. */
static SEXP eval_builtins, eval_wrappers, eval_compile_fn;

/* Remaining interrupt checks for the current input; 0 means no limit, which
 * is also how eval_compile pauses the count. */
static long eval_budget;
static clock_t eval_cpu_start;

/* Only primitives: importing a base closure would also import its enclosing
 * namespace and the capabilities reachable through its implementation.
 * No class/attribute setters or reflection/metaprogramming APIs are exposed.
 * Closures created by the input inherit only the restricted environment.
 * `:` is provided separately, through a length-capped wrapper (below).
 */
static const char *const eval_primitives[] = {
    "{", "(", "if", "for", "while", "repeat", "break", "next",
    "function", "return", "<-", "=",
    "+", "-", "*", "/", "^", "%%", "%/%",
    "==", "!=", "<", "<=", ">", ">=", "!", "&", "|", "&&", "||",
    "c", "list", "[", "[[", "$", "[<-", "[[<-", "$<-",
    "length", "is.null", "is.logical", "is.integer", "is.double",
    "is.complex", "is.character", "is.list", "is.na", "is.nan", "is.finite",
    "is.infinite", "as.integer", "as.double", "as.logical", "as.character",
    "as.complex", "as.raw", "abs", "sqrt", "floor", "ceiling", "trunc",
    "sum", "prod", "min", "max", "any", "all", "invisible"
};

/*
 * `:` is wrapped rather than imported.  A compact ALTREP sequence costs
 * nothing to create whatever its length, and the reductions without an
 * ALTREP shortcut (prod, or min/max/sum with two arguments) then walk
 * 1e9 elements in C without an interrupt check: 8-18 s under ASAN, which
 * the budget cannot see and ClusterFuzz would file as a timeout.  Nothing
 * else in the allowlist builds a long vector without allocating it, and
 * allocation is bounded by the vector heap.
 *
 * The wrapper's enclosure holds only what its definition and body name
 * (`function` included: it is a primitive looked up like any other), so
 * it adds no capability.  .Internal is bound there to raise the error,
 * and nowhere the input can see.
 *
 * The wrapper is bound in eval_wrappers, a frame of its own below the
 * allowlist: the compiler inlines calls to names it finds in the base-like
 * frame, and the COLON instruction would bypass the cap (see eval_compile).
 */
static const char *const eval_wrapper_primitives[] = {
    "function", "{", "if", "&&", "==", ">=", "-", "length", "is.finite", "abs",
    ".Internal"
};

static const char *const eval_colon_source =
    "function(from, to) {\n"
    "    if (length(from) == 1L && length(to) == 1L &&\n"
    "        is.finite(from) && is.finite(to) && abs(to - from) >= 1e6)\n"
    "        .Internal(stop(TRUE, \"sequence too long for the eval target\"))\n"
    "    .colon(from, to)\n"
    "}";

typedef struct {
    const uint8_t *data;
    size_t size;
} eval_input_t;

/*
 * Execution budget, counted in interrupt checks.
 *
 * R_CheckUserInterrupt() -> R_ProcessEvents() -> R_PolledEvents() is the
 * hook R offers for event loops, and it is reached from the same places
 * that honour setTimeLimit(): every 10th eval() of the AST interpreter
 * (every 1000th in stock R; instrumentation/0001 lowers it),
 * the byte-code loop back-edges, and the long-running C loops that poll
 * for interrupts.  Counting those calls instead of CPU time gives every
 * input the same budget on every machine, so an input that is cut off
 * under ASAN on a slow bot is cut off the same way in a local reproduction,
 * and libFuzzer's coverage feedback stops depending on timing.
 *
 * Exactness is to within one check interval: eval()'s counter is static
 * and carries over between inputs.
 *
 * The unit is an evaluation, and an evaluation can be `!x` over the whole
 * heap: with a 64 MiB heap and a check every 1000 evaluations,
 * `x <- !1:4e4; repeat !x` ran 15 s under ASAN before the budget was
 * spent, and would have been filed as a timeout.  Three things bound that.
 * The heap is small (8 MiB), which caps the work of any one evaluation.
 * The check interval is short (instrumentation/0001), which caps the number of
 * evaluations between two checks.  And a CPU backstop ends the input at
 * the first check after FUZZ_EVAL_CPU_LIMIT seconds, whatever the budget
 * says.  The backstop is the one timing-dependent limit left, and it only
 * decides whether a vector-heavy input completes or errors, never whether
 * it crashes; it sits far below ClusterFuzz's timeout threshold so that
 * difference stays out of the tracker.
 *
 * The error unwinds to R_tryEvalSilent like any other R error.  Raising it
 * from inside R_ProcessEvents is what R_CheckTimeLimits does, so the
 * interpreter is prepared for a longjmp at this point.  The budget is
 * zero by the time either error is raised, which switches the check off,
 * so nothing on the error path can re-enter it.
 */
static void eval_poll_budget(void)
{
    if (eval_budget <= 0)
        return;

    if (--eval_budget == 0)
        Rf_error("evaluation budget exhausted");

    if ((double)(clock() - eval_cpu_start) / CLOCKS_PER_SEC > FUZZ_EVAL_CPU_LIMIT) {
        eval_budget = 0;
        Rf_error("evaluation CPU limit exhausted");
    }
}

/* The allowlist is only ever primitives (see eval_primitives): a name that
 * stops being one would silently import a closure and its namespace. */
static SEXP eval_primitive(const char *name)
{
    SEXP value = Rf_findFun(Rf_install(name), R_BaseEnv);
    if (TYPEOF(value) != BUILTINSXP && TYPEOF(value) != SPECIALSXP) {
        fprintf(stderr, "eval: %s is no longer a primitive\n", name);
        abort();
    }
    return value;
}

static void eval_import_primitives(SEXP env, const char *const *names, size_t n)
{
    for (size_t i = 0; i < n; i++)
        Rf_defineVar(Rf_install(names[i]), eval_primitive(names[i]), env);
}

/* Parse and evaluate one expression of set-up code.  A failure here is a
 * harness bug, so it stops the process rather than becoming an R error. */
static SEXP eval_run_init(const char *source, SEXP env)
{
    ParseStatus status;
    SEXP text, parsed, value;
    int error = 0;

    Rf_protect(text = Rf_mkString(source));
    Rf_protect(parsed = R_ParseVector(text, -1, &status, R_NilValue));
    if (status != PARSE_OK || XLENGTH(parsed) != 1)
        abort();

    value = R_tryEvalSilent(VECTOR_ELT(parsed, 0), env, &error);
    if (error) {
        fprintf(stderr, "eval: set-up failed: %s", R_curErrorBuf());
        abort();
    }

    Rf_unprotect(2);
    return value;
}

static int eval_valid_utf8(const uint8_t *data, size_t size)
{
    size_t i = 0;
    while (i < size) {
        uint8_t c = data[i++];
        if (c < 0x80)
            continue;
        if (c >= 0xc2 && c <= 0xdf) {
            if (i >= size || (data[i++] & 0xc0) != 0x80)
                return 0;
            continue;
        }
        if (c >= 0xe0 && c <= 0xef) {
            if (i + 1 >= size || (data[i] & 0xc0) != 0x80 ||
                (data[i + 1] & 0xc0) != 0x80 ||
                (c == 0xe0 && data[i] < 0xa0) ||
                (c == 0xed && data[i] >= 0xa0))
                return 0;
            i += 2;
            continue;
        }
        if (c >= 0xf0 && c <= 0xf4) {
            if (i + 2 >= size || (data[i] & 0xc0) != 0x80 ||
                (data[i + 1] & 0xc0) != 0x80 ||
                (data[i + 2] & 0xc0) != 0x80 ||
                (c == 0xf0 && data[i] < 0x90) ||
                (c == 0xf4 && data[i] >= 0x90))
                return 0;
            i += 3;
            continue;
        }
        return 0;
    }
    return 1;
}

/* Bound the post-parse walk, including wide argument lists. This limits test
 * complexity, not execution time: even a tiny expression can loop forever.
 */
static int eval_tree_within_budget(SEXP x, unsigned depth, unsigned *nodes)
{
    if (depth > FUZZ_MAX_DEPTH || ++*nodes > FUZZ_MAX_NODES)
        return 0;

    switch (TYPEOF(x)) {
    case LANGSXP:
    case LISTSXP:
        for (SEXP p = x; p != R_NilValue; p = CDR(p)) {
            if (++*nodes > FUZZ_MAX_NODES ||
                !eval_tree_within_budget(CAR(p), depth + 1, nodes))
                return 0;
        }
        return 1;
    case EXPRSXP:
        for (R_xlen_t i = 0; i < XLENGTH(x); i++) {
            if (!eval_tree_within_budget(VECTOR_ELT(x, i), depth + 1, nodes))
                return 0;
        }
        return 1;
    default:
        return 1;
    }
}

/*
 * Byte-code.
 *
 * Nearly all R code that runs in a session is byte-compiled: packages at
 * install time, everything else by the JIT after a call or two.  The JIT
 * is not used here (R_ENABLE_JIT=0): it compiles on its own schedule,
 * keeps a cache across inputs, and catches errors inside the compiler,
 * where a budget error would be swallowed and the budget left switched
 * off.  Instead the harness compiles each top-level expression itself,
 * with the budget paused, and evaluates the result.  Closures the input
 * defines are created with compiled bodies (MAKECLOSURE), top-level loops
 * are compiled too, and anything the compiler declines runs through the
 * AST interpreter, which is what the JIT falls back to as well.  Compile
 * time is bounded by the parsed-tree limits; constant folding evaluates
 * base functions on literals only.
 *
 * The compiler (compiler:::cmp.R) needs two things from the sandbox.  It
 * refuses an environment whose chain does not end in a frame topenv()
 * recognises, and it inlines base syntax and arithmetic only for names it
 * finds bound in a frame it classifies as base, by the frame's "name"
 * attribute.  So eval_builtins carries the name of base's package frame.
 * Its bindings are base's own primitives, so the BASEGUARD check that
 * compiled code makes before an inlined builtin call passes, and a name
 * the input rebinds is looked up like any other.  isBaseVar, which gates
 * whether break/next compile to a jump or to a loop context, compares
 * frames by identity instead, so it is rebound to accept the named frame;
 * without that every loop with a conditional break would compile with a
 * context, which a session's would not.
 */
static const char *const eval_compiler_setup =
    "local({\n"
    "    ns <- asNamespace(\"compiler\")\n"
    "    isBaseVar <- function(var, cntxt) {\n"
    "        info <- getInlineInfo(var, cntxt)\n"
    "        !is.null(info) &&\n"
    "            (identical(info$frame, .BaseNamespaceEnv) ||\n"
    "             identical(info$frame, baseenv()) ||\n"
    "             packFrameName(info$frame) == \"base\")\n"
    "    }\n"
    "    environment(isBaseVar) <- ns\n"
    "    unlockBinding(\"isBaseVar\", ns)\n"
    "    assign(\"isBaseVar\", isBaseVar, envir = ns)\n"
    "    lockBinding(\"isBaseVar\", ns)\n"
    "    compiler::compile\n"
    "})";

/* Run once at start-up, so the compiler's lazily loaded internals are in
 * memory before the first input and every input sees the same R. */
static const char *const eval_warmup_source =
    "f <- function(n) {\n"
    "    s <- 0\n"
    "    for (i in 1:n) if (i %% 2 == 0) s <- s + i else next\n"
    "    s\n"
    "}\n"
    "x <- c(f(10), 1)\n"
    "x[[2]] <- x[1]\n"
    "g <- function(...) list(...)\n"
    "g(x, repeat break)\n";

/* Byte-code for expr, or expr itself if the compiler declined it. */
static SEXP eval_compile(SEXP expr, SEXP env)
{
    SEXP quoted, call, code;
    int error = 0;
    long budget = eval_budget;

    Rf_protect(quoted = Rf_lang2(R_QuoteSymbol, expr));
    Rf_protect(call = Rf_lang3(eval_compile_fn, quoted, env));
    eval_budget = 0;
    code = R_tryEvalSilent(call, R_BaseEnv, &error);
    eval_budget = budget;
    Rf_unprotect(2);

    return error ? expr : code;
}

/* Caller protects the returned object immediately if it needs the result.
 * All errors (including parsing/allocation) must be under R_ToplevelExec.
 */
static SEXP eval_source(const eval_input_t *input, int *error)
{
    ParseStatus status;
    SEXP text, parsed, env, result = R_NilValue;
    Rf_protect(text = Rf_allocVector(STRSXP, 1));
    SET_STRING_ELT(text, 0,
                  Rf_mkCharLenCE((const char *)input->data, (int)input->size,
                                 CE_UTF8));
    Rf_protect(parsed = R_ParseVector(text, -1, &status, R_NilValue));
    unsigned nodes = 0;
    if (status != PARSE_OK || !eval_tree_within_budget(parsed, 0, &nodes)) {
        *error = 1;
        Rf_unprotect(2);
        return R_NilValue;
    }

    /* One budget covers all top-level expressions of an input. */
    Rf_protect(env = R_NewEnv(eval_wrappers, TRUE, 29));
    eval_cpu_start = clock();
    eval_budget = FUZZ_EVAL_BUDGET;
    for (R_xlen_t i = 0; i < XLENGTH(parsed); i++) {
        SEXP code;
        Rf_protect(code = eval_compile(VECTOR_ELT(parsed, i), env));
        result = R_tryEvalSilent(code, env, error);
        Rf_unprotect(1);
        if (*error)
            break;
    }
    eval_budget = 0;

    Rf_unprotect(3);
    return *error ? R_NilValue : result;
}

static void eval_one(void *data)
{
    int error = 0;
    eval_source((const eval_input_t *)data, &error);
}

static void eval_run(const uint8_t *data, size_t size)
{
    eval_input_t input = { data, size };
    R_ToplevelExec(eval_one, &input);
    /* A jump past eval_source (an interrupt, not an error) skips its reset. */
    eval_budget = 0;
}

int fuzz_target_init(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    /* The harness compiles explicitly (eval_compile); nothing is attached
     * that a method lookup could reach. */
    setenv("R_ENABLE_JIT", "0", 1);
    setenv("R_DEFAULT_PACKAGES", "NULL", 1);
    if (getenv("R_VSIZE") == NULL)
        setenv("R_VSIZE", FUZZ_R_MAX_VSIZE, 1);
    fuzz_init_r();

    Rf_protect(eval_builtins = R_NewEnv(R_EmptyEnv, TRUE, 97));
    Rf_setAttrib(eval_builtins, R_NameSymbol, Rf_mkString("package:base"));
    eval_import_primitives(eval_builtins, eval_primitives,
                           sizeof(eval_primitives) / sizeof(*eval_primitives));
    R_LockEnvironment(eval_builtins, TRUE);

    Rf_protect(eval_wrappers = R_NewEnv(eval_builtins, TRUE, 29));
    SEXP private_env, colon;
    Rf_protect(private_env = R_NewEnv(R_EmptyEnv, TRUE, 29));
    eval_import_primitives(private_env, eval_wrapper_primitives,
                           sizeof(eval_wrapper_primitives) / sizeof(*eval_wrapper_primitives));
    Rf_defineVar(Rf_install(".colon"), eval_primitive(":"), private_env);
    R_LockEnvironment(private_env, TRUE);
    Rf_protect(colon = eval_run_init(eval_colon_source, private_env));
    Rf_defineVar(Rf_install(":"), colon, eval_wrappers);
    Rf_unprotect(2);
    R_LockEnvironment(eval_wrappers, TRUE);

    eval_compile_fn = eval_run_init(eval_compiler_setup, R_BaseEnv);
    R_PreserveObject(eval_compile_fn);

    R_PolledEvents = eval_poll_budget;
    eval_run((const uint8_t *)eval_warmup_source, strlen(eval_warmup_source));
    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_MAX_INPUT || memchr(data, '\0', size) ||
        !eval_valid_utf8(data, size))
        return 0;

    eval_run(data, size);
    return 0;
}
