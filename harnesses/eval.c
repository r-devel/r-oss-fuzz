/*
 * Evaluate R source in a fresh environment with selected primitives only.
 *
 * The parse target stops at R_ParseVector; this one runs what it parsed,
 * which is where the interpreter core lives (eval.c, envir.c, subset.c,
 * subassign.c, coerce.c, arithmetic.c).  Each input is evaluated in a new
 * environment whose locked parent holds a small allowlist of primitives,
 * so the input can define closures, build and index vectors, loop and
 * branch, set attributes and dispatch S3 methods of its own, but cannot
 * reach I/O, native calls, namespaces, reflection or process-global state.
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

/* Interrupt checks the code run by the unwind itself (on.exit expressions)
 * gets after the budget is spent, per expression; see eval_poll_budget. */
#define FUZZ_EVAL_GRACE 1000

/* The allowlist frame, the wrappers frame below it, compiler::compile, and
 * the closure that puts the allowlist frame's attributes back, with the
 * attributes it puts back. */
static SEXP eval_builtins, eval_wrappers, eval_compile_fn;
static SEXP eval_reset_builtins_fn, eval_builtins_attributes;

/* Remaining interrupt checks for the current input; 0 means no limit. */
static long eval_budget;
/* Set once the budget or the CPU limit has ended the current input. */
static int eval_exhausted;
static clock_t eval_cpu_start;

/* Only primitives: importing a base closure would also import its enclosing
 * namespace and the capabilities reachable through its implementation.
 * No reflection or metaprogramming APIs are exposed; language objects from
 * quote() and substitute() are inert without eval().  Closures created by
 * the input inherit only the restricted environment.  `:`, seq_len,
 * seq.int, `attr<-` and `attributes<-` are provided separately, through
 * wrappers (below); class<- and oldClass<- not at all.
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
    "sum", "prod", "min", "max", "any", "all", "invisible",
    /* Language objects, argument introspection, switch and on.exit. */
    "quote", "substitute", "missing", "nargs", "switch", "on.exit",
    /* Attributes other than class; see the wrappers for `attr<-`. */
    "attr", "attributes", "names", "names<-", "dim", "dim<-", "dimnames",
    "dimnames<-", "levels<-", "unclass", "class", "oldClass",
    /* S3 dispatch on the implicit class to methods the input defines;
     * .GenericDefEnv is the allowlist frame itself, see eval_reset_builtins.
     * NextMethod is a closure and is not imported. */
    "UseMethod",
    /* rep allocates its result, so the vector heap bounds it; the compact
     * sequence builders are wrapped below. */
    "rep", "seq_along"
};

/*
 * Wrappers: closures standing in for primitives whose plain form would
 * get past a limit.  Each is bound in eval_wrappers, a frame of its own
 * below the allowlist, because the compiler inlines and constant-folds
 * calls to names it finds in the base-like frame (the COLON and SEQLEN
 * instructions; `:`, seq_len, seq.int and rep are in its foldFuns), and
 * an inlined call would bypass the wrapper (see eval_compile).  The
 * wrappers share one private enclosure holding only the primitives their
 * bodies name (`function` included: it is a primitive looked up like any
 * other), the wrapped primitives under dotted names, and .Internal, bound
 * there to raise the errors and nowhere the input can see.  So they add
 * no capability.
 *
 * `:`, seq_len and seq.int build compact ALTREP sequences, which cost
 * nothing to create whatever their length; the reductions without an
 * ALTREP shortcut (prod, or min/max/sum with two arguments) then walk 1e9
 * elements in C without an interrupt check: 8-18 s under ASAN, which the
 * budget cannot see and ClusterFuzz would file as a timeout.  Nothing
 * else in the allowlist builds a long vector without allocating it, and
 * allocation is bounded by the vector heap.  `:` is capped on what it
 * uses: the first element of each argument, as a double, so a longer
 * vector or a character argument (`c(1e12, 1):5`, `"1":"1e9"`) is bounded
 * like a scalar.  seq_len and seq.int have more argument forms, so they
 * are capped on the result instead: building it is free, and its length
 * is known before anything walks it.
 *
 * `attr<-` and `attributes<-` refuse the class attribute.  An object with
 * a class attribute dispatches every internal generic in the allowlist
 * (`[`, `+`, `length`, `c`, ...) to the S3 methods base registers for its
 * classes -- `[.data.frame`, `Ops.Date`, `$.DLLInfo` -- which are closures
 * over the base namespace running on input-shaped data, and a crash in
 * one of them on `class(x) <- "DLLInfo"` is the "you asked for it" report
 * this target is meant not to produce.  UseMethod dispatches on the
 * implicit class (matrix, integer, function, ...) to methods the input
 * defines, which is the dispatch code this allowlist is for.
 */
static const char *const eval_wrapper_primitives[] = {
    "function", "{", "if", "&&", ">=", ">", "==", "-", "<-", "length", "[[",
    "as.double", "is.finite", "abs", "is.character", "is.na", "!", "any",
    "names", ".Internal"
};

static const char eval_colon_source[] = R"(
function(from, to) {
    if (length(from) >= 1L && length(to) >= 1L) {
        f <- as.double(from[[1L]])
        t <- as.double(to[[1L]])
        if (is.finite(f) && is.finite(t) && abs(t - f) >= 1e6)
            .Internal(stop(TRUE, "sequence too long for the eval target"))
    }
    .colon(from, to)
}
)";

static const char eval_seq_len_source[] = R"(
function(length.out) {
    x <- .seq_len(length.out)
    if (length(x) > 1e6)
        .Internal(stop(TRUE, "sequence too long for the eval target"))
    x
}
)";

static const char eval_seq_int_source[] = R"(
function(...) {
    x <- .seq_int(...)
    if (length(x) > 1e6)
        .Internal(stop(TRUE, "sequence too long for the eval target"))
    x
}
)";

static const char eval_attr_set_source[] = R"(
function(x, which, value) {
    if (is.character(which) && length(which) == 1L && !is.na(which) &&
        which == "class")
        .Internal(stop(TRUE, "the class attribute is not available in the eval target"))
    .attr_set(x, which, value = value)
}
)";

static const char eval_attributes_set_source[] = R"(
function(x, value) {
    if (any(names(value) == "class"))
        .Internal(stop(TRUE, "the class attribute is not available in the eval target"))
    .attributes_set(x, value)
}
)";

typedef struct {
    const char *name;       /* bound in eval_wrappers */
    const char *primitive;  /* the primitive, bound in the private enclosure */
    const char *source;
} eval_wrapper_t;

static const eval_wrapper_t eval_wrapper_table[] = {
    { ":", ".colon", eval_colon_source },
    { "seq_len", ".seq_len", eval_seq_len_source },
    { "seq.int", ".seq_int", eval_seq_int_source },
    { "attr<-", ".attr_set", eval_attr_set_source },
    { "attributes<-", ".attributes_set", eval_attributes_set_source },
};

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
 * interpreter is prepared for a longjmp at this point.
 *
 * The unwind runs the on.exit expressions of every frame it leaves, and
 * those are input code: `on.exit(repeat {})` would run forever if the
 * check switched itself off once spent (setTimeLimit() has exactly that
 * gap in plain R).  So the count is reloaded with a small grace instead,
 * and the CPU backstop keeps measuring from the start of the input.  Each
 * on.exit expression gets at most FUZZ_EVAL_GRACE checks, or one check
 * once the CPU limit has passed, before it is cut off in turn; R drops an
 * expression that errors and carries on with the rest of the unwind
 * (R_run_onexits), so the cascade is bounded by the number of on.exit
 * expressions and the total by the CPU limit.  The grace also covers the
 * few checks the error path itself can make, since deparsing the call for
 * the message polls through instrumentation/0005.
 */
static void eval_poll_budget(void)
{
    if (eval_budget <= 0)
        return;

    int over_cpu =
        (double)(clock() - eval_cpu_start) / CLOCKS_PER_SEC > FUZZ_EVAL_CPU_LIMIT;
    if (--eval_budget > 0 && !over_cpu)
        return;

    eval_exhausted = 1;
    eval_budget = FUZZ_EVAL_GRACE;
    if (over_cpu)
        Rf_error("evaluation CPU limit exhausted");
    Rf_error("evaluation budget exhausted");
}

/* UseMethod() binds .GenericDefEnv in the method's frame to the top
 * environment of the generic's enclosure, which here is the allowlist frame
 * itself.  Its bindings are locked, but attributes are not bindings:
 * `attr(.GenericDefEnv, "name") <- "x"` would take away the name the
 * compiler keys on, and anything set there would outlive the input.  So the
 * frame's attributes are put back after every input, and before it in case
 * the last one left by a jump.  (.GenericCallEnv is the caller's frame, the
 * input's own.)  Through R, since the attribute list is not reachable from
 * the public API; in two steps with a preserved value, so that nothing is
 * allocated while an attribute the input left may be filling the heap. */
static const char eval_reset_builtins_source[] = R"(
function(env, value) {
    attributes(env) <- NULL
    attributes(env) <- value
}
)";

static void eval_reset_builtins(void)
{
    SEXP call;
    Rf_protect(call = Rf_lang3(eval_reset_builtins_fn, eval_builtins,
                               eval_builtins_attributes));
    Rf_eval(call, R_BaseEnv);
    Rf_unprotect(1);
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
static const char eval_compiler_setup[] = R"(
local({
    ns <- asNamespace("compiler")
    isBaseVar <- function(var, cntxt) {
        info <- getInlineInfo(var, cntxt)
        !is.null(info) &&
            (identical(info$frame, .BaseNamespaceEnv) ||
             identical(info$frame, baseenv()) ||
             packFrameName(info$frame) == "base")
    }
    environment(isBaseVar) <- ns
    unlockBinding("isBaseVar", ns)
    assign("isBaseVar", isBaseVar, envir = ns)
    lockBinding("isBaseVar", ns)
    compiler::compile
})
)";

/* Run once at start-up, so the compiler's lazily loaded internals are in
 * memory before the first input and every input sees the same R. */
static const char eval_warmup_source[] = R"(
f <- function(n) {
    s <- 0
    for (i in 1:n) if (i %% 2 == 0) s <- s + i else next
    s
}
x <- c(f(10), 1)
x[[2]] <- x[1]
g <- function(...) list(...)
g(x, repeat break)
h <- function(x) UseMethod("h")
h.default <- function(x) { on.exit(nargs()); switch(class(x), numeric = 1, 2) }
h.function <- function(x) attr(unclass(x), "srcref")
h(x); h(g)
y <- seq_len(3); names(y) <- c("a", "b", "c"); dim(y) <- 3L; y[[2L]]
)";

/* Byte-code for expr, or expr itself if the compiler declined it.
 *
 * The compiler is R code and runs under the input's budget like the code
 * it produces.  It used to run with the budget paused, bounded only by
 * the parsed-tree limits, but its cost is not linear in the tree: constant
 * folding re-walks every subtree at each level of nesting, so an
 * expression nested 62 calls deep compiles in about a second under ASAN
 * and four of them (270 bytes, within the tree limits) in over four,
 * which on the bots was the 25 s libFuzzer timeout.  A compile the
 * budget cuts off leaves eval_budget at zero; the caller stops the input
 * there rather than running the expression uncompiled.
 */
static SEXP eval_compile(SEXP expr, SEXP env)
{
    SEXP quoted, call, code;
    int error = 0;

    Rf_protect(quoted = Rf_lang2(R_QuoteSymbol, expr));
    Rf_protect(call = Rf_lang3(eval_compile_fn, quoted, env));
    code = R_tryEvalSilent(call, R_BaseEnv, &error);
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
    eval_reset_builtins();
    Rf_protect(env = R_NewEnv(eval_wrappers, TRUE, 29));
    eval_cpu_start = clock();
    eval_exhausted = 0;
    eval_budget = FUZZ_EVAL_BUDGET;
    for (R_xlen_t i = 0; i < XLENGTH(parsed); i++) {
        SEXP code;
        Rf_protect(code = eval_compile(VECTOR_ELT(parsed, i), env));
        if (eval_exhausted) {
            /* The compiler used up the budget or the CPU limit. */
            *error = 1;
            Rf_unprotect(1);
            break;
        }
        result = R_tryEvalSilent(code, env, error);
        Rf_unprotect(1);
        if (*error)
            break;
    }
    eval_budget = 0;
    eval_reset_builtins();

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

    eval_reset_builtins_fn = eval_run_init(eval_reset_builtins_source, R_BaseEnv);
    R_PreserveObject(eval_reset_builtins_fn);
    eval_builtins_attributes = eval_run_init("list(name = \"package:base\")", R_BaseEnv);
    R_PreserveObject(eval_builtins_attributes);
    Rf_protect(eval_builtins = R_NewEnv(R_EmptyEnv, TRUE, 97));
    eval_reset_builtins();
    eval_import_primitives(eval_builtins, eval_primitives,
                           sizeof(eval_primitives) / sizeof(*eval_primitives));
    R_LockEnvironment(eval_builtins, TRUE);

    Rf_protect(eval_wrappers = R_NewEnv(eval_builtins, TRUE, 29));
    SEXP private_env;
    size_t n_wrappers = sizeof(eval_wrapper_table) / sizeof(*eval_wrapper_table);
    Rf_protect(private_env = R_NewEnv(R_EmptyEnv, TRUE, 29));
    eval_import_primitives(private_env, eval_wrapper_primitives,
                           sizeof(eval_wrapper_primitives) / sizeof(*eval_wrapper_primitives));
    for (size_t i = 0; i < n_wrappers; i++)
        Rf_defineVar(Rf_install(eval_wrapper_table[i].primitive),
                     eval_primitive(eval_wrapper_table[i].name), private_env);
    R_LockEnvironment(private_env, TRUE);
    for (size_t i = 0; i < n_wrappers; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = eval_run_init(eval_wrapper_table[i].source, private_env));
        Rf_defineVar(Rf_install(eval_wrapper_table[i].name), wrapper, eval_wrappers);
        Rf_unprotect(1);
    }
    Rf_unprotect(1);
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
