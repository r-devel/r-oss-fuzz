/* Standalone behavioral checks; include the harness to test its boundaries. */
#include <assert.h>
#include <sys/wait.h>
#include "../harnesses/eval.c"

typedef struct {
    const char *source;
    int expect_error;
    double expected;
} eval_check_t;

static void check_source(void *data)
{
    eval_check_t *check = data;
    eval_input_t input = { (const uint8_t *)check->source, strlen(check->source) };
    int error = 0;
    SEXP result;
    Rf_protect(result = eval_source(&input, &error));
    if (!!error != check->expect_error) {
        fprintf(stderr, "unexpected error=%d for: %s\n", error, check->source);
        if (error)
            fprintf(stderr, "R said: %s", R_curErrorBuf());
        abort();
    }
    if (!error) {
        assert(XLENGTH(result) == 1);
        assert(Rf_asReal(result) == check->expected);
    }
    Rf_unprotect(1);
}

/* The input's last value must be a closure with a byte-code body. */
static void check_compiled_source(void *data)
{
    const char *source = data;
    eval_input_t input = { (const uint8_t *)source, strlen(source) };
    int error = 0;
    SEXP result;
    Rf_protect(result = eval_source(&input, &error));
    if (error || TYPEOF(result) != CLOSXP || TYPEOF(R_ClosureBody(result)) != BCODESXP) {
        fprintf(stderr, "closure not compiled for: %s\n", source);
        abort();
    }
    Rf_unprotect(1);
}

static void check_compiled(const char *source)
{
    R_ToplevelExec(check_compiled_source, (void *)source);
    assert(eval_budget == 0);
}

/* A loop with a conditional break compiles to a jump, not a loop context,
 * only while the isBaseVar rebinding in eval_compiler_setup takes. */
static void check_loop_jump(void *unused)
{
    (void)unused;
    SEXP env, fn, call, result;
    Rf_protect(env = R_NewEnv(eval_wrappers, TRUE, 29));
    Rf_protect(fn = R_ParseEvalString(
        "function(env) {\n"
        "    code <- compiler::compile(quote(for (i in 1:3) if (i == 2) break), env)\n"
        "    ops <- paste(deparse(compiler::disassemble(code)), collapse = \"\")\n"
        "    grepl(\"STARTFOR\", ops) && !grepl(\"STARTLOOPCNTXT\", ops)\n"
        "}", R_BaseEnv));
    Rf_protect(call = Rf_lang2(fn, env));
    result = Rf_eval(call, R_BaseEnv);
    assert(Rf_asLogical(result) == TRUE);
    Rf_unprotect(3);
}

static void check(const char *source, int expect_error, double expected)
{
    eval_check_t test = { source, expect_error, expected };
    Rboolean completed = R_ToplevelExec(check_source, &test);
    if (!completed && !expect_error) {
        fprintf(stderr, "unexpected top-level error for: %s\n", source);
        abort();
    }
    /* Every path out of an input must leave the budget switched off. */
    assert(eval_budget == 0);
}

static void run_checks(void *unused)
{
    (void)unused;
    check("1 + 2 * 3", 0, 7);
    check("f <- function(x, y = x + 1) y * 2; f(3)", 0, 8);
    check("f <- function(x, y) x; f(42, missing_name)", 0, 42);
    check("make <- function(x) function(y) x + y; f <- make(10); f(2)", 0, 12);
    check("f <- function(...) sum(c(...)); f(1, 2, 3)", 0, 6);
    check("x <- list(a = 1:3); x[[1]][2] <- 9L; x$a[2]", 0, 9);
    check("x <- 0; for (i in 1:4) x <- x + i; x", 0, 10);
    check("x <- 1:3; y <- x; y[1] <- 9; x[1]", 0, 1);

    /* Values, closures, and shadowed primitives must not survive an input. */
    check("x <- 99; f <- function() 1; length <- 7; length", 0, 7);
    check("x", 1, 0);
    check("f()", 1, 0);
    check("length(NULL)", 0, 0);

    /* Ordinary capability access must fail without side effects. These are
     * intentionally harmless probes even if the restriction regresses.
     */
    const char *blocked[] = {
        "system('true')", "base::identity(1)", "base:::identity(1)",
        "get('identity')", "getNamespace('base')", "library(base)",
        ".GlobalEnv", "globalenv()", "environment()", "parent.frame()",
        "eval(1)", "quote(1)", ".Internal(inspect(NULL))",
        ".Call('eval_harness_nonexistent_symbol')", "file()", "quit()",
        "options(warn = 0)", "setTimeLimit(cpu = Inf)", "x <<- 1",
        "attr(1, 'class') <- 'example'"
    };
    for (size_t i = 0; i < sizeof(blocked) / sizeof(*blocked); i++)
        check(blocked[i], 1, 0);
    assert(!R_existsVarInFrame(R_GlobalEnv, Rf_install("x")));

    /* Warnings are suppressed (options(warn = -1) in fuzz_init_r), never
     * turned into errors: an error raised from inside C code would unwind
     * past its allocations and show up as a leak.  options() is unbound, so
     * the input cannot change that. */
    check("is.na(as.integer('a'))", 0, 1);
    check("is.na(2147483647L + 1L)", 0, 1);
    check("length(1:3 + 1:2)", 0, 3);
    check("f <- function() as.integer('a'); is.na(f())", 0, 1);

    check("if (", 1, 0);
    check("missing_name + 1", 1, 0);
    /* The 8Mb vector heap: a 4MB vector fits, a 16MB one is refused before
     * allocation, both as ordinary R errors. */
    check("x <- 1; x[500000] <- 1; length(x)", 0, 500000);
    check("x <- 1; x[2000000] <- 1", 1, 0);
    check("x <- 1; x[100000000] <- 1", 1, 0);

    /* Runaway inputs: an infinite loop is stopped by the evaluation budget,
     * unbounded recursion by R's expression or C stack limit -- all as R
     * errors, and the next input is unaffected.  Repeated, because the
     * budget and the stack checks must recover as well as fire. */
    for (int i = 0; i < 3; i++) {
        check("repeat {}", 1, 0);
        check("i <- 0; while (TRUE) i <- i + 1", 1, 0);
        /* The fuzzer's own find: one evaluation per heap-sized vector op,
         * which the small heap and the CPU backstop keep to seconds. */
        check("x <- !1:40000; repeat !x", 1, 0);
        check("x <- !1:999999; repeat !x", 1, 0);
        check("f <- function() f(); f()", 1, 0);
        check("f <- function(n) if (n > 0) f(n - 1) else 0; f(100000)", 1, 0);
        check("40 + 2", 0, 42);
        R_gc();
    }

    /* Deep C recursion that R does not stack-check (bind.c, deparse.c)
     * over a list an input can build within the budget: the R thread's
     * stack absorbs it, so these complete rather than overflow.  deparse
     * of such a value is quadratic in the depth; instrumentation/0005
     * makes it poll, so the budget ends it as an R error instead of a
     * timeout, while a depth deparse can handle still completes. */
    const char *nest =
        "x <- list(); for (i in 1:15000) "
        "x <- list(list(list(list(list(list(list(list(x)))))))); ";
    char deep_source[512];
    snprintf(deep_source, sizeof(deep_source), "%s%s", nest, "length(c(x, recursive = TRUE))");
    check(deep_source, 0, 0);
    snprintf(deep_source, sizeof(deep_source), "%s%s", nest, "length(c(x, x)[[1]])");
    check(deep_source, 0, 1);
    snprintf(deep_source, sizeof(deep_source), "%s%s", nest, "as.character(x)");
    check(deep_source, 1, 0);
    check("x <- list(); for (i in 1:2000) x <- list(x); length(as.character(x))", 0, 1);
    /* And R's own check still fires, as an R error, for recursion it sees. */
    check("f <- function(n) if (n > 0) f(n - 1) else 0; f(100000)", 1, 0);
    assert(R_CStackLimit == (uintptr_t)(0.95 * FUZZ_R_STACK_SIZE));

    /* The budget bounds work, not time: a loop that fits runs to the end,
     * and the same input gives the same answer every time. */
    for (int i = 0; i < 3; i++)
        check("x <- 0; for (i in 1:20000) x <- x + 1; x", 0, 20000);

    /* `:` is a length-capped wrapper: long compact sequences are refused
     * before a reduction can walk them, short ones behave as usual, and
     * the wrapper's private environment stays out of reach. */
    check("length(1:1000000)", 0, 1000000);
    check("1:1000001", 1, 0);
    check("prod(1:1000000000)", 1, 0);
    check("max(1:1000000000, 1L)", 1, 0);
    check("(3:1)[1]", 0, 3);
    check("f <- `:`; f(2, 4)[2]", 0, 3);
    check("`:`(1, 3)[3]", 0, 3);
    check("1:NA", 1, 0);
    check("1:'a'", 1, 0);
    check(".colon(1, 2)", 1, 0);
    check(".Internal(stop(TRUE, 'x'))", 1, 0);

    /* Byte-code: closures are created with compiled bodies, top-level
     * loops are compiled, and every bound above holds on that path too. */
    check_compiled("function(x) x + 1");
    check_compiled("f <- function(n) { s <- 0; for (i in 1:n) if (i %% 2 == 0) s <- s + i; s }; f");
    check("f <- function(n) { s <- 0; for (i in 1:n) if (i %% 2 == 0) s <- s + i; s }; f(10)", 0, 30);
    check("f <- function() { x <- 0; for (i in 1:5) { if (i == 3) break; x <- i }; x }; f()", 0, 2);
    check("f <- function(x, ...) length(list(...)); f(1, 2, 3)", 0, 2);
    check("f <- function() g(); f()", 1, 0);
    check("f <- function() repeat {}; f()", 1, 0);
    check("f <- function() prod(1:1000000000); f()", 1, 0);
    check("f <- function() length(1:1000000); f()", 0, 1000000);
    check("f <- function() { x <- !1:999999; repeat !x }; f()", 1, 0);
    check("f <- function() { x <- 1; x[2000000] <- 1 }; f()", 1, 0);
    assert(R_ToplevelExec(check_loop_jump, NULL));

    /* Construct the tree directly: older R parsers can fail on deep syntax
     * before our post-parse guard is reached. This check is for the guard.
     */
    SEXP deep = R_NilValue;
    PROTECT_INDEX deep_index;
    PROTECT_WITH_INDEX(deep, &deep_index);
    for (unsigned i = 0; i <= FUZZ_MAX_DEPTH; i++)
        REPROTECT(deep = Rf_lang2(Rf_install("("), deep), deep_index);
    unsigned nodes = 0;
    assert(!eval_tree_within_budget(deep, 0, &nodes));
    Rf_unprotect(1);
    nodes = FUZZ_MAX_NODES;
    assert(!eval_tree_within_budget(R_NilValue, 0, &nodes));

    const uint8_t nul[] = { '1', 0, '+', '2' };
    const uint8_t invalid_utf8[] = { 0xf0, 0x80, 0x80, 0x80 };
    const uint8_t valid_utf8[] = { 0xf0, 0x9f, 0x98, 0x80 };
    assert(!eval_valid_utf8(invalid_utf8, sizeof(invalid_utf8)));
    assert(eval_valid_utf8(valid_utf8, sizeof(valid_utf8)));
    LLVMFuzzerTestOneInput(nul, sizeof(nul));
    LLVMFuzzerTestOneInput(invalid_utf8, sizeof(invalid_utf8));
    LLVMFuzzerTestOneInput(nul, 0);
    LLVMFuzzerTestOneInput(nul, FUZZ_MAX_INPUT + 1);
    check("40 + 2", 0, 42);
    puts("eval harness checks passed");
}

/* AFL++'s driver forks its forkserver after LLVMFuzzerInitialize, so
 * every input runs in a child that inherited the initialized R but not
 * the R thread.  The child must grow a new one, with R's stack check
 * pointed at it, rather than wait forever on the old. */
static void run_forked_checks(void *unused)
{
    (void)unused;
    assert(R_CStackStart == fuzz_r_thread.stack_top);
    check("40 + 2", 0, 42);
    check("f <- function(n) if (n > 0) f(n - 1) else 0; f(100000)", 1, 0);
    check("x <- list(); for (i in 1:20000) x <- list(x); "
          "length(c(x, recursive = TRUE))", 0, 0);
    const uint8_t source[] = "1 + 1";
    LLVMFuzzerTestOneInput(source, sizeof(source) - 1);
    check("40 + 2", 0, 42);
}

static void check_after_fork(void)
{
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        fuzz_run_on_r_thread(run_forked_checks, NULL);
        exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    /* And the parent's R thread is untouched. */
    fuzz_run_on_r_thread(run_forked_checks, NULL);
    puts("eval harness fork checks passed");
}

int main(int argc, char **argv)
{
    LLVMFuzzerInitialize(&argc, &argv);
    /* The checks call R directly, so they run where R does. */
    fuzz_run_on_r_thread(run_checks, NULL);
    check_after_fork();
    return 0;
}
