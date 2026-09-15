/* Standalone behavioral checks; include the harness to test its boundaries. */
#include <assert.h>
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
        abort();
    }
    if (!error) {
        assert(XLENGTH(result) == 1);
        assert(Rf_asReal(result) == check->expected);
    }
    Rf_unprotect(1);
}

static void check(const char *source, int expect_error, double expected)
{
    eval_check_t test = { source, expect_error, expected };
    Rboolean completed = R_ToplevelExec(check_source, &test);
    if (!completed && !expect_error) {
        fprintf(stderr, "unexpected top-level error for: %s\n", source);
        abort();
    }
    assert(R_ToplevelExec(eval_reset_limit, NULL));
}

int main(int argc, char **argv)
{
    LLVMFuzzerInitialize(&argc, &argv);
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

    check("if (", 1, 0);
    check("missing_name + 1", 1, 0);
    /* Exceeds the harness's 64Mb vector heap, before allocating the vector. */
    check("x <- 1; x[100000000] <- 1", 1, 0);
    for (int i = 0; i < 3; i++) {
        check("repeat {}", 1, 0);
        check("f <- function() f(); f()", 1, 0);
        check("40 + 2", 0, 42);
        R_gc();
    }

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
    return 0;
}
