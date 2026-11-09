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

typedef struct {
    const char *source;
    const char *instruction;
    int expected;
} ops_check_t;

/* Whether the byte-code the sandbox's compiler produces for source names
 * the instruction: the base-like frame makes the compiler inline what it
 * finds there, and the wrappers frame keeps it from inlining past a cap. */
static void check_ops_source(void *data)
{
    const ops_check_t *check = data;
    SEXP env, fn, call, result;
    Rf_protect(env = R_NewEnv(eval_wrappers, TRUE, 29));
    Rf_protect(fn = R_ParseEvalString(
        "function(env, source, instruction) {\n"
        "    code <- compiler::compile(parse(text = source)[[1L]], env)\n"
        "    ops <- paste(deparse(compiler::disassemble(code)), collapse = \"\")\n"
        "    grepl(instruction, ops, fixed = TRUE)\n"
        "}", R_BaseEnv));
    Rf_protect(call = Rf_lang4(fn, env, Rf_mkString(check->source),
                               Rf_mkString(check->instruction)));
    result = Rf_eval(call, R_BaseEnv);
    if (Rf_asLogical(result) != check->expected) {
        fprintf(stderr, "%s %s in the byte-code of: %s\n",
                check->expected ? "expected" : "did not expect",
                check->instruction, check->source);
        abort();
    }
    Rf_unprotect(3);
}

static void check_ops(const char *source, const char *instruction, int expected)
{
    ops_check_t check = { source, instruction, expected };
    assert(R_ToplevelExec(check_ops_source, &check));
}

/* The allowlist frame's attributes are the one name the compiler keys on,
 * whatever an input did to .GenericDefEnv. */
static void check_builtins_name(void)
{
    SEXP fn, call, result;
    Rf_protect(fn = R_ParseEvalString(
        "function(env) identical(attributes(env), list(name = 'package:base')) && "
        "!is.object(env)", R_BaseEnv));
    Rf_protect(call = Rf_lang2(fn, eval_builtins));
    result = Rf_eval(call, R_BaseEnv);
    assert(Rf_asLogical(result) == TRUE);
    Rf_unprotect(2);
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
    check_builtins_name();
}

/* An input that must end, and how long it took: the on.exit grace is a
 * bound on work, so the time is printed rather than asserted. */
static void check_timed(const char *source)
{
    clock_t start = clock();
    check(source, 1, 0);
    fprintf(stderr, "  %.2fs  %s\n", (double)(clock() - start) / CLOCKS_PER_SEC, source);
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
        "eval(1)", "eval(quote(1))", ".Internal(inspect(NULL))",
        ".Call('eval_harness_nonexistent_symbol')", "file()", "quit()",
        "options(warn = 0)", "setTimeLimit(cpu = Inf)", "x <<- 1",
        "x <- 1; attr(x, 'class') <- 'example'",
        "x <- 1; attributes(x) <- list(class = 'example')",
        "x <- 1; attributes(x) <- list(names = 'a', class = 'example')",
        "x <- 1; class(x) <- 'example'", "x <- 1; oldClass(x) <- 'example'",
        "f <- function(x) UseMethod('f'); f.default <- function(x) NextMethod(); f(1)",
        "inherits(1, 'numeric')", "environment(sum)", "sys.call()",
        "sys.function()", "parent.frame()", "Recall()", "standardGeneric('f')",
        "forceAndCall(1, sum, 1)", ".seq_len(1)", ".seq_int(1, 2)",
        ".attr_set(1, 'a', 1)", ".attributes_set(1, NULL)", ".colon(1, 2)"
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

    /* The compiler runs under the budget too.  Its constant folding is
     * quadratic in nesting depth: a chain of 62 unary pluses costs about
     * 20000 interrupt checks to compile (one second under ASAN), so four
     * of them, within the tree limits, used to run for several seconds
     * with the budget paused.  Now the budget ends the input inside the
     * compiler, and a shallower chain still compiles and runs. */
    char chain[128], chains_source[640];
    snprintf(chain, sizeof(chain), "x%.*sy\n", 62, "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
    snprintf(chains_source, sizeof(chains_source), "x <- 1; y <- 2\n%s%s%s%s", chain, chain, chain, chain);
    for (int i = 0; i < 2; i++) {
        check(chains_source, 1, 0);
        check("x <- 1; y <- 2; x++++++++++++++++++++y", 0, 3);
    }

    /* Language objects are inert: substitute() and quote() hand back calls
     * the input can take apart but never run. */
    check("length(quote(f(x)))", 0, 2);
    check("f <- function(x) substitute(x); length(f(a + b))", 0, 3);
    check("f <- function(x) substitute(x); length(f(system('true')))", 0, 2);
    check("f <- function(x) substitute(x); e <- f(system('true')); e[[1]] <- quote(c); length(e)", 0, 2);
    check("e <- quote(f(x)); e[[1]] <- quote(sum); e[[2]] <- 3; length(e)", 0, 2);
    check("all(quote(x))", 1, 0);
    check("as.character(quote(x)) == 'x'", 0, 1);
    check("x <- quote(y); as.character(x) == 'y'", 0, 1);

    /* missing(), nargs(), switch() and on.exit() behave as in a session. */
    check("f <- function(x, y) missing(y) + nargs(); f(1)", 0, 2);
    check("f <- function(x) switch(x, a = 1, b = , c = 3, 9); f('b') + f('z')", 0, 12);
    check("is.null(switch('z', a = 1))", 0, 1);
    check("switch(2, 1, 2, 3)", 0, 2);
    check("f <- function() { on.exit(return(x + 1)); x <- 10; 0 }; f()", 0, 11);
    check("f <- function() { on.exit(x <- 1); on.exit(x <- 2, add = TRUE); x <- 0; invisible(x) }; f()", 0, 0);

    /* on.exit code runs during the unwind the budget error starts, with
     * the check reloaded: a loop there ends too, however many frames set
     * one, and whichever limit fired first. */
    check_timed("f <- function() { on.exit(repeat {}); repeat {} }; f()");
    check_timed("f <- function() { on.exit(repeat {}, add = TRUE); on.exit(repeat {}, add = TRUE); repeat {} }; f()");
    check_timed("g <- function(n) { on.exit(repeat {}); if (n > 0) g(n - 1) else repeat {} }; g(200)");
    check_timed("f <- function() { on.exit(repeat {}); x <- !1:999999; repeat !x }; f()");
    check_timed("f <- function() { on.exit({ x <- !1:999999; repeat !x }); repeat {} }; f()");
    check_timed("f <- function() { on.exit(f()); repeat {} }; f()");
    check("40 + 2", 0, 42);
    check("x <- 0; for (i in 1:20000) x <- x + 1; x", 0, 20000);

    /* Attributes other than class, through the primitives and through
     * attr<-, which refuses only the class attribute, by exact name. */
    check("x <- 1:3; names(x) <- c('a', 'b', 'c'); x[['b']]", 0, 2);
    check("x <- 1:4; dim(x) <- c(2, 2); x[2, 1]", 0, 2);
    check("x <- 1:4; dim(x) <- c(2, 2); dimnames(x) <- list(c('a', 'b'), NULL); x['b', 1]", 0, 2);
    check("x <- 1; attr(x, 'foo') <- 2; attr(x, 'foo')", 0, 2);
    check("x <- 1; attr(x, 'cls') <- 'foo'; attr(x, 'cls') == 'foo'", 0, 1);
    check("x <- 1:2; attributes(x) <- list(names = c('a', 'b')); names(x)[2] == 'b'", 0, 1);
    check("x <- 1:2; attributes(x) <- NULL; is.null(names(x))", 0, 1);
    check("x <- 1:2; levels(x) <- c('a', 'b'); length(attr(x, 'levels'))", 0, 2);
    check("x <- 1; levels(x) <- 'a'; class(x) == 'numeric'", 0, 1);
    check("x <- 1:4; attr(x, 'dim') <- c(2, 2); length(dim(x))", 0, 2);
    check("is.null(attr(1, 'class')) + is.null(oldClass(1)) + is.null(attributes(1))", 0, 3);
    check("class(1) == 'numeric'", 0, 1);
    check("x <- 1:4; dim(x) <- c(2, 2); class(x)[1] == 'matrix'", 0, 1);
    check("unclass(1)", 0, 1);
    check("x <- 1:3; names(x) <- 'a'; is.na(names(x)[3])", 0, 1);
    check("x <- 1:3; dim(x) <- 2", 1, 0);
    check("x <- 1; attr(x, c('a', 'b')) <- 1", 1, 0);
    check("x <- 1; attr(x, NA) <- 1", 1, 0);
    check("f <- function() 1; attr(f, 'a') <- 2; attr(f, 'a') + f()", 0, 3);

    /* S3 dispatch on the implicit class, to methods the input defines and
     * nothing else; the dispatch variables are set; .GenericDefEnv is the
     * locked allowlist frame, whose attributes do not survive the input. */
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) 1; "
          "foo.numeric <- function(x) 2; foo(1) + 10 * foo('a')", 0, 12);
    check("foo <- function(x) UseMethod('foo'); foo.function <- function(x) 3; foo(foo)", 0, 3);
    check("foo <- function(x) UseMethod('foo'); foo.matrix <- function(x) 4; "
          "x <- 1:4; dim(x) <- c(2, 2); foo(x)", 0, 4);
    check("foo <- function(x) UseMethod('foo'); foo.integer <- function(x) 5; "
          "foo.numeric <- function(x) 6; foo(1L) + 10 * foo(1)", 0, 65);
    check("foo <- function(x, ...) UseMethod('foo'); foo.default <- function(x, ...) length(list(...)); foo(1, 2, 3)", 0, 2);
    check("foo <- function(x) UseMethod('foo'); foo(1)", 1, 0);
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) .Generic == 'foo'; foo(1)", 0, 1);
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) length(.Class); foo(1)", 0, 0);
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) .GenericDefEnv$c(1, 2)[2]; foo(1)", 0, 2);
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) { .GenericDefEnv$x <- 1; 1 }; foo(1)", 1, 0);
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) { .GenericDefEnv[['sum']] <- 1; 1 }; foo(1)", 1, 0);
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) { attr(.GenericDefEnv, 'name') <- 'x'; 1 }; foo(1)", 0, 1);
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) { attributes(.GenericDefEnv) <- NULL; 1 }; foo(1)", 0, 1);
    /* ... and a 3 MB one is gone before the next input needs 4 MB of the
     * 8 MB heap (base R holds about 1 MB of it). */
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) { attr(.GenericDefEnv, 'junk') <- rep(1, 375000); 1 }; foo(1)", 0, 1);
    check("x <- 1; x[500000] <- 1; length(x)", 0, 500000);
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) { .GenericCallEnv$y <- 7; 1 }; foo(1); y", 0, 7);
    check("foo <- function(x) UseMethod('foo'); foo.default <- function(x) { on.exit(repeat {}); repeat {} }; foo(1)", 1, 0);
    /* Internal generics do not dispatch without a class attribute, so
     * base's own S3 methods stay out of reach. */
    check("x <- 1:4; dim(x) <- c(2, 2); length(x)", 0, 4);
    check("x <- list(a = 1); levels(x) <- 'z'; x$a", 0, 1);

    /* The compact sequence builders are capped on their result; rep()
     * allocates, so the heap bounds it. */
    check("length(seq_len(1000000))", 0, 1000000);
    check("seq_len(1000001)", 1, 0);
    check("prod(seq_len(1000000000))", 1, 0);
    check("seq_len(-1)", 1, 0);
    check("length(seq.int(1, 10))", 0, 10);
    check("seq.int(1, 3)[3]", 0, 3);
    check("length(seq.int(0, 1, by = 0.25))", 0, 5);
    check("seq.int(1, 1000000000)", 1, 0);
    check("seq.int(1, 1000000000, by = 1)", 1, 0);
    check("seq.int(length.out = 10000000)", 1, 0);
    check("seq.int(1, 1000000000, length.out = 1000000000)", 1, 0);
    check("sum(seq.int(1, 1000000000), 1)", 1, 0);
    check("f <- function() prod(seq_len(1000000000)); f()", 1, 0);
    check("f <- function() max(seq.int(1, 1000000000), 1L); f()", 1, 0);
    check("length(rep(1:2, 3))", 0, 6);
    check("rep(1L, 1000000000)", 1, 0);
    check("rep(1:2, length.out = 1000000000)", 1, 0);
    check("length(seq_along(c(1, 2, 3)))", 0, 3);

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
    /* `:` takes the first element of a longer argument, and coerces a
     * character one; the cap must see those the same way. */
    check("c(1e12, 1):5", 1, 0);
    check("1:c(1e12, 1)", 1, 0);
    check("sum(1, -c(9999, 1)^3:9991)", 1, 0);
    check("'1':'1e9'", 1, 0);
    check("length(c(2, 9):4)", 0, 3);
    check("length('1':'3')", 0, 3);
    check(".colon(1, 2)", 1, 0);
    check(".Internal(stop(TRUE, 'x'))", 1, 0);

    /* The warm-up input exercises the new surface too, and must not have
     * been failing silently. */
    check(eval_warmup_source, 0, 2);

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
    /* A loop with a conditional break compiles to a jump, not a loop
     * context, only while the isBaseVar rebinding in eval_compiler_setup
     * takes; names in the base-like frame are inlined, the wrappers are
     * called. */
    check_ops("for (i in 1:3) if (i == 2) break", "STARTFOR", 1);
    check_ops("for (i in 1:3) if (i == 2) break", "STARTLOOPCNTXT", 0);
    check_ops("seq_along(x)", "SEQALONG", 1);
    check_ops("switch(x, a = 1, 2)", "SWITCH", 1);
    check_ops("x + 1", "ADD", 1);
    check_ops("1:3", "COLON", 0);
    check_ops("seq_len(3)", "SEQLEN", 0);
    check_ops("prod(seq_len(1))", "LDCONST", 0);
    check_ops("prod(seq_along(1))", "LDCONST", 1);

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
