/*
 * Evaluate R source in a fresh environment with selected primitives only.
 *
 * This is a restricted evaluator, NOT a security sandbox. Run it inside an
 * externally isolated worker (see scripts/run-eval.sh). The allowlist keeps
 * ordinary inputs away from I/O, native calls, namespace loading, reflection,
 * and process-global state. It cannot contain a bug in the interpreter.
 */

#define FUZZ_R_MAX_VSIZE "64Mb"
#include "common.h"

#define FUZZ_MAX_INPUT 8192
#define FUZZ_MAX_DEPTH 64
#define FUZZ_MAX_NODES 1024

static SEXP eval_builtins;
static SEXP eval_limit;
static SEXP eval_unlimit;

/* Only primitives: importing a base closure would also import its enclosing
 * namespace and the capabilities reachable through its implementation.
 * No class/attribute setters or reflection/metaprogramming APIs are exposed.
 * Closures created by the input inherit only the restricted environment.
 */
static const char *const eval_primitives[] = {
    "{", "(", "if", "for", "while", "repeat", "break", "next",
    "function", "return", "<-", "=",
    "+", "-", "*", "/", "^", "%%", "%/%", ":",
    "==", "!=", "<", "<=", ">", ">=", "!", "&", "|", "&&", "||",
    "c", "list", "[", "[[", "$", "[<-", "[[<-", "$<-",
    "length", "is.null", "is.logical", "is.integer", "is.double",
    "is.complex", "is.character", "is.list", "is.na", "is.nan", "is.finite",
    "is.infinite", "as.integer", "as.double", "as.logical", "as.character",
    "as.complex", "as.raw", "abs", "sqrt", "floor", "ceiling", "trunc",
    "sum", "prod", "min", "max", "any", "all", "invisible"
};

typedef struct {
    const uint8_t *data;
    size_t size;
} eval_input_t;

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

    Rf_protect(env = R_NewEnv(eval_builtins, TRUE, 29));
    R_tryEvalSilent(eval_limit, R_BaseEnv, error);
    if (!*error) {
        for (R_xlen_t i = 0; i < XLENGTH(parsed); i++) {
            result = R_tryEvalSilent(VECTOR_ELT(parsed, i), env, error);
            if (*error)
                break;
        }
    }
    Rf_unprotect(3);
    return *error ? R_NilValue : result;
}

static void eval_one(void *data)
{
    int error = 0;
    eval_source((const eval_input_t *)data, &error);
}

static void eval_reset_limit(void *data)
{
    (void)data;
    int error = 0;
    R_tryEvalSilent(eval_unlimit, R_BaseEnv, &error);
    if (error)
        abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    /* Keep this target focused on interpreted evaluation. Avoid loading
     * optional packages and compiler state into a persistent worker.
     */
    setenv("R_ENABLE_JIT", "0", 1);
    setenv("R_DEFAULT_PACKAGES", "NULL", 1);
    fuzz_init_r();

    Rf_protect(eval_builtins = R_NewEnv(R_EmptyEnv, TRUE, 97));
    for (size_t i = 0; i < sizeof(eval_primitives) / sizeof(*eval_primitives); i++) {
        SEXP name = Rf_install(eval_primitives[i]);
        SEXP value = Rf_findFun(name, R_BaseEnv);
        if (TYPEOF(value) != BUILTINSXP && TYPEOF(value) != SPECIALSXP) {
            fprintf(stderr, "eval: %s is no longer a primitive\n", eval_primitives[i]);
            abort();
        }
        Rf_defineVar(name, value, eval_builtins);
    }
    R_LockEnvironment(eval_builtins, TRUE);

    /* Trusted calls, inaccessible to the input. Limits are cooperative R
     * interrupt checks; the worker still needs an external hard deadline.
     * A single budget covers all top-level expressions in an input.
     */
    SEXP limit_fun, cpu, elapsed, transient, infinity;
    Rf_protect(limit_fun = Rf_findFun(Rf_install("setTimeLimit"), R_BaseEnv));
    Rf_protect(cpu = Rf_ScalarReal(0.05));
    Rf_protect(elapsed = Rf_ScalarReal(0.1));
    Rf_protect(transient = Rf_ScalarLogical(TRUE));
    Rf_protect(infinity = Rf_ScalarReal(R_PosInf));
    eval_limit = Rf_lang4(limit_fun, cpu, elapsed, transient);
    R_PreserveObject(eval_limit);
    eval_unlimit = Rf_lang4(limit_fun, infinity, infinity, transient);
    R_PreserveObject(eval_unlimit);
    Rf_unprotect(5);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_MAX_INPUT || memchr(data, '\0', size) ||
        !eval_valid_utf8(data, size))
        return 0;

    eval_input_t input = { data, size };
    R_ToplevelExec(eval_one, &input);
    /* Run even after a longjmp; a timed-out input must not poison the next. */
    if (!R_ToplevelExec(eval_reset_limit, NULL))
        abort();
    return 0;
}
