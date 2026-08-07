/*
 * libFuzzer harness for R's approximate string matching (agrep).
 *
 * Uses fuzzed input as a pattern passed to agrep() and agrepl(),
 * exercising TRE's approximate-matching engine (edit-distance
 * computation) -- a distinct code path from the exact matching covered
 * by the grep harness, and the source of a previously found TRE
 * heap-buffer-overflow.
 *
 * Adapted from r-afl's agrep harness.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 3

static SEXP x_pat;
static SEXP calls[N_CALLS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_init_r();

    SEXP sym_agrep  = Rf_install("agrep");
    SEXP sym_agrepl = Rf_install("agrepl");

    /* Fixed strings to match the fuzzed pattern against. */
    SEXP x;
    Rf_protect(x = Rf_allocVector(STRSXP, 5));
    SET_STRING_ELT(x, 0, Rf_mkChar("hello world"));
    SET_STRING_ELT(x, 1, Rf_mkChar("foo bar baz 123"));
    SET_STRING_ELT(x, 2, Rf_mkChar("the quick brown fox jumps over the lazy dog"));
    SET_STRING_ELT(x, 3, Rf_mkChar("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"));
    SET_STRING_ELT(x, 4, Rf_mkChar(""));

    /* max.distance=0.3 -- allow ~30% edit distance. */
    SEXP max_dist;
    Rf_protect(max_dist = Rf_ScalarReal(0.3));

    /* Reusable pattern container -- each iteration swaps its CHARSXP. */
    Rf_protect(x_pat = Rf_allocVector(STRSXP, 1));

    SEXP false_val;
    Rf_protect(false_val = Rf_ScalarLogical(FALSE));

    /* [0] agrep(pattern, x, max.distance=0.3) -- literal approximate */
    Rf_protect(calls[0] = Rf_lang4(sym_agrep, x_pat, x, max_dist));
    SET_TAG(CDDDR(calls[0]), Rf_install("max.distance"));

    /* [1] agrepl(pattern, x, max.distance=0.3) -- logical variant */
    Rf_protect(calls[1] = Rf_lang4(sym_agrepl, x_pat, x, max_dist));
    SET_TAG(CDDDR(calls[1]), Rf_install("max.distance"));

    /* [2] agrep(pattern, x, fixed=FALSE) -- regex approximate */
    Rf_protect(calls[2] = Rf_lang4(sym_agrep, x_pat, x, false_val));
    SET_TAG(CDDDR(calls[2]), Rf_install("fixed"));

    /* Warmup: prime TRE's approximate-matching engine. */
    {
        int error = 0;
        SET_STRING_ELT(x_pat, 0, Rf_mkChar("hello"));
        for (int i = 0; i < N_CALLS; i++) {
            R_tryEval(calls[i], R_GlobalEnv, &error);
            error = 0;
        }
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_MAX_INPUT)
        return 0;

    char buf[FUZZ_MAX_INPUT + 1];
    memcpy(buf, data, size);
    buf[size] = '\0';

    /* TRE compiles bounded repeats by AST duplication; unbounded nesting
     * has cost 8.5GB from a 36-byte pattern.  See common.h. */
    if (fuzz_repeat_product_excessive(buf))
        return 0;

    if (!fuzz_set_string(x_pat, buf))
        return 0;

    fuzz_eval_data_t ed = { .env = R_GlobalEnv };
    for (int i = 0; i < N_CALLS; i++) {
        ed.call = calls[i];
        R_ToplevelExec(fuzz_do_eval, &ed);
    }

    return 0;
}
