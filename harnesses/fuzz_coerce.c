/*
 * libFuzzer harness for R's type coercion / string-to-X parsing.
 *
 * Passes fuzzed input as a character string through R's type conversion
 * functions: as.numeric (R_strtod4), as.complex (complex number parsing),
 * as.logical, and type.convert (auto-detection).
 *
 * Adapted from r-afl's coerce harness.
 */

#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 4

static SEXP x_str;
static SEXP calls[N_CALLS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_init_r();

    SEXP sym_as_numeric   = Rf_install("as.numeric");
    SEXP sym_as_complex   = Rf_install("as.complex");
    SEXP sym_as_logical   = Rf_install("as.logical");
    SEXP sym_type_convert = Rf_install("type.convert");

    SEXP true_val;
    Rf_protect(true_val = Rf_ScalarLogical(TRUE));

    /* Pre-build reusable string container and all call objects. */
    Rf_protect(x_str = Rf_allocVector(STRSXP, 1));

    /* as.numeric(x) -- exercises R_strtod4 */
    Rf_protect(calls[0] = Rf_lang2(sym_as_numeric, x_str));

    /* as.complex(x) -- exercises complex number parsing (a+bi) */
    Rf_protect(calls[1] = Rf_lang2(sym_as_complex, x_str));

    /* as.logical(x) -- exercises logical string matching */
    Rf_protect(calls[2] = Rf_lang2(sym_as_logical, x_str));

    /* type.convert(x, as.is=TRUE) -- auto-detection heuristic */
    Rf_protect(calls[3] = Rf_lang3(sym_type_convert, x_str, true_val));
    SET_TAG(CDDR(calls[3]), Rf_install("as.is"));

    /* Warmup: prime coercion code paths. */
    {
        int error = 0;
        SET_STRING_ELT(x_str, 0, Rf_mkChar("1"));
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

    fuzz_eval_data_t ed = { .env = R_GlobalEnv };

    SET_STRING_ELT(x_str, 0, Rf_mkChar(buf));

    for (int i = 0; i < N_CALLS; i++) {
        ed.call = calls[i];
        R_ToplevelExec(fuzz_do_eval, &ed);
    }

    return 0;
}
