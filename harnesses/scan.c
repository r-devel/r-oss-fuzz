/*
 * libFuzzer harness for R's scan / delimited-text parser.
 *
 * Feeds fuzzed input to scan() as text with several type/separator
 * configurations, exercising the C-level parsing state machine in
 * src/main/scan.c: field separation, quoting, escapes, comment chars,
 * NA-string matching, and type coercion.  R's equivalent of a
 * csv.reader target.
 *
 * Adapted from r-afl's scan harness.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 4

static SEXP x_text;
static SEXP calls[N_CALLS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_init_r();

    SEXP sym_scan = Rf_install("scan");

    SEXP str_empty, str_comma, str_tab, val_zero, val_true;
    Rf_protect(str_empty = Rf_mkString(""));
    Rf_protect(str_comma = Rf_mkString(","));
    Rf_protect(str_tab   = Rf_mkString("\t"));
    Rf_protect(val_zero  = Rf_ScalarReal(0.0));
    Rf_protect(val_true  = Rf_ScalarLogical(TRUE));

    /* Reusable text container -- each iteration swaps its CHARSXP. */
    Rf_protect(x_text = Rf_allocVector(STRSXP, 1));

    /* [0] scan(text=x, what="", quiet=TRUE) -- whitespace separated */
    Rf_protect(calls[0] = Rf_lang4(sym_scan, x_text, str_empty, val_true));
    SET_TAG(CDR(calls[0]),   Rf_install("text"));
    SET_TAG(CDDR(calls[0]),  Rf_install("what"));
    SET_TAG(CDDDR(calls[0]), Rf_install("quiet"));

    /* [1] scan(text=x, what=0, quiet=TRUE) -- numeric reading */
    Rf_protect(calls[1] = Rf_lang4(sym_scan, x_text, val_zero, val_true));
    SET_TAG(CDR(calls[1]),   Rf_install("text"));
    SET_TAG(CDDR(calls[1]),  Rf_install("what"));
    SET_TAG(CDDDR(calls[1]), Rf_install("quiet"));

    /* [2] scan(text=x, what="", sep=",", quiet=TRUE) -- CSV */
    Rf_protect(calls[2] = Rf_lang5(sym_scan, x_text, str_empty,
                                   val_true, str_comma));
    SET_TAG(CDR(calls[2]),        Rf_install("text"));
    SET_TAG(CDDR(calls[2]),       Rf_install("what"));
    SET_TAG(CDDDR(calls[2]),      Rf_install("quiet"));
    SET_TAG(CDR(CDDDR(calls[2])), Rf_install("sep"));

    /* [3] scan(text=x, what="", sep="\t", quiet=TRUE) -- TSV */
    Rf_protect(calls[3] = Rf_lang5(sym_scan, x_text, str_empty,
                                   val_true, str_tab));
    SET_TAG(CDR(calls[3]),        Rf_install("text"));
    SET_TAG(CDDR(calls[3]),       Rf_install("what"));
    SET_TAG(CDDDR(calls[3]),      Rf_install("quiet"));
    SET_TAG(CDR(CDDDR(calls[3])), Rf_install("sep"));

    /* Warmup: prime scan's type-dispatch and locale state. */
    {
        int error = 0;
        SET_STRING_ELT(x_text, 0, Rf_mkChar("1,2,3"));
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

    if (!fuzz_set_string(x_text, buf))
        return 0;

    fuzz_eval_data_t ed = { .env = R_GlobalEnv };
    for (int i = 0; i < N_CALLS; i++) {
        ed.call = calls[i];
        R_ToplevelExec(fuzz_do_eval, &ed);
    }

    return 0;
}
