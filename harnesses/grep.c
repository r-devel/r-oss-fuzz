/*
 * libFuzzer harness for R's regex engine.
 *
 * Uses fuzzed input as a regex pattern passed to grep() -- exercising
 * both the TRE (default) and PCRE2 (perl=TRUE) regex backends, plus
 * sub() for substitution.
 *
 * Adapted from r-afl's grep harness.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)

static SEXP x_pat;
static SEXP call_grep_tre;
static SEXP call_grep_pcre;
static SEXP call_sub;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_init_r();

    /* Fixed strings to match the fuzzed pattern against. */
    SEXP x;
    Rf_protect(x = Rf_allocVector(STRSXP, 5));
    SET_STRING_ELT(x, 0, Rf_mkChar("hello world"));
    SET_STRING_ELT(x, 1, Rf_mkChar("foo bar baz 123"));
    SET_STRING_ELT(x, 2, Rf_mkChar("the quick brown fox jumps over the lazy dog"));
    SET_STRING_ELT(x, 3, Rf_mkChar("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"));
    SET_STRING_ELT(x, 4, Rf_mkChar(""));

    /* Reusable pattern container -- each iteration swaps the CHARSXP. */
    Rf_protect(x_pat = Rf_allocVector(STRSXP, 1));

    SEXP replacement;
    Rf_protect(replacement = Rf_mkString("X"));

    SEXP perl_true;
    Rf_protect(perl_true = Rf_ScalarLogical(TRUE));

    SEXP sym_grep = Rf_install("grep");
    SEXP sym_sub  = Rf_install("sub");

    /* grep(pattern, x) -- TRE regex engine */
    Rf_protect(call_grep_tre = Rf_lang3(sym_grep, x_pat, x));

    /* grep(pattern, x, perl=TRUE) -- PCRE2 engine */
    Rf_protect(call_grep_pcre = Rf_lang4(sym_grep, x_pat, x, perl_true));
    SET_TAG(CDDDR(call_grep_pcre), Rf_install("perl"));

    /* sub(pattern, "X", x) -- TRE substitution */
    Rf_protect(call_sub = Rf_lang4(sym_sub, x_pat, replacement, x));

    /* Warmup: prime regex engine state before fuzzing. */
    {
        int error = 0;
        SET_STRING_ELT(x_pat, 0, Rf_mkChar("x"));
        R_tryEval(call_grep_tre,  R_GlobalEnv, &error); error = 0;
        R_tryEval(call_grep_pcre, R_GlobalEnv, &error); error = 0;
        R_tryEval(call_sub,       R_GlobalEnv, &error);
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

    /* Same TRE bounded-repeat blowup as agrep; grep's TRE calls compile
     * the same pattern.  PCRE2 loses a little repeat coverage too, but it
     * rejects nested quantifiers anyway.  See common.h. */
    if (fuzz_repeat_product_excessive(buf))
        return 0;

    if (!fuzz_set_string(x_pat, buf))
        return 0;

    fuzz_eval_data_t ed = { .env = R_GlobalEnv };

    ed.call = call_grep_tre;
    R_ToplevelExec(fuzz_do_eval, &ed);

    ed.call = call_grep_pcre;
    R_ToplevelExec(fuzz_do_eval, &ed);

    ed.call = call_sub;
    R_ToplevelExec(fuzz_do_eval, &ed);

    return 0;
}
