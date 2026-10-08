/*
 * libFuzzer harness for R's regex engines.
 *
 * Uses fuzzed input as a regex pattern against a fixed character vector,
 * exercising both the TRE (default) and PCRE2 (perl=TRUE) backends
 * through every entry point in grep.c: grep/grepl, sub/gsub (including
 * backreference and case-conversion replacements), regexpr/gregexpr,
 * regexec, and grepRaw.  The first input byte selects the call; the
 * rest is the pattern.
 *
 * Adapted from r-afl's grep harness.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 16

/* Closures over (pattern, subjects).  The first three are the original
 * harness's calls. */
static const char *const sources[N_CALLS] = {
    "function(p, x) grep(p, x)",
    "function(p, x) grep(p, x, perl = TRUE)",
    "function(p, x) sub(p, \"X\", x)",
    "function(p, x) regexpr(p, x)",
    "function(p, x) gregexpr(p, x)",
    "function(p, x) regexec(p, x)",
    "function(p, x) gregexpr(p, x, perl = TRUE)",
    "function(p, x) regexpr(p, x, fixed = TRUE)",
    "function(p, x) gsub(p, \"X\", x, perl = TRUE)",
    "function(p, x) grepRaw(p, charToRaw(x[3L]), all = TRUE)",
    "function(p, x) grepl(p, x, useBytes = TRUE)",
    "function(p, x) regexec(p, x, perl = TRUE)",
    "function(p, x) regexpr(p, x, perl = TRUE)",
    "function(p, x) gsub(p, \"\\\\1\", x)",
    "function(p, x) sub(p, \"X\", x, fixed = TRUE)",
    "function(p, x) gsub(p, \"\\\\U\\\\1\", x, perl = TRUE)",
};

static SEXP x_pat;
static SEXP calls[N_CALLS];

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

    for (int i = 0; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang3(wrapper, x_pat, x));
    }

    /* Warmup: prime regex engine state before fuzzing. */
    SET_STRING_ELT(x_pat, 0, Rf_mkChar("(o)"));
    for (int i = 0; i < N_CALLS; i++)
        fuzz_eval_silent(calls[i], R_GlobalEnv);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT || memchr(data + 1, '\0', size - 1))
        return 0;

    char buf[FUZZ_MAX_INPUT];
    memcpy(buf, data + 1, size - 1);
    buf[size - 1] = '\0';

    /* Same TRE bounded-repeat blowup as agrep; every slot compiles the
     * pattern with TRE or PCRE2.  PCRE2 loses a little repeat coverage
     * too, but it rejects nested quantifiers anyway.  See common.h. */
    if (fuzz_repeat_product_excessive(buf))
        return 0;

    if (!fuzz_set_string(x_pat, buf))
        return 0;

    fuzz_eval_silent(calls[data[0] % N_CALLS], R_GlobalEnv);
    return 0;
}
