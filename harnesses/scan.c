/*
 * libFuzzer harness for R's scan / delimited-text parser.
 *
 * Feeds fuzzed input to scan() as text under one of several
 * configurations, exercising the C-level parsing state machine in
 * src/main/scan.c: field separation, quoting, escapes, comment chars,
 * NA-string matching, and the per-type converters (scanVector for an
 * atomic `what`, scanFrame for a list `what`).  R's equivalent of a
 * csv.reader target.
 *
 * The first input byte selects the configuration; the rest is the text.
 * Running every configuration on every input stopped scaling once there
 * were more than a handful, and one-per-input keeps libFuzzer's
 * coverage signal attributable.
 *
 * Adapted from r-afl's scan harness.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 18

/* Each configuration is an R closure over the text so that named
 * arguments need no Rf_lang* plumbing.  The first four match the
 * original harness; the rest reach converters and options it never
 * exercised (integer/complex/raw/logical readers, scanFrame, escapes,
 * quoting, NA strings, decimal marks, comments, fill, skip). */
static const char *const sources[N_CALLS] = {
    "function(x) scan(text = x, what = \"\", quiet = TRUE)",
    "function(x) scan(text = x, what = 0, quiet = TRUE)",
    "function(x) scan(text = x, what = \"\", sep = \",\", quiet = TRUE)",
    "function(x) scan(text = x, what = \"\", sep = \"\\t\", quiet = TRUE)",
    "function(x) scan(text = x, what = integer(), quiet = TRUE)",
    "function(x) scan(text = x, what = complex(), quiet = TRUE)",
    "function(x) scan(text = x, what = raw(), quiet = TRUE)",
    "function(x) scan(text = x, what = logical(), quiet = TRUE)",
    "function(x) scan(text = x, what = list(\"\", 0, \"\"), sep = \",\", "
    "quiet = TRUE)",
    "function(x) scan(text = x, what = \"\", allowEscapes = TRUE, quiet = TRUE)",
    "function(x) scan(text = x, what = \"\", sep = \",\", quote = \"\\\"'\", "
    "quiet = TRUE)",
    "function(x) scan(text = x, what = 0, na.strings = c(\"NA\", \"-\"), "
    "quiet = TRUE)",
    "function(x) scan(text = x, what = 0, dec = \",\", quiet = TRUE)",
    "function(x) scan(text = x, what = \"\", comment.char = \"#\", quiet = TRUE)",
    "function(x) scan(text = x, what = \"\", sep = \",\", strip.white = TRUE, "
    "quiet = TRUE)",
    "function(x) scan(text = x, what = list(\"\", 0, \"\"), sep = \",\", "
    "fill = TRUE, multi.line = FALSE, quiet = TRUE)",
    "function(x) scan(text = x, what = \"\", skip = 1, nlines = 4, quiet = TRUE)",
    "function(x) scan(text = x, what = \"\", sep = \",\", "
    "blank.lines.skip = FALSE, quiet = TRUE)",
};

static SEXP x_text;
static SEXP calls[N_CALLS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    /* Reusable text container -- each iteration swaps its CHARSXP. */
    Rf_protect(x_text = Rf_allocVector(STRSXP, 1));

    for (int i = 0; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang2(wrapper, x_text));
    }

    /* Warmup: prime scan's type-dispatch and locale state. */
    SET_STRING_ELT(x_text, 0, Rf_mkChar("1,2,3\n4,5,6\n"));
    for (int i = 0; i < N_CALLS; i++)
        fuzz_eval_silent(calls[i], R_GlobalEnv);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT || memchr(data + 1, '\0', size - 1))
        return 0;

    char buffer[FUZZ_MAX_INPUT];
    memcpy(buffer, data + 1, size - 1);
    buffer[size - 1] = '\0';
    if (!fuzz_set_string(x_text, buffer))
        return 0;

    fuzz_eval_silent(calls[data[0] % N_CALLS], R_GlobalEnv);
    return 0;
}
