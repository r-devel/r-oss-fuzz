/*
 * libFuzzer harness for R's parser.
 *
 * Feeds input to R_ParseVector -- exercising the lexer and parser
 * without evaluating the result.  Targets parser bugs: crashes,
 * OOB reads, infinite loops, stack overflows in deeply nested input.
 *
 * Adapted from r-afl's parse harness.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 16)

static SEXP x_str;

typedef struct {
    SEXP str;
    ParseStatus status;
} parse_data_t;

static void do_parse(void *data)
{
    parse_data_t *pd = (parse_data_t *)data;
    SEXP parsed;
    Rf_protect(parsed = R_ParseVector(pd->str, -1, &pd->status, R_NilValue));
    Rf_unprotect(1);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_init_r();

    /* Enable pipe bind (=>) syntax so the fuzzer exercises that path. */
    setenv("_R_USE_PIPEBIND_", "true", 0);

    /* Pre-allocate reusable string container.  Each iteration just
     * swaps the CHARSXP inside via SET_STRING_ELT. */
    Rf_protect(x_str = Rf_allocVector(STRSXP, 1));

    /* Warmup: prime the parser's internal state so early iterations
     * don't diverge from later ones. */
    {
        static const char *warmup[] = {
            "1+1",
            "x <- function(a, b) a + b",
            "if (TRUE) 'yes' else 'no'",
            "for (i in 1:10) i",
            "list(a=1, b=\"hello\", c=NULL, d=NA)",
            "\\(x) x + 1",
            "1:10 |> rev()",
            NULL
        };
        parse_data_t pd;
        for (int i = 0; warmup[i] != NULL; i++) {
            SET_STRING_ELT(x_str, 0, Rf_mkChar(warmup[i]));
            pd.str = x_str;
            pd.status = PARSE_NULL;
            R_ToplevelExec(do_parse, &pd);
        }
        R_gc();
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_MAX_INPUT)
        return 0;

    /* Null-terminate the input for R's string API. */
    char buf[FUZZ_MAX_INPUT + 1];
    memcpy(buf, data, size);
    buf[size] = '\0';

    if (!fuzz_set_string(x_str, buf))
        return 0;

    parse_data_t pd;
    pd.status = PARSE_NULL;
    pd.str = x_str;
    R_ToplevelExec(do_parse, &pd);

    return 0;
}
