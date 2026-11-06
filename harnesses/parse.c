/*
 * libFuzzer harness for R's parser.
 *
 * Feeds input to the lexer and parser without evaluating the result.
 * Targets parser bugs: crashes, OOB reads, infinite loops, stack
 * overflows in deeply nested input.
 *
 * The first input byte selects the route; the rest is the source text.
 * Slot 0 is the bare R_ParseVector of the original harness.  The others
 * go through R-level parse() so the srcref machinery runs, then push the
 * parsed expressions through deparse() and back, str2lang(), and the
 * deparse control options -- deparse.c is the parser's inverse and had
 * only ever been reached incidentally.  Nothing here evaluates what was
 * parsed.
 *
 * Adapted from r-afl's parse harness.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 16)
#define N_CALLS 7

/*
 * The R sources use raw string literals, a GNU extension that clang (19
 * and later) and gcc accept in their default gnu C modes.  They are arrays
 * rather than pointers so the table below can take their addresses in a
 * static initializer.
 *
 * The round-trip and srcref slots run R closures per top-level expression
 * (the vapply; deparse's useSource path calls as.character() on each
 * srcref, in both of its passes).  7k one-character expressions in 16 KB
 * took 27 s on the bots, past libFuzzer's 25 s timeout, without adding
 * coverage, so both skip inputs with more than 256 expressions.
 */
static const char parse_data_source[] = R"(
function(x) {
    e <- parse(text = x, keep.source = TRUE)
    getParseData(e)
}
)";

static const char deparse_roundtrip_source[] = R"(
function(x) {
    e <- parse(text = x, keep.source = FALSE)
    if (length(e) > 256L)
        return(NULL)
    d <- vapply(as.list(e), function(ex) {
        paste(deparse(ex, control = "all"), collapse = "\n")
    }, "")
    identical(e, parse(text = d, keep.source = FALSE))
}
)";

static const char str2lang_source[] = R"(
function(x) str2lang(x)
)";

static const char str2expression_source[] = R"(
function(x) str2expression(x)
)";

static const char deparse_options_source[] = R"(
function(x) {
    e <- parse(text = x, keep.source = FALSE)
    deparse(
        e,
        width.cutoff = 20L,
        backtick = TRUE,
        control = c("keepInteger", "quoteExpressions",
                    "showAttributes", "digits17")
    )
}
)";

static const char deparse_srcref_source[] = R"(
function(x) {
    e <- parse(text = x, keep.source = TRUE)
    if (length(e) > 256L)
        return(NULL)
    deparse(e, control = c("useSource", "keepNA", "niceNames"))
}
)";

/* Slot 0 is handled in C; sources[0] is a placeholder so slot numbers
 * line up with the table. */
static const char *const sources[N_CALLS] = {
    NULL,
    parse_data_source,
    deparse_roundtrip_source,
    str2lang_source,
    str2expression_source,
    deparse_options_source,
    deparse_srcref_source,
};

static SEXP x_str;
static SEXP calls[N_CALLS];

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

static void run_slot(int selected)
{
    if (selected == 0) {
        parse_data_t pd;
        pd.status = PARSE_NULL;
        pd.str = x_str;
        R_ToplevelExec(do_parse, &pd);
        return;
    }

    fuzz_eval_silent(calls[selected], R_GlobalEnv);
}

int fuzz_target_init(int *argc, char ***argv)
{
    fuzz_init_r();

    /* Enable pipe bind (=>) syntax so the fuzzer exercises that path. */
    setenv("_R_USE_PIPEBIND_", "true", 0);

    /* Pre-allocate reusable string container.  Each iteration just
     * swaps the CHARSXP inside via SET_STRING_ELT. */
    Rf_protect(x_str = Rf_allocVector(STRSXP, 1));

    for (int i = 1; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang2(wrapper, x_str));
    }

    fuzz_label_calls(calls, N_CALLS);

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
        for (int i = 0; warmup[i] != NULL; i++) {
            SET_STRING_ELT(x_str, 0, Rf_mkChar(warmup[i]));
            for (int slot = 0; slot < N_CALLS; slot++)
                run_slot(slot);
        }
        R_gc();
    }

    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT || memchr(data + 1, '\0', size - 1))
        return 0;

    /* Null-terminate the input for R's string API. */
    char buf[FUZZ_MAX_INPUT];
    memcpy(buf, data + 1, size - 1);
    buf[size - 1] = '\0';

    if (!fuzz_set_string(x_str, buf))
        return 0;

    run_slot(data[0] % N_CALLS);
    return 0;
}
