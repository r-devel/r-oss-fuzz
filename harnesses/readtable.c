/*
 * libFuzzer harness for read.table() and friends -- the tabular readers
 * most untrusted CSV enters R through.
 *
 * The scan target covers scan.c, but read.table() wraps it in C code of
 * its own in src/library/utils/src/io.c that scan never reaches:
 * readtablehead (the header/line pre-reader that tracks quotes and
 * comments across physical lines), countfields (count.fields), and
 * writetable (the quoting and encoding of write.table()).  Each input is
 * handed to one of those paths as the text of a file, under a
 * configuration chosen by the first byte; the readers that succeed hand
 * their data frame to write.table() so the writer sees real, fuzz-shaped
 * columns rather than only hand-built ones.
 *
 * Writers go to nullfile(): the C code runs in full, nothing hits the
 * fuzzer's stdout.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 20

/* Slot layout:
 *   [0,12)   read.table() and its csv/csv2/delim presets under assorted
 *            separators, quoting, comments, NA strings, fill/flush,
 *            escapes, encodings, colClasses and row.names handling
 *   [12,15)  count.fields() on a textConnection of the input
 *   [15,20)  readers chained into write.table()/write.csv(): quoting
 *            methods, factor levels, NA and decimal marks, line endings,
 *            and a re-encoding fileEncoding
 * Every connection a slot opens is closed before it returns: R caps the
 * connection table at 128 slots. */
static const char *const sources[N_CALLS] = {
    "function(x) read.table(text = x)",
    "function(x) read.csv(text = x)",
    "function(x) read.csv2(text = x)",
    "function(x) read.delim(text = x)",
    "function(x) read.table(text = x, header = TRUE, sep = \",\", "
    "quote = \"\\\"'\", comment.char = \"#\", fill = TRUE)",
    "function(x) read.table(text = x, sep = \",\", allowEscapes = TRUE, "
    "strip.white = TRUE, blank.lines.skip = FALSE)",
    "function(x) read.table(text = x, header = TRUE, row.names = 1, "
    "check.names = TRUE)",
    "function(x) read.table(text = x, colClasses = \"character\", "
    "nrows = 100, skip = 1, fill = TRUE)",
    "function(x) read.table(text = x, header = TRUE, "
    "na.strings = c(\"NA\", \"\", \"-\", \"?\"), stringsAsFactors = TRUE)",
    "function(x) read.table(text = x, flush = TRUE, numerals = \"no.loss\", "
    "dec = \",\")",
    "function(x) read.csv(text = x, encoding = \"UTF-8\", skipNul = TRUE)",
    "function(x) read.csv(text = x, encoding = \"latin1\", header = FALSE, "
    "col.names = paste0(\"V\", 1:3), fill = TRUE)",
    "function(x) { con <- textConnection(x); on.exit(close(con)); "
    "count.fields(con, sep = \",\", quote = \"\\\"\", comment.char = \"#\") }",
    "function(x) { con <- textConnection(x); on.exit(close(con)); "
    "count.fields(con, sep = \"\", blank.lines.skip = FALSE, skip = 1) }",
    "function(x) { con <- textConnection(x); on.exit(close(con)); "
    "count.fields(con, sep = \";\", quote = \"'\", comment.char = \"\") }",
    "function(x) { d <- read.csv(text = x, stringsAsFactors = TRUE); "
    "write.table(d, nullfile(), sep = \",\", qmethod = \"double\") }",
    "function(x) { d <- read.table(text = x, fill = TRUE); "
    "write.csv(d, nullfile(), row.names = FALSE, na = \"\") }",
    "function(x) { d <- read.csv2(text = x); "
    "write.table(d, nullfile(), quote = FALSE, dec = \",\", eol = \"\\r\\n\", "
    "col.names = NA) }",
    "function(x) { d <- read.delim(text = x); "
    "write.table(d, nullfile(), qmethod = \"escape\", quote = seq_along(d)) }",
    "function(x) { d <- read.csv(text = x, encoding = \"UTF-8\"); "
    "write.csv(d, nullfile(), fileEncoding = \"UTF-16LE\") }",
};

static SEXP x_text;
static SEXP calls[N_CALLS];

int fuzz_target_init(int *argc, char ***argv)
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

    /* Warmup: load utils and prime read.table's method dispatch. */
    SET_STRING_ELT(x_text, 0, Rf_mkChar("a,b,c\n1,2,x\n4,NA,\"y\"\n"));
    for (int i = 0; i < N_CALLS; i++)
        fuzz_eval_silent(calls[i], R_GlobalEnv);

    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
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
