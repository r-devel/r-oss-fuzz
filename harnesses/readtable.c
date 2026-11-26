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

/* Most cells a padding slot may be handed (see cell_bound).  The cost of
 * a cell grows with the number of columns: under ASAN, 1M cells took 2 s
 * as 250 columns and 12 s as 30000, the widest a 64 KiB input allows,
 * and 4M took 18 s as 30000 columns. */
#define FUZZ_MAX_CELLS (1024 * 1024)

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

/* The slots whose reader pads short rows: fill = TRUE, given or by
 * default (read.csv, read.csv2, read.delim, and read.table() with
 * blank.lines.skip = FALSE).  Keep in step with sources[]. */
static const int pads[N_CALLS] = {
    0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1,     /* [0,12)  readers */
    0, 0, 0,                                /* [12,15) count.fields() */
    1, 1, 1, 1, 1,                          /* [15,20) readers into writers */
};

/*
 * Upper bound on the cells a padding slot makes of text.  With fill,
 * read.table() pads every row to the most fields in its first five
 * lines, so one wide line over many short ones is quadratic in the
 * input: 43 KB of tabs and carriage returns read as 10574 rows of 4458
 * columns, 47M cells (oss-fuzz testcase 6363833382535168).
 *
 * There are at most as many rows as physical lines, which \n and \r
 * each end.  A row has at most one field more than the bytes on its
 * lines that can end a field in some slot: the separators (sep = ""
 * splits at blanks, and at NBSP in a Latin-1 locale) and the quote
 * characters, as sep = "" reads "a"b as two fields.  A row spans lines
 * only inside a quote, and a line without a quote character is then
 * quoted from end to end, so nothing on it ends a field: the counts on
 * the lines that hold a quote character bound every row that spans
 * lines, whatever each slot takes as its quotes.  Slot 11's three
 * col.names are the one width that is not counted.
 */
static size_t cell_bound(const char *text)
{
    size_t lines = 1, widest = 0, quoted = 0, ends = 0;
    int has_quote = 0;

    for (const unsigned char *p = (const unsigned char *)text; ; p++) {
        if (*p == '\0' || *p == '\n' || *p == '\r') {
            if (ends > widest)
                widest = ends;
            if (has_quote)
                quoted += ends;
            if (*p == '\0')
                break;
            lines++;
            ends = 0;
            has_quote = 0;
        } else if (*p == ' ' || *p == '\t' || *p == ',' || *p == ';'
                   || *p == 0xa0) {
            ends++;
        } else if (*p == '"' || *p == '\'') {
            ends++;
            has_quote = 1;
        }
    }

    return lines * (1 + (quoted > widest ? quoted : widest));
}

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

    fuzz_label_calls(calls, N_CALLS);

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
    int slot = data[0] % N_CALLS;
    if (pads[slot] && cell_bound(buffer) > FUZZ_MAX_CELLS)
        return 0;
    if (!fuzz_set_string(x_text, buffer))
        return 0;

    fuzz_eval_silent(calls[slot], R_GlobalEnv);
    return 0;
}
