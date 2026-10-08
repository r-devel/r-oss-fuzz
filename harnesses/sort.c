/*
 * Exercise R's sorting, ordering, ranking and hashing primitives.
 *
 * src/main/sort.c (shell/quick sorts, psort, order, rank), radixsort.c
 * (the data.table forder port, with its CHARSXP truelength bookkeeping
 * and encoding-specific string comparison) and unique.c (the hash tables
 * behind unique/duplicated/match/charmatch/pmatch/rowsum) are reached by
 * no other target beyond R's own startup.  The input is split on
 * newlines into a character vector, from which each slot derives the
 * numeric, integer, complex, raw, list, factor and encoding-marked
 * variants it needs.
 *
 * Strings are marked UTF-8 only when valid, so every encoding the radix
 * sort sees is one R itself would produce.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 16)
#define FUZZ_MAX_LINES 2000
#define N_CALLS 22

static SEXP calls[N_CALLS];

/* Each slot is a closure over the character vector x.  Several related
 * calls share a slot so one input exercises a whole family at once;
 * the families are kept small enough that a 2000-line input stays
 * well under a millisecond. */
static const char *const sources[N_CALLS] = {
    /* 0 */
    "function(x) { sort(x, method = 'radix'); sort(x, method = 'radix',"
    "  decreasing = TRUE, na.last = TRUE) }",
    /* 1 */
    "function(x) { sort(x, method = 'shell'); sort(x, method = 'shell',"
    "  decreasing = TRUE, na.last = FALSE) }",
    /* 2 */
    "function(x) { n <- as.numeric(x); sort(n, method = 'quick');"
    "  sort(n, method = 'radix', na.last = TRUE); sort(n, method = 'shell') }",
    /* 3 */
    "function(x) { i <- as.integer(as.numeric(x)); sort(i, method = 'shell',"
    "  na.last = FALSE); sort(i, method = 'radix', decreasing = TRUE);"
    "  sort(i, method = 'quick') }",
    /* 4 */
    "function(x) { order(x, method = 'radix'); order(x, method = 'radix',"
    "  decreasing = TRUE, na.last = NA) }",
    /* 5 */
    "function(x) { n <- as.numeric(x); order(x, n, method = 'radix',"
    "  decreasing = c(TRUE, FALSE)); order(n, x, method = 'radix') }",
    /* 6 */
    "function(x) { n <- as.numeric(x); order(x, method = 'shell');"
    "  order(n, method = 'shell', na.last = NA); order(n, x) }",
    /* 7 */
    "function(x) { n <- as.numeric(x); rank(x, ties.method = 'min');"
    "  rank(n, ties.method = 'average'); rank(x, ties.method = 'first');"
    "  rank(n, ties.method = 'last', na.last = 'keep') }",
    /* 8 */
    "function(x) { xtfrm(x); xtfrm(factor(x)); xtfrm(as.numeric(x)) }",
    /* 9 */
    "function(x) { unique(x); duplicated(x); anyDuplicated(x);"
    "  unique(x, fromLast = TRUE); duplicated(x, fromLast = TRUE) }",
    /* 10 */
    "function(x) { n <- as.numeric(x); unique(n); duplicated(n);"
    "  anyDuplicated(n, fromLast = TRUE); i <- as.integer(n); unique(i);"
    "  duplicated(i); match(i, rev(i)); match(n, rev(n)) }",
    /* 11 */
    "function(x) { n <- as.numeric(x); z <- complex(real = n, imaginary = rev(n));"
    "  unique(z); duplicated(z); match(z, rev(z)); anyDuplicated(z) }",
    /* 12 */
    "function(x) { i <- as.integer(as.numeric(x)); i[is.na(i)] <- 0L;"
    "  r <- as.raw(i %% 256L); unique(r); duplicated(r); match(r, rev(r));"
    "  l <- as.logical(i %% 3L - 1L); unique(l); duplicated(l); match(l, rev(l)) }",
    /* 13 */
    "function(x) { l <- as.list(x); unique(l); duplicated(l); match(l, rev(l));"
    "  anyDuplicated(l) }",
    /* 14 */
    "function(x) { match(x, rev(x)); x %in% rev(x); charmatch(x, rev(x));"
    "  pmatch(x, rev(x), duplicates.ok = TRUE); pmatch(x, rev(x)) }",
    /* 15 */
    "function(x) { n <- as.numeric(x); n[is.na(n)] <- 0; rowsum(n, group = x);"
    "  rowsum(matrix(n, ncol = 1L), group = x, reorder = FALSE) }",
    /* 16 */
    "function(x) { if (length(x) >= 3L) { n <- as.numeric(x);"
    "  sort(n, partial = c(2L, 3L), na.last = TRUE); sort.int(as.integer(n), partial = 1L);"
    "  sort.int(n, partial = c(1L, 3L), na.last = TRUE) } }",
    /* 17 */
    "function(x) { n <- as.numeric(x); is.unsorted(x); is.unsorted(n);"
    "  is.unsorted(x, strictly = TRUE); is.unsorted(n, na.rm = TRUE) }",
    /* 18 */
    "function(x) { u <- x; Encoding(u) <- ifelse(validUTF8(u), 'UTF-8', 'unknown');"
    "  sort(u, method = 'radix'); order(u, method = 'radix'); unique(u);"
    "  match(u, x); duplicated(u) }",
    /* 19 */
    "function(x) { l <- x; Encoding(l) <- 'latin1'; sort(l, method = 'radix');"
    "  order(l, method = 'shell'); unique(l); match(l, x); duplicated(c(l, x)) }",
    /* 20 */
    "function(x) { f <- factor(x); sort(f); order(f, method = 'radix');"
    "  unique(f); duplicated(f); match(f, rev(f)); rank(f) }",
    /* 21 */
    "function(x) { sort(x, index.return = TRUE); rev(sort(x, decreasing = TRUE));"
    "  n <- as.numeric(x); sort(n, index.return = TRUE, method = 'radix');"
    "  h <- utils::hashtab('identical'); k <- x[seq_len(min(50L, length(x)))];"
    "  for (s in k) utils::sethash(h, s, nchar(s)); for (s in k) utils::gethash(h, s);"
    "  utils::numhash(h) }",
};

typedef struct {
    const uint8_t *data;
    size_t size;
} lines_input_t;

/* Split the input on newlines into a STRSXP and hand it to every slot.
 * Runs under R_ToplevelExec because the allocations can hit the vector
 * heap cap. */
static void set_lines(void *data)
{
    lines_input_t *input = data;
    const uint8_t *p = input->data;
    const uint8_t *end = input->data + input->size;

    int n = 1;
    for (const uint8_t *q = p; q < end && n < FUZZ_MAX_LINES; q++) {
        if (*q == '\n')
            n++;
    }

    SEXP lines;
    Rf_protect(lines = Rf_allocVector(STRSXP, n));
    for (int i = 0; i < n; i++) {
        const uint8_t *nl = memchr(p, '\n', (size_t)(end - p));
        if (nl == NULL || i == n - 1)
            nl = end;
        SET_STRING_ELT(lines, i, Rf_mkCharLen((const char *)p, (int)(nl - p)));
        p = nl < end ? nl + 1 : end;
    }

    for (int i = 0; i < N_CALLS; i++)
        SETCADR(calls[i], lines);
    Rf_unprotect(1);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    SEXP placeholder;
    Rf_protect(placeholder = Rf_allocVector(STRSXP, 0));
    for (int i = 0; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang2(wrapper, placeholder));
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT || memchr(data + 1, '\0', size - 1))
        return 0;

    lines_input_t input = { data + 1, size - 1 };
    if (!R_ToplevelExec(set_lines, &input))
        return 0;

    fuzz_eval_silent(calls[data[0] % N_CALLS], R_GlobalEnv);
    return 0;
}
