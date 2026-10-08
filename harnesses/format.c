/*
 * Exercise R's number and string formatting and the default print
 * methods.
 *
 * src/main/format.c (formatReal/formatInteger/formatComplex and their
 * width computation), paste.c (do_format, do_formatinfo), util.c
 * (do_formatC and str_signif, which build a C printf format from the
 * caller's digits/width/flag), printvector.c, printarray.c, print.c and
 * printutils.c are reached by nothing else: sprintf() fuzzes the format
 * string but not R's own formatting of arbitrary doubles under arbitrary
 * digits/width/nsmall, and nothing prints.
 *
 * Input layout: byte 0 selects the slot, bytes 1-4 feed the numeric
 * parameters (digits, width, nsmall, formatC flag), the rest is a string
 * s.  Each slot derives the numeric vector it needs by splitting s on
 * separators, so the same corpus serves the string and numeric paths.
 * Printing goes to a null sink opened once at startup.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 16)
#define FUZZ_HEADER 5
#define N_CALLS 24

/* formatC flags; str_signif pastes these into the printf format. */
#define N_FLAGS 8
static const char *const flag_values[N_FLAGS] = {
    "", "-", "0", "+", " ", "#", "0-", "+#0"
};

static SEXP calls[N_CALLS];
static SEXP input_string, digits, width, nsmall, flag, flags;

/* Every slot has the signature (s, d, w, ns, fl).  num(s) is inlined as
 * a strsplit so the slots stay independent of each other; 500 numbers is
 * plenty for the width scans in formatReal. */
#define NUM "n <- as.numeric(strsplit(s, '[ ,;\\t\\n]+')[[1]]); n <- n[seq_len(min(500L, length(n)))];"

static const char *const sources[N_CALLS] = {
    /* 0 */
    "function(s, d, w, ns, fl) { format(s); format(s, width = w, justify = 'right');"
    "  format(s, justify = 'centre'); format(c(s, NA), na.encode = FALSE) }",
    /* 1 */
    "function(s, d, w, ns, fl) {" NUM " format(n); format(n, digits = d);"
    "  format(n, width = w) }",
    /* 2 */
    "function(s, d, w, ns, fl) {" NUM " format(n, digits = d, nsmall = ns);"
    "  format(n, nsmall = ns, width = w); format(NA_real_, nsmall = ns) }",
    /* 3 */
    "function(s, d, w, ns, fl) {" NUM " format(n, scientific = TRUE);"
    "  format(n, scientific = FALSE, digits = d); format(n, scientific = w - 20L) }",
    /* 4 */
    "function(s, d, w, ns, fl) {" NUM " format(n, big.mark = ',', small.mark = ' ',"
    "  small.interval = 2L); prettyNum(n, big.mark = \"'\", decimal.mark = ',');"
    "  prettyNum(s, big.mark = ',') }",
    /* 5 */
    "function(s, d, w, ns, fl) {" NUM " formatC(n, digits = d, width = w,"
    "  format = 'f', flag = fl) }",
    /* 6 */
    "function(s, d, w, ns, fl) {" NUM " formatC(n, digits = d, width = w,"
    "  format = 'e', flag = fl) }",
    /* 7 */
    "function(s, d, w, ns, fl) {" NUM " formatC(n, digits = d, width = w,"
    "  format = 'g', flag = fl); formatC(n, format = 'G', digits = d) }",
    /* 8 */
    "function(s, d, w, ns, fl) {" NUM " formatC(n, digits = d, width = w,"
    "  format = 'fg', flag = fl); formatC(n, format = 'fg', digits = d, flag = '#') }",
    /* 9 */
    "function(s, d, w, ns, fl) {" NUM " i <- as.integer(n); formatC(i, width = w,"
    "  format = 'd', flag = fl); formatC(n, format = 'd', big.mark = ',');"
    "  formatC(i, mode = 'integer', width = -w) }",
    /* 10 */
    "function(s, d, w, ns, fl) { formatC(s, width = w, flag = fl);"
    "  formatC(s, width = -w, format = 's'); formatC(s, mode = 'character',"
    "  width = w, flag = '-') }",
    /* 11 */
    "function(s, d, w, ns, fl) {" NUM " i <- as.integer(n); format(i);"
    "  format(i, width = w); format(i, big.mark = ','); toString(i, width = w) }",
    /* 12 */
    "function(s, d, w, ns, fl) {" NUM " z <- complex(real = n, imaginary = rev(n));"
    "  format(z); format(z, digits = d, nsmall = ns); format(as.complex(n), width = w) }",
    /* 13 */
    "function(s, d, w, ns, fl) {" NUM " i <- as.integer(n); i[is.na(i)] <- 0L;"
    "  format(as.raw(i %% 256L)); format(as.logical(n)); format(is.na(n), width = w);"
    "  format(list(s, n, i)) }",
    /* 14 */
    "function(s, d, w, ns, fl) {" NUM " toString(n); toString(s, width = w);"
    "  format(n, trim = TRUE, drop0trailing = TRUE); format(n, zero.print = '.') }",
    /* 15 */
    "function(s, d, w, ns, fl) {" NUM " print(n); print(n, digits = max(1L, d));"
    "  print(as.integer(n)); print(complex(real = n, imaginary = -n)) }",
    /* 16 */
    "function(s, d, w, ns, fl) { print(s, quote = FALSE); print(s);"
    "  print(noquote(s)); print(s, max = w); print(c(a = s)) }",
    /* 17 */
    "function(s, d, w, ns, fl) {" NUM " m <- matrix(n, nrow = max(1L, w %% 7L));"
    "  print(m); print(m, digits = max(1L, d)); print(t(m), quote = FALSE);"
    "  print(array(n, c(2L, 2L, max(1L, length(n) %/% 4L)))) }",
    /* 18 */
    "function(s, d, w, ns, fl) {" NUM " print(list(s, n, list(n, s)));"
    "  print(structure(n, names = rep_len(s, length(n))));"
    "  print(structure(n, class = 'nosuchclass')); utils::str(list(s, n)) }",
    /* 19 */
    "function(s, d, w, ns, fl) {" NUM " old <- options(OutDec = ',', digits = max(1L, d),"
    "  scipen = w - 20L); on.exit(options(old)); format(n); print(n); formatC(n);"
    "  format(n, nsmall = ns) }",
    /* 20 */
    "function(s, d, w, ns, fl) {" NUM " print(summary(n)); print(summary(s));"
    "  print(data.frame(a = n, b = rep_len(s, length(n)))) }",
    /* 21 */
    "function(s, d, w, ns, fl) {" NUM " cat(n, s, sep = ' ', fill = max(1L, w));"
    "  cat(s, fill = TRUE); cat(n, sep = '\\n'); cat(s, n, sep = ', ') }",
    /* 22 */
    "function(s, d, w, ns, fl) {" NUM " round(n, d - 10L); signif(n, max(1L, d));"
    "  format(round(n, d - 10L), nsmall = ns); formatC(signif(n, max(1L, d)), format = 'fg') }",
    /* 23 */
    "function(s, d, w, ns, fl) {" NUM " format(n, digits = d, width = w, justify = 'left');"
    "  format(c(n, NA), na.encode = TRUE); format(as.factor(s)); format(s, width = w,"
    "  justify = 'left', na.encode = FALSE); format(NULL); format(NA) }",
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    /* All printing goes to the null device; nothing reads it back. */
    {
        int error = 0;
        SEXP sink_call;
        Rf_protect(sink_call = Rf_lang2(Rf_install("sink"),
                                        Rf_lang1(Rf_install("nullfile"))));
        R_tryEval(sink_call, R_BaseEnv, &error);
        Rf_unprotect(1);
        if (error)
            abort();
    }

    Rf_protect(input_string = Rf_allocVector(STRSXP, 1));
    Rf_protect(digits = Rf_ScalarInteger(7));
    Rf_protect(width = Rf_ScalarInteger(0));
    Rf_protect(nsmall = Rf_ScalarInteger(0));
    Rf_protect(flag = Rf_allocVector(STRSXP, 1));
    Rf_protect(flags = Rf_allocVector(STRSXP, N_FLAGS));
    for (int i = 0; i < N_FLAGS; i++)
        SET_STRING_ELT(flags, i, Rf_mkChar(flag_values[i]));
    SET_STRING_ELT(flag, 0, STRING_ELT(flags, 0));

    for (int i = 0; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang6(wrapper, input_string, digits, width,
                                       nsmall, flag));
    }
    SET_STRING_ELT(input_string, 0, Rf_mkChar("1.5 2 3"));
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < FUZZ_HEADER + 1 || size > FUZZ_MAX_INPUT
        || memchr(data + FUZZ_HEADER, '\0', size - FUZZ_HEADER))
        return 0;

    /* Ranges follow what R accepts: digits 1..22, nsmall 0..20, and a
     * width small enough that the padded output stays a few KB. */
    INTEGER(digits)[0] = 1 + data[1] % 22;
    INTEGER(width)[0] = data[2] % 41;
    INTEGER(nsmall)[0] = data[3] % 21;
    SET_STRING_ELT(flag, 0, STRING_ELT(flags, data[4] % N_FLAGS));

    char buffer[FUZZ_MAX_INPUT];
    memcpy(buffer, data + FUZZ_HEADER, size - FUZZ_HEADER);
    buffer[size - FUZZ_HEADER] = '\0';
    if (!fuzz_set_string(input_string, buffer))
        return 0;

    fuzz_eval_silent(calls[data[0] % N_CALLS], R_GlobalEnv);
    return 0;
}
