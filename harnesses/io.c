/*
 * Exercise readBin() / writeBin() / readChar() / writeChar() over raw
 * vectors and in-memory raw connections.
 *
 * The first input byte selects a slot.  The first N_BIN slots are the
 * original typed readBin round trips (read, write back, read again,
 * and abort if the two reads differ).  The rest wrap the input in R
 * closures that reach the string readers (readChar, readBin of
 * "character"), the rawConnection layer (seek, readLines, the
 * connection-backed readBin), and the writeChar encoder -- none of
 * which the round trips touched.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_BIN 8
#define N_WRAP 10
#define N_CALLS (N_BIN + N_WRAP)

static SEXP read_calls[N_BIN];
static SEXP write_calls[N_BIN];
static SEXP wrap_calls[N_WRAP];

/* Connections are closed on exit from each closure: a read error must
 * not leak one of R's 128 connection slots across iterations. */
static const char *const wrap_sources[N_WRAP] = {
    "function(x) readChar(x, c(1L, 5L, 16L, 64L), useBytes = TRUE)",
    "function(x) readChar(x, c(1L, 5L, 16L, 64L))",
    "function(x) { con <- rawConnection(x); on.exit(close(con)); "
    "readChar(con, c(1L, 5L, 16L, 64L)) }",
    "function(x) { s <- readChar(x, c(4L, 8L, 16L), useBytes = TRUE); "
    "r <- writeChar(s, raw(), nchars = c(4L, 8L, 16L), eos = NULL); "
    "readChar(r, c(4L, 8L, 16L), useBytes = TRUE) }",
    "function(x) { con <- rawConnection(x); on.exit(close(con)); "
    "readBin(con, \"character\", n = 64L) }",
    "function(x) { con <- rawConnection(x); on.exit(close(con)); "
    "readBin(con, \"integer\", n = 16384L, size = 2L, signed = FALSE) }",
    "function(x) readBin(x, \"integer\", n = 16384L, size = 1L, signed = TRUE)",
    "function(x) { con <- rawConnection(x); on.exit(close(con)); seek(con, 3L); "
    "readBin(con, \"double\", n = 16384L, size = 4L, endian = \"big\") }",
    "function(x) { con <- rawConnection(x); on.exit(close(con)); readLines(con) }",
    "function(x) { con <- rawConnection(x); on.exit(close(con)); "
    "readBin(con, \"numeric\", n = 16384L, endian = \"swap\") }",
};

typedef struct {
    int selected;
    const uint8_t *data;
    size_t size;
} io_input_t;

static void run_io(void *data)
{
    io_input_t *input = data;
    int error = 0;
    SEXP raw, value, encoded, roundtrip;
    Rf_protect(raw = Rf_allocVector(RAWSXP, (R_xlen_t)input->size));
    memcpy(RAW(raw), input->data, input->size);
    SETCADR(read_calls[input->selected], raw);

    value = R_tryEvalSilent(read_calls[input->selected], R_GlobalEnv, &error);
    if (!error) {
        SETCADR(write_calls[input->selected], value);
        encoded = R_tryEvalSilent(write_calls[input->selected], R_GlobalEnv,
                                  &error);
    }
    if (!error) {
        SETCADR(read_calls[input->selected], encoded);
        roundtrip = R_tryEvalSilent(read_calls[input->selected], R_GlobalEnv,
                                    &error);
    }
    if (!error) {
        Rf_protect(roundtrip);
        if (!R_compute_identical(value, roundtrip, IDENT_USE_CLOENV))
            abort();
        Rf_unprotect(1);
    }
    Rf_unprotect(1);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    SEXP what[N_BIN], sizes[N_BIN], endian[N_BIN];
    Rcomplex zero;
    zero.r = 0.0;
    zero.i = 0.0;
    Rf_protect(what[0] = Rf_allocVector(RAWSXP, 0));
    Rf_protect(what[1] = Rf_ScalarInteger(0));
    Rf_protect(what[2] = Rf_ScalarInteger(0));
    Rf_protect(what[3] = Rf_ScalarReal(0));
    Rf_protect(what[4] = Rf_ScalarReal(0));
    Rf_protect(what[5] = Rf_ScalarComplex(zero));
    Rf_protect(what[6] = Rf_mkString(""));
    Rf_protect(what[7] = Rf_ScalarLogical(FALSE));

    int size_values[N_BIN] = { 1, 1, 4, 4, 8, 16, 1, 4 };
    const char *endian_values[N_BIN] = {
        "little", "big", "little", "big", "little", "big", "little",
        "little"
    };
    SEXP placeholder, count, output;
    Rf_protect(placeholder = Rf_allocVector(RAWSXP, 0));
    Rf_protect(count = Rf_ScalarInteger(16384));
    Rf_protect(output = Rf_allocVector(RAWSXP, 0));
    SEXP read_bin = Rf_install("readBin");
    SEXP write_bin = Rf_install("writeBin");

    for (int i = 0; i < N_BIN; i++) {
        Rf_protect(sizes[i] = Rf_ScalarInteger(size_values[i]));
        Rf_protect(endian[i] = Rf_mkString(endian_values[i]));
        Rf_protect(read_calls[i] = Rf_lang6(read_bin, placeholder, what[i], count,
                                            sizes[i], endian[i]));
        SET_TAG(CDR(CDR(CDDR(read_calls[i]))), Rf_install("size"));
        SET_TAG(CDR(CDR(CDR(CDDR(read_calls[i])))), Rf_install("endian"));

        Rf_protect(write_calls[i] = Rf_lang5(write_bin, R_NilValue, output,
                                             sizes[i], endian[i]));
        SET_TAG(CDDDR(write_calls[i]), Rf_install("size"));
        SET_TAG(CDR(CDDDR(write_calls[i])), Rf_install("endian"));
    }

    for (int i = 0; i < N_WRAP; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(wrap_sources[i]));
        Rf_protect(wrap_calls[i] = Rf_lang2(wrapper, placeholder));
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT)
        return 0;

    int selected = data[0] % N_CALLS;
    if (selected < N_BIN) {
        io_input_t input = { selected, data + 1, size - 1 };
        R_ToplevelExec(run_io, &input);
        return 0;
    }

    SEXP call = wrap_calls[selected - N_BIN];
    if (!fuzz_set_raw_arg(call, data + 1, size - 1))
        return 0;

    fuzz_eval_silent(call, R_GlobalEnv);
    return 0;
}
