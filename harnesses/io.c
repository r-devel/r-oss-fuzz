/* Exercise readBin() and writeBin() using in-memory raw connections. */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 8

static SEXP read_calls[N_CALLS];
static SEXP write_calls[N_CALLS];

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

    SEXP what[N_CALLS], sizes[N_CALLS], endian[N_CALLS];
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

    int size_values[N_CALLS] = { 1, 1, 4, 4, 8, 16, 1, 4 };
    const char *endian_values[N_CALLS] = {
        "little", "big", "little", "big", "little", "big", "little",
        "little"
    };
    SEXP placeholder, count, output;
    Rf_protect(placeholder = Rf_allocVector(RAWSXP, 0));
    Rf_protect(count = Rf_ScalarInteger(16384));
    Rf_protect(output = Rf_allocVector(RAWSXP, 0));
    SEXP read_bin = Rf_install("readBin");
    SEXP write_bin = Rf_install("writeBin");

    for (int i = 0; i < N_CALLS; i++) {
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
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT)
        return 0;

    io_input_t input = { data[0] % N_CALLS, data + 1, size - 1 };
    R_ToplevelExec(run_io, &input);
    return 0;
}
