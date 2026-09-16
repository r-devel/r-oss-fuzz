/* Exercise R's iconv wrapper with arbitrary byte strings. */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 6

static SEXP x_list;
static SEXP calls[N_CALLS];

typedef struct {
    const uint8_t *data;
    size_t size;
} encoding_input_t;

static void set_encoding_input(void *data)
{
    encoding_input_t *input = data;
    SEXP raw = Rf_allocVector(RAWSXP, (R_xlen_t)input->size);
    memcpy(RAW(raw), input->data, input->size);
    SET_VECTOR_ELT(x_list, 0, raw);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    static const char *const from[N_CALLS] = {
        "UTF-8", "latin1", "CP1252", "UTF-16LE", "UTF-16BE", ""
    };
    static const char *const to[N_CALLS] = {
        "UTF-8", "UTF-8", "UTF-8", "UTF-8", "UTF-8", "ASCII//TRANSLIT"
    };

    Rf_protect(x_list = Rf_allocVector(VECSXP, 1));
    SET_VECTOR_ELT(x_list, 0, Rf_allocVector(RAWSXP, 0));
    SEXP sub, to_raw;
    Rf_protect(sub = Rf_mkString("byte"));
    Rf_protect(to_raw = Rf_ScalarLogical(TRUE));

    SEXP iconv = Rf_install("iconv");
    for (int i = 0; i < N_CALLS; i++) {
        SEXP from_string, to_string;
        Rf_protect(from_string = Rf_mkString(from[i]));
        Rf_protect(to_string = Rf_mkString(to[i]));
        Rf_protect(calls[i] = Rf_lang6(iconv, x_list, from_string, to_string,
                                       sub, to_raw));
        SET_TAG(CDDR(calls[i]), Rf_install("from"));
        SET_TAG(CDR(CDDR(calls[i])), Rf_install("to"));
        SET_TAG(CDR(CDR(CDDR(calls[i]))), Rf_install("sub"));
        SET_TAG(CDR(CDR(CDR(CDDR(calls[i])))), Rf_install("toRaw"));
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT)
        return 0;

    int selected = data[0] % N_CALLS;
    encoding_input_t input = { data + 1, size - 1 };
    if (!R_ToplevelExec(set_encoding_input, &input))
        return 0;

    fuzz_eval_silent(calls[selected], R_GlobalEnv);
    return 0;
}
