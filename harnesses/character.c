/* Exercise byte-, character-, width-, substring-, and quoting operations. */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 9

static SEXP input_string;
static SEXP calls[N_CALLS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    SEXP bytes, chars, width, true_value, one, end, empty, quote, none;
    Rf_protect(input_string = Rf_allocVector(STRSXP, 1));
    Rf_protect(bytes = Rf_mkString("bytes"));
    Rf_protect(chars = Rf_mkString("chars"));
    Rf_protect(width = Rf_mkString("width"));
    Rf_protect(true_value = Rf_ScalarLogical(TRUE));
    Rf_protect(one = Rf_ScalarInteger(1));
    Rf_protect(end = Rf_ScalarInteger(32));
    Rf_protect(empty = Rf_mkString(""));
    Rf_protect(quote = Rf_mkString("\""));
    Rf_protect(none = Rf_mkString("none"));

    SEXP nchar = Rf_install("nchar");
    Rf_protect(calls[0] = Rf_lang3(nchar, input_string, bytes));
    SET_TAG(CDDR(calls[0]), Rf_install("type"));
    Rf_protect(calls[1] = Rf_lang3(nchar, input_string, chars));
    SET_TAG(CDDR(calls[1]), Rf_install("type"));
    Rf_protect(calls[2] = Rf_lang3(nchar, input_string, width));
    SET_TAG(CDDR(calls[2]), Rf_install("type"));
    Rf_protect(calls[3] = Rf_lang4(Rf_install("substr"), input_string, one, end));
    Rf_protect(calls[4] = Rf_lang4(Rf_install("substring"), input_string, one, end));
    Rf_protect(calls[5] = Rf_lang4(Rf_install("strsplit"), input_string, empty,
                                   true_value));
    SET_TAG(CDDDR(calls[5]), Rf_install("fixed"));
    Rf_protect(calls[6] = Rf_lang5(Rf_install("encodeString"), input_string,
                                   quote, none, true_value));
    SET_TAG(CDDR(calls[6]), Rf_install("quote"));
    SET_TAG(CDDDR(calls[6]), Rf_install("justify"));
    SET_TAG(CDR(CDDDR(calls[6])), Rf_install("na.encode"));
    Rf_protect(calls[7] = Rf_lang3(Rf_install("make.names"), input_string,
                                   true_value));
    SET_TAG(CDDR(calls[7]), Rf_install("unique"));

    SEXP to_raw;
    Rf_protect(to_raw = Rf_lang2(Rf_install("charToRaw"), input_string));
    Rf_protect(calls[8] = Rf_lang3(Rf_install("rawToChar"), to_raw, true_value));
    SET_TAG(CDDR(calls[8]), Rf_install("multiple"));
    SET_STRING_ELT(input_string, 0, Rf_mkChar("fuzz"));
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT || memchr(data + 1, '\0', size - 1))
        return 0;

    char buffer[FUZZ_MAX_INPUT];
    memcpy(buffer, data + 1, size - 1);
    buffer[size - 1] = '\0';
    if (!fuzz_set_string(input_string, buffer))
        return 0;

    fuzz_eval_silent(calls[data[0] % N_CALLS], R_GlobalEnv);
    return 0;
}
