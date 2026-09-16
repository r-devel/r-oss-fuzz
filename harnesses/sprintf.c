/* Exercise R's C-style format-string parser and argument dispatch. */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 16)
#define N_CALLS 4

static SEXP format;
static SEXP calls[N_CALLS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    SEXP string, integer, real;
    Rf_protect(format = Rf_allocVector(STRSXP, 1));
    Rf_protect(string = Rf_mkString("fuzz"));
    Rf_protect(integer = Rf_ScalarInteger(-12345));
    Rf_protect(real = Rf_ScalarReal(3.141592653589793));

    SEXP sprintf = Rf_install("sprintf");
    Rf_protect(calls[0] = Rf_lang3(sprintf, format, string));
    Rf_protect(calls[1] = Rf_lang3(sprintf, format, integer));
    Rf_protect(calls[2] = Rf_lang3(sprintf, format, real));
    Rf_protect(calls[3] = Rf_lang5(sprintf, format, integer, real, string));
    SET_STRING_ELT(format, 0, Rf_mkChar("%s"));
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT || memchr(data + 1, '\0', size - 1))
        return 0;

    char buffer[FUZZ_MAX_INPUT];
    memcpy(buffer, data + 1, size - 1);
    buffer[size - 1] = '\0';
    if (!fuzz_set_string(format, buffer))
        return 0;

    fuzz_eval_silent(calls[data[0] % N_CALLS], R_GlobalEnv);
    return 0;
}
