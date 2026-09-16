/* Exercise tools::parse_Rd with complete documents and fragments. */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)

static SEXP input_string;
static SEXP calls[2];

static SEXP make_wrapper(const char *source)
{
    ParseStatus status;
    SEXP text, parsed, wrapper;
    Rf_protect(text = Rf_mkString(source));
    Rf_protect(parsed = R_ParseVector(text, -1, &status, R_NilValue));
    if (status != PARSE_OK || XLENGTH(parsed) != 1)
        abort();
    wrapper = Rf_eval(VECTOR_ELT(parsed, 0), R_BaseEnv);
    Rf_unprotect(2);
    return wrapper;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    static const char source[] =
        "function(x, fragment) { con <- textConnection(x); "
        "on.exit(close(con)); tools::parse_Rd(con, fragment = fragment, "
        "permissive = TRUE) }";
    SEXP wrapper, false_value, true_value;
    Rf_protect(wrapper = make_wrapper(source));
    Rf_protect(input_string = Rf_allocVector(STRSXP, 1));
    Rf_protect(false_value = Rf_ScalarLogical(FALSE));
    Rf_protect(true_value = Rf_ScalarLogical(TRUE));
    Rf_protect(calls[0] = Rf_lang3(wrapper, input_string, false_value));
    Rf_protect(calls[1] = Rf_lang3(wrapper, input_string, true_value));
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

    fuzz_eval_silent(calls[data[0] & 1], R_GlobalEnv);
    return 0;
}
