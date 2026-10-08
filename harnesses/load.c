/*
 * libFuzzer harness for load() -- R's .RData reader.
 *
 * load() reads a five-byte magic and, for RD[ABX][2-9], hands the rest
 * of the file to the serialization code that unserialize() already
 * fuzzes.  Anything else falls through to .Internal(load()) and the
 * readers in src/main/saveload.c: the pre-R-1.4.0 formats (RDA1, RDB1,
 * RDX1 via NewAsciiLoad/NewBinaryLoad/NewXdrLoad) and the even older
 * numeric-magic layouts (1971, 1972, 1975-1977 via DataLoad).  Those
 * readers are ~1700 lines that no test suite exercises, yet they still
 * run on any .RData file handed to load(), which users routinely do with
 * files from the network.
 *
 * Both slots load into a fresh environment so nothing accumulates across
 * iterations.  The entry point only takes a path, so the input is staged
 * in a per-process scratch file (see common.h).
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 2

static char *scratch_path;
static SEXP calls[N_CALLS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    scratch_path = fuzz_scratch_file("load");
    if (scratch_path == NULL)
        abort();

    /* [0] the public entry point: R-level magic check, then either
     *     loadFromConn2 (v2/v3) or the legacy .Internal(load) fallback.
     * [1] the legacy fallback directly, so the fuzzer does not have to
     *     get past the R-level grepl() on the magic to reach it. */
    static const char *const sources[N_CALLS] = {
        "function(path) load(path, envir = new.env())",
        "function(path) .Internal(load(path, new.env()))",
    };
    SEXP path;
    Rf_protect(path = Rf_mkString(scratch_path));
    for (int i = 0; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang2(wrapper, path));
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT)
        return 0;

    if (!fuzz_write_scratch(scratch_path, data + 1, size - 1))
        return 0;

    fuzz_eval_silent(calls[data[0] % N_CALLS], R_GlobalEnv);
    return 0;
}
