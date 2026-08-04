/*
 * libFuzzer harness for R's deserializer.
 *
 * Feeds raw bytes to unserialize() as a raw vector -- exercising R's
 * serialization format parser (src/main/serialize.c).
 *
 * The serialization format is used for .rds/.RData files, and users
 * routinely deserialize data from untrusted sources via readRDS().
 * This is a critical security surface.
 *
 * Adapted from r-afl's unserialize harness.
 */

#include <stdint.h>
#include <string.h>

#include "fuzz_common.h"

#define FUZZ_MAX_INPUT (1024 * 64)

static SEXP call_unser;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_init_r();

    /* Pre-build the call: unserialize(<placeholder>) */
    Rf_protect(call_unser = Rf_lang2(Rf_install("unserialize"),
                                     Rf_allocVector(RAWSXP, 1)));

    /* Warmup: serialize(NULL, NULL) to get a valid RDS blob, then
     * round-trip it through unserialize to prime the code path. */
    {
        int error = 0;
        SEXP ser_call;
        Rf_protect(ser_call = Rf_lang3(Rf_install("serialize"),
                                       R_NilValue, R_NilValue));
        SEXP w_raw = R_tryEval(ser_call, R_GlobalEnv, &error);
        if (!error && w_raw != R_NilValue) {
            Rf_protect(w_raw);
            SETCADR(call_unser, w_raw);
            fuzz_eval_data_t ed = { .call = call_unser, .env = R_GlobalEnv };
            R_ToplevelExec(fuzz_do_eval, &ed);
            Rf_unprotect(1);
        }
        Rf_unprotect(1); /* ser_call */
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_MAX_INPUT)
        return 0;

    SEXP raw_vec;
    Rf_protect(raw_vec = Rf_allocVector(RAWSXP, size));
    memcpy(RAW(raw_vec), data, size);

    SETCADR(call_unser, raw_vec);

    fuzz_eval_data_t ed = { .call = call_unser, .env = R_GlobalEnv };
    R_ToplevelExec(fuzz_do_eval, &ed);

    Rf_unprotect(1);
    return 0;
}
