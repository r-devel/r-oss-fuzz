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

/* This target spends most of its time in R's GC rather than in the
 * deserializer.  A serialized stream names the length of a vector before
 * its contents, so a few hundred bytes of input ask allocVector for
 * hundreds of megabytes; against the shared 1Gb default R answers each
 * such request with a full collection of a near-1Gb heap.  In CI the
 * target sits pinned at the cap (rss 917Mb) running 12-16 exec/s while
 * every other target runs in the hundreds, and that is what starved the
 * corpus merge during the prune run.
 *
 * Halving the cap roughly halves the cost of each of those collections.
 * Replaying the pruned corpus locally, one pass over 535 inputs:
 *
 *     1Gb     5.78s / 6.43s      ~88 exec/s
 *     512Mb   2.35s / 2.53s     ~220 exec/s
 *     256Mb   2.64s / 2.78s     ~198 exec/s
 *
 * The win is all in the first step down and it plateaus below that, so
 * take 512Mb: the smallest change from the default that captures it.
 * The cost is coverage of the paths that read a vector larger than
 * 512Mb -- those inputs now hit the vector limit inside allocVector and
 * are discarded before InIntegerVec/InRealVec run.  That is a deliberate
 * trade: bugs in those read loops reproduce at any length, and the loops
 * are still reached by every input under the cap. */
#define FUZZ_R_MAX_VSIZE "512Mb"

#include "common.h"

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

    if (!fuzz_set_raw_arg(call_unser, data, size))
        return 0;

    fuzz_eval_data_t ed = { .call = call_unser, .env = R_GlobalEnv };
    R_ToplevelExec(fuzz_do_eval, &ed);

    return 0;
}
