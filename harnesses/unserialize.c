/*
 * libFuzzer harness for R's deserializer.
 *
 * Feeds raw bytes to the serialization format parser (src/main/serialize.c)
 * either directly, as unserialize() on a raw vector, or through the
 * connection-backed readers that readRDS() really uses: a rawConnection,
 * and a rawConnection wrapped in gzcon() so the gzip framing layer in
 * connections.c is parsed too.  The last input byte selects the route.
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
#define N_CALLS 4

/* Slot 0 is the raw-vector route the original harness used.  The others
 * close their connection on exit so a failed read cannot leak one of
 * R's 128 connection slots across iterations. */
static const char *const sources[N_CALLS] = {
    "function(x) unserialize(x)",
    "function(x) { con <- rawConnection(x); on.exit(close(con)); "
    "unserialize(con) }",
    "function(x) { con <- rawConnection(x); on.exit(close(con)); "
    "readRDS(con) }",
    "function(x) { con <- gzcon(rawConnection(x)); on.exit(close(con)); "
    "readRDS(con) }",
};

static SEXP calls[N_CALLS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    for (int i = 0; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang2(wrapper, Rf_allocVector(RAWSXP, 1)));
    }

    /* Warmup: serialize(NULL, NULL) to get a valid RDS blob, then
     * round-trip it through every route to prime the code paths. */
    {
        int error = 0;
        SEXP ser_call;
        Rf_protect(ser_call = Rf_lang3(Rf_install("serialize"),
                                       R_NilValue, R_NilValue));
        SEXP w_raw = R_tryEval(ser_call, R_GlobalEnv, &error);
        if (!error && w_raw != R_NilValue) {
            Rf_protect(w_raw);
            for (int i = 0; i < N_CALLS; i++) {
                SETCADR(calls[i], w_raw);
                fuzz_eval_silent(calls[i], R_GlobalEnv);
            }
            Rf_unprotect(1);
        }
        Rf_unprotect(1); /* ser_call */
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT)
        return 0;

    /* The last byte picks the route and stays in the payload: the
     * deserializer ignores trailing bytes, so every stored input keeps
     * its full meaning on every route. */
    int selected = data[size - 1] % N_CALLS;
    if (!fuzz_set_raw_arg(calls[selected], data, size))
        return 0;

    fuzz_eval_silent(calls[selected], R_GlobalEnv);
    return 0;
}
