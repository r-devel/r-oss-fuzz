/*
 * Shared helpers for R fuzzing harnesses (libFuzzer).
 *
 * Provides:
 *   fuzz_suppress_warnings() - Suppress R warnings to avoid buffer overflow
 *   fuzz_init_r()            - Full R initialization sequence
 *   fuzz_set_string()        - Stage a string input under a toplevel context
 *   fuzz_set_raw_arg()       - Stage a raw-vector input likewise
 *   fuzz_repeat_product_excessive() - Guard against TRE repeat blowup
 *
 * Adapted from r-afl's fuzz.h for use with libFuzzer instead of AFL++.
 */

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define R_NO_REMAP 1
#include <Rembedded.h>
#include <Rinternals.h>
#include <Rinterface.h>   /* R_SignalHandlers */
#include <R_ext/Parse.h>

/*
 * Suppress R warnings globally.
 *
 * Many R functions emit warnings on invalid input (e.g., "NAs introduced
 * by coercion").  In persistent fuzzing, these accumulate and can overflow
 * R's warning buffer, triggering fatal errors.  Setting warn = -1
 * suppresses all warnings.
 */
static void fuzz_suppress_warnings(void)
{
    int error = 0;
    SEXP warn_call;
    Rf_protect(warn_call = Rf_lang2(Rf_install("options"),
                                    Rf_ScalarInteger(-1)));
    SET_TAG(CDR(warn_call), Rf_install("warn"));
    R_tryEval(warn_call, R_GlobalEnv, &error);
    Rf_unprotect(1);
}

/*
 * Set R_HOME based on the fuzzer binary's location.
 *
 * OSS-Fuzz places everything in $OUT.  The build.sh installs R to
 * $OUT/r-install, so R_HOME is at $OUT/r-install/lib/R.  We derive
 * this from /proc/self/exe so it works regardless of the mount path.
 */
static void fuzz_set_r_home(void)
{
    /* Skip if R_HOME is already set (e.g., for local testing) */
    if (getenv("R_HOME") != NULL)
        return;

    char exe[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len <= 0)
        return;
    exe[len] = '\0';

    /* Find the directory containing the binary */
    char *slash = strrchr(exe, '/');
    if (slash == NULL)
        return;
    *slash = '\0';

    char r_home[PATH_MAX];
    snprintf(r_home, sizeof(r_home), "%s/r-install/lib/R", exe);
    setenv("R_HOME", r_home, 1);
}

/*
 * Cap R's vector heap.
 *
 * Hostile input reaches R's allocator directly -- a serialized vector can
 * declare any length it likes, and coercion or scanning can be talked into
 * asking for one -- so a 64KB input can request gigabytes.
 *
 * R enforces R_MAX_VSIZE in allocVector and signals an ordinary R error
 * ("vector memory limit of N reached").  When it fires inside R_ToplevelExec
 * the iteration is discarded and fuzzing carries on; every per-iteration
 * allocation must therefore go through fuzz_set_string / fuzz_set_raw_arg
 * below, which run under such a context.  That catchability is the reason
 * to prefer this over a sanitizer-level RSS limit: ASAN's soft_rss_limit_mb
 * either aborts the process or starts handing NULL back to allocators that
 * never expected it, and both look like crashes.
 *
 * Caveats:
 *   - The cap bounds R's cumulative LIVE vector heap, not one input's
 *     allocations.  Interned symbols are never collected, so the parse and
 *     unserialize targets ratchet toward the cap over a long run.
 *   - It bounds R's vector heap ONLY.  malloc-based allocations, like TRE
 *     compiling a pattern, bypass it entirely; see
 *     fuzz_repeat_product_excessive for that guard.
 *   - It does cost coverage of code paths that need larger results.
 *     Targets with legitimately large outputs (decompress: a 64KB bzip2
 *     stream of zeros expands past 1GB) raise the default by defining
 *     FUZZ_R_MAX_VSIZE before including this header.
 *   - R's suffix parsing is case-sensitive: "4Gb" works, "4gb" silently
 *     leaves the heap uncapped (R only warns on stderr at startup).  The
 *     env override is for local runs; the CI runner does not forward
 *     arbitrary environment variables.
 *
 * Local reproduction of vector-limit findings under plain Rscript needs
 * the same value exported; see README.md.
 */
#ifndef FUZZ_R_MAX_VSIZE
# define FUZZ_R_MAX_VSIZE "1Gb"
#endif

static void fuzz_set_vsize_limit(void)
{
    if (getenv("R_MAX_VSIZE") == NULL)
        setenv("R_MAX_VSIZE", FUZZ_R_MAX_VSIZE, 1);
}

/*
 * Initialize R for fuzzing.  Call once from LLVMFuzzerInitialize.
 *
 * Performs:
 *   1. Set R_HOME from binary location
 *   2. Cap the vector heap (must precede R's startup, which reads it)
 *   3. Initialize embedded R, without R's signal handlers
 *   4. Suppress warnings
 */
static void fuzz_init_r(void)
{
    fuzz_set_r_home();
    fuzz_set_vsize_limit();

    /* R's SIGSEGV/SIGILL/etc. handlers enter an interactive recovery
     * prompt instead of crashing, which would hang the fuzzer.  Telling
     * R not to install them (rather than resetting to SIG_DFL after
     * init) keeps the sanitizers' own handlers in place, so wild-pointer
     * faults still get full ASAN reports and clean deduplication. */
    R_SignalHandlers = 0;

    char *r_argv[] = {"R", "--vanilla", "--no-echo", "--no-restore"};
    int r_argc = sizeof(r_argv) / sizeof(r_argv[0]);
    Rf_initEmbeddedR(r_argc, r_argv);

    fuzz_suppress_warnings();
}

/*
 * Helper for protected evaluation via R_ToplevelExec.
 *
 * R API calls that touch R objects can longjmp on error.  Without a
 * top-level context, R's error handler crashes.  Wrapping calls in
 * R_ToplevelExec catches the longjmp cleanly.
 */
typedef struct {
    SEXP call;
    SEXP env;
} fuzz_eval_data_t;

static void fuzz_do_eval(void *data)
{
    fuzz_eval_data_t *ed = (fuzz_eval_data_t *)data;
    Rf_eval(ed->call, ed->env);
}

/*
 * Stage per-iteration inputs under a toplevel context.
 *
 * Rf_mkChar and Rf_allocVector can themselves signal the vector-limit
 * error.  Outside a toplevel context that error longjmps into a stack
 * frame that returned during Rf_initEmbeddedR -- undefined behaviour --
 * so input staging must be wrapped just like evaluation.  Both helpers
 * return FALSE when the allocation failed; skip the iteration then.
 */
typedef struct {
    SEXP vec;
    const char *str;
} fuzz_string_data_t;

static void fuzz_do_set_string(void *data)
{
    fuzz_string_data_t *sd = (fuzz_string_data_t *)data;
    SET_STRING_ELT(sd->vec, 0, Rf_mkChar(sd->str));
}

static Rboolean fuzz_set_string(SEXP vec, const char *str)
{
    fuzz_string_data_t sd = { vec, str };
    return R_ToplevelExec(fuzz_do_set_string, &sd);
}

typedef struct {
    SEXP call;
    const uint8_t *data;
    size_t size;
} fuzz_raw_data_t;

static void fuzz_do_set_raw(void *data)
{
    fuzz_raw_data_t *rd = (fuzz_raw_data_t *)data;

    /* The raw vector is reachable from the (protected) call as soon as
     * SETCADR runs, and nothing allocates before the memcpy completes,
     * so no extra protection is needed. */
    SEXP raw = Rf_allocVector(RAWSXP, (R_xlen_t)rd->size);
    SETCADR(rd->call, raw);
    memcpy(RAW(raw), rd->data, rd->size);
}

static Rboolean fuzz_set_raw_arg(SEXP call, const uint8_t *data, size_t size)
{
    fuzz_raw_data_t rd = { call, data, size };
    return R_ToplevelExec(fuzz_do_set_raw, &rd);
}

/*
 * Guard against TRE's bounded-repeat blowup.
 *
 * TRE compiles bounded repeats by duplicating the pattern AST, so nested
 * counted repeats multiply: a 36-byte pattern like
 * (?:a{2,101,})(?:a{2,101,}){100}{100} expands to ~10^8 nodes and >8GB of
 * allocations at compile time.  Those allocations are malloc, not R's
 * vector heap, so R_MAX_VSIZE cannot bound them; reject the pattern
 * before it reaches R instead.
 *
 * The product of all repeat bounds is a deliberate over-estimate --
 * sequential (non-nested) repeats add rather than multiply -- trading a
 * little coverage of repeat-heavy patterns for a hard bound on compile
 * cost.
 */
#define FUZZ_MAX_REPEAT_PRODUCT 1000000.0

static int fuzz_repeat_product_excessive(const char *pattern)
{
    double product = 1.0;

    for (const char *p = pattern; *p != '\0'; p++) {
        if (*p != '{')
            continue;

        /* The largest number inside the braces bounds this repeat. */
        unsigned long bound = 0, cur = 0;
        int counted = 0;
        const char *q = p + 1;
        for (; *q != '\0' && *q != '}'; q++) {
            if (*q >= '0' && *q <= '9') {
                cur = cur * 10 + (unsigned long)(*q - '0');
                if (cur > 10000000)
                    cur = 10000000;  /* saturate; already over any budget */
                counted = 1;
            } else if (*q == ',') {
                if (cur > bound)
                    bound = cur;
                cur = 0;
            } else {
                counted = 0;  /* not a counted repeat, e.g. "{a}" */
                break;
            }
        }
        if (!counted || *q != '}')
            continue;

        if (cur > bound)
            bound = cur;
        if (bound > 1)
            product *= (double)bound;
        if (product > FUZZ_MAX_REPEAT_PRODUCT)
            return 1;

        p = q;
    }

    return 0;
}

#endif /* FUZZ_COMMON_H */
