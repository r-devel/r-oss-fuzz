/*
 * Shared helpers for R fuzzing harnesses (libFuzzer).
 *
 * Provides:
 *   fuzz_suppress_warnings() - Suppress R warnings to avoid buffer overflow
 *   fuzz_init_r()          - Full R initialization sequence
 *
 * Adapted from r-afl's fuzz.h for use with libFuzzer instead of AFL++.
 */

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <limits.h>
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
 * ("vector memory limit of N reached"), which the R_ToplevelExec wrapper
 * below already catches -- so the iteration is discarded and fuzzing carries
 * on.  That is the reason to prefer this over a sanitizer-level RSS limit:
 * ASAN's soft_rss_limit_mb either aborts the process or starts handing NULL
 * back to allocators that never expected it, and both look like crashes.
 * Replaying a synthetic length-field bomb takes peak RSS from 3103MB to
 * 51MB with this set, with the process surviving every iteration.
 *
 * This bounds R's own vector heap ONLY, and is not the fix for the largest
 * peaks seen in CI.  Replaying the stored agrep corpus shows 8.5GB of RSS
 * driven entirely by TRE compiling a 36-byte nested-repetition pattern,
 * unchanged whether this limit is set or not.  Nor does libFuzzer's
 * -malloc_limit_mb help there: that blowup is ~2.5 million allocations
 * whose largest single member is 277MB, so a single-allocation limit high
 * enough to be safe never fires.  Bounding that needs a guard on the
 * pattern itself.
 *
 * The limit is deliberately far above anything a legitimate ~64KB input
 * needs, so it costs no coverage; override R_MAX_VSIZE to retune.
 */
static void fuzz_set_vsize_limit(void)
{
    if (getenv("R_MAX_VSIZE") == NULL)
        setenv("R_MAX_VSIZE", "1Gb", 1);
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

#endif /* FUZZ_COMMON_H */
