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
 * Initialize R for fuzzing.  Call once from LLVMFuzzerInitialize.
 *
 * Performs:
 *   1. Set R_HOME from binary location
 *   2. Initialize embedded R, without R's signal handlers
 *   3. Suppress warnings
 */
static void fuzz_init_r(void)
{
    fuzz_set_r_home();

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
