/*
 * libFuzzer harness for R's date/time parsing.
 *
 * Passes fuzzed input as a character string through strptime, as.Date,
 * as.POSIXct, and as.POSIXlt -- exercising R_strptime (Rstrptime.h) and
 * src/main/datetime.c: ~2000 lines of locale-dependent parsing, timezone
 * handling, leap seconds, and DST transitions.
 *
 * Adapted from r-afl's datetime harness.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)

/*
 * strptime format strings, each exercising a different path in
 * Rstrptime.h's strptime_internal (numeric fields, locale month/weekday
 * names, ISO 8601 zone offset, locale preferred representations).
 */
#define N_FORMATS 6
static const char *strptime_formats[N_FORMATS] = {
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y",
    "%Y-%m-%dT%H:%M:%S%z",
    "%c",
    "%x %X",
    "%a %d %b %Y",
};

#define N_CALLS (N_FORMATS + 3)

static SEXP x_str;
static SEXP calls[N_CALLS];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_init_r();

    SEXP sym_strptime   = Rf_install("strptime");
    SEXP sym_as_Date    = Rf_install("as.Date");
    SEXP sym_as_POSIXct = Rf_install("as.POSIXct");
    SEXP sym_as_POSIXlt = Rf_install("as.POSIXlt");

    /* Reusable input container -- each iteration swaps its CHARSXP. */
    Rf_protect(x_str = Rf_allocVector(STRSXP, 1));

    SEXP tz_utc;
    Rf_protect(tz_utc = Rf_mkString("UTC"));

    /* strptime(x, format=fmt, tz="UTC") for each fixed format */
    for (int i = 0; i < N_FORMATS; i++) {
        SEXP fmt;
        Rf_protect(fmt = Rf_mkString(strptime_formats[i]));
        Rf_protect(calls[i] = Rf_lang4(sym_strptime, x_str, fmt, tz_utc));
        SET_TAG(CDDR(calls[i]), Rf_install("format"));
        SET_TAG(CDR(CDDR(calls[i])), Rf_install("tz"));
    }

    /* as.Date(x, format="%Y-%m-%d") */
    {
        SEXP date_fmt;
        Rf_protect(date_fmt = Rf_mkString("%Y-%m-%d"));
        Rf_protect(calls[N_FORMATS] = Rf_lang3(sym_as_Date, x_str, date_fmt));
        SET_TAG(CDDR(calls[N_FORMATS]), Rf_install("format"));
    }

    /* as.POSIXct(x, tz="UTC") */
    Rf_protect(calls[N_FORMATS + 1] = Rf_lang3(sym_as_POSIXct, x_str, tz_utc));
    SET_TAG(CDDR(calls[N_FORMATS + 1]), Rf_install("tz"));

    /* as.POSIXlt(x, tz="UTC") */
    Rf_protect(calls[N_FORMATS + 2] = Rf_lang3(sym_as_POSIXlt, x_str, tz_utc));
    SET_TAG(CDDR(calls[N_FORMATS + 2]), Rf_install("tz"));

    /* Warmup: prime datetime internals. */
    {
        int error = 0;
        SET_STRING_ELT(x_str, 0, Rf_mkChar("2024-01-15 12:30:00"));
        for (int i = 0; i < N_CALLS; i++) {
            R_tryEval(calls[i], R_GlobalEnv, &error);
            error = 0;
        }
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > FUZZ_MAX_INPUT)
        return 0;

    char buf[FUZZ_MAX_INPUT + 1];
    memcpy(buf, data, size);
    buf[size] = '\0';

    if (!fuzz_set_string(x_str, buf))
        return 0;

    fuzz_eval_data_t ed = { .env = R_GlobalEnv };
    for (int i = 0; i < N_CALLS; i++) {
        ed.call = calls[i];
        R_ToplevelExec(fuzz_do_eval, &ed);
    }

    return 0;
}
