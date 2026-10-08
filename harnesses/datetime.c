/*
 * libFuzzer harness for R's date/time parsing and formatting.
 *
 * Passes fuzzed input through strptime, as.Date, as.POSIXct, as.POSIXlt,
 * format.POSIXlt and balancePOSIXlt -- exercising R_strptime (Rstrptime.h)
 * and src/main/datetime.c: ~2000 lines of locale-dependent parsing,
 * timezone handling, leap seconds, and DST transitions.
 *
 * Input layout: the first byte selects a call slot, the rest is the
 * payload.  Slots 0-8 take the whole payload as the datetime string and
 * use fixed format strings (the original shape of this target, so the
 * stored corpus keeps its meaning).  Slots 9 and up split the payload at
 * its first newline: the format string comes before it and the datetime
 * string after, so strptime directives and strftime output are fuzzed
 * too.  Without a newline the payload is the datetime string and a
 * default format is used.
 *
 * Adapted from r-afl's datetime harness.
 */

#include <locale.h>
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

#define N_FIXED_CALLS (N_FORMATS + 3)
#define N_FMT_CALLS 8
#define N_CALLS (N_FIXED_CALLS + N_FMT_CALLS)

/* Slots from this index on run with a UTF-8 LC_CTYPE so R_strptime takes
 * its wide-character path (w_strptime_internal), which is otherwise
 * unreachable from a C-locale fuzzer. */
#define FIRST_UTF8_CALL (N_CALLS - 2)

#define DEFAULT_FORMAT "%Y-%m-%d %H:%M:%OS"

static SEXP x_str;
static SEXP fmt_str;
static SEXP calls[N_CALLS];

static SEXP call_ctype_utf8;
static SEXP call_ctype_c;
static int ctype_is_utf8 = 0;

/* Pick a UTF-8 locale this runner has.  Returns NULL when none exists,
 * in which case the UTF-8 slots simply run in the C locale. */
static const char *find_utf8_locale(void)
{
    static const char *const candidates[] = { "C.UTF-8", "en_US.UTF-8", NULL };
    const char *found = NULL;

    for (int i = 0; candidates[i] != NULL; i++) {
        if (setlocale(LC_CTYPE, candidates[i]) != NULL) {
            found = candidates[i];
            break;
        }
    }
    setlocale(LC_CTYPE, "C");
    return found;
}

static SEXP make_setlocale_call(const char *name)
{
    SEXP call;
    Rf_protect(call = Rf_lang3(Rf_install("Sys.setlocale"),
                               Rf_mkString("LC_CTYPE"), Rf_mkString(name)));
    return call;
}

/* Switch LC_CTYPE only when a slot needs the other setting; Sys.setlocale
 * is cheap but not free, and consecutive inputs usually share a slot. */
static void set_ctype(int want_utf8)
{
    if (call_ctype_utf8 == NULL || want_utf8 == ctype_is_utf8)
        return;

    fuzz_eval_silent(want_utf8 ? call_ctype_utf8 : call_ctype_c, R_GlobalEnv);
    ctype_is_utf8 = want_utf8;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_init_r();

    SEXP sym_strptime   = Rf_install("strptime");
    SEXP sym_as_Date    = Rf_install("as.Date");
    SEXP sym_as_POSIXct = Rf_install("as.POSIXct");
    SEXP sym_as_POSIXlt = Rf_install("as.POSIXlt");
    SEXP sym_format     = Rf_install("format");
    SEXP sym_tz         = Rf_install("tz");

    /* Reusable input containers -- each iteration swaps their CHARSXPs. */
    Rf_protect(x_str = Rf_allocVector(STRSXP, 1));
    Rf_protect(fmt_str = Rf_allocVector(STRSXP, 1));

    SEXP tz_utc, tz_london, true_val;
    Rf_protect(tz_utc = Rf_mkString("UTC"));
    Rf_protect(tz_london = Rf_mkString("Europe/London"));
    Rf_protect(true_val = Rf_ScalarLogical(TRUE));

    /* strptime(x, format=fmt, tz="UTC") for each fixed format */
    for (int i = 0; i < N_FORMATS; i++) {
        SEXP fmt;
        Rf_protect(fmt = Rf_mkString(strptime_formats[i]));
        Rf_protect(calls[i] = Rf_lang4(sym_strptime, x_str, fmt, tz_utc));
        SET_TAG(CDDR(calls[i]), sym_format);
        SET_TAG(CDR(CDDR(calls[i])), sym_tz);
    }

    /* as.Date(x, format="%Y-%m-%d") */
    {
        SEXP date_fmt;
        Rf_protect(date_fmt = Rf_mkString("%Y-%m-%d"));
        Rf_protect(calls[N_FORMATS] = Rf_lang3(sym_as_Date, x_str, date_fmt));
        SET_TAG(CDDR(calls[N_FORMATS]), sym_format);
    }

    /* as.POSIXct(x, tz="UTC") */
    Rf_protect(calls[N_FORMATS + 1] = Rf_lang3(sym_as_POSIXct, x_str, tz_utc));
    SET_TAG(CDDR(calls[N_FORMATS + 1]), sym_tz);

    /* as.POSIXlt(x, tz="UTC") */
    Rf_protect(calls[N_FORMATS + 2] = Rf_lang3(sym_as_POSIXlt, x_str, tz_utc));
    SET_TAG(CDDR(calls[N_FORMATS + 2]), sym_tz);

    /* The fuzzed-format slots.  strptime(x, fmt, tz="UTC") is shared by
     * several of them as the inner call. */
    SEXP strptime_fmt;
    Rf_protect(strptime_fmt = Rf_lang4(sym_strptime, x_str, fmt_str, tz_utc));
    SET_TAG(CDDR(strptime_fmt), sym_format);
    SET_TAG(CDR(CDDR(strptime_fmt)), sym_tz);

    int k = N_FIXED_CALLS;

    /* [9] strptime(x, fmt, tz="UTC") */
    calls[k++] = strptime_fmt;

    /* [10] format(strptime(x, fmt, tz="UTC"), format=fmt, usetz=TRUE)
     * -- do_formatPOSIXlt with a fuzzed strftime format */
    Rf_protect(calls[k] = Rf_lang4(sym_format, strptime_fmt, fmt_str, true_val));
    SET_TAG(CDDR(calls[k]), sym_format);
    SET_TAG(CDR(CDDR(calls[k])), Rf_install("usetz"));
    k++;

    /* [11] as.POSIXlt(as.Date(x, format=fmt)) -- do_D2POSIXlt */
    {
        SEXP as_date;
        Rf_protect(as_date = Rf_lang3(sym_as_Date, x_str, fmt_str));
        SET_TAG(CDDR(as_date), sym_format);
        Rf_protect(calls[k] = Rf_lang2(sym_as_POSIXlt, as_date));
        k++;
    }

    /* [12] format(as.POSIXct(x, format=fmt, tz="UTC"), format=fmt) */
    {
        SEXP as_ct;
        Rf_protect(as_ct = Rf_lang4(sym_as_POSIXct, x_str, fmt_str, tz_utc));
        SET_TAG(CDDR(as_ct), sym_format);
        SET_TAG(CDR(CDDR(as_ct)), sym_tz);
        Rf_protect(calls[k] = Rf_lang3(sym_format, as_ct, fmt_str));
        SET_TAG(CDDR(calls[k]), sym_format);
        k++;
    }

    /* [13], [14] Perturb the parsed fields by amounts taken from the
     * input bytes, then balance, convert and format the result.  A
     * strptime result carries a "balanced" attribute that short-circuits
     * balancePOSIXlt, so dropping it is what reaches the normalisation
     * code in balancePOSIXlt, mktime0 and localtime0; the second slot
     * uses a DST-observing zone so the local-time paths run. */
    {
        static const char *const source =
            "function(x, fmt, tz) {\n"
            "    lt <- unclass(strptime(x, fmt, tz = tz))\n"
            "    attr(lt, \"balanced\") <- NULL\n"
            "    b <- as.integer(charToRaw(x))\n"
            "    fields <- c(\"sec\", \"min\", \"hour\", \"mday\", \"mon\", \"year\")\n"
            "    for (i in seq_len(min(length(b), length(fields))))\n"
            "        lt[[fields[i]]] <- lt[[fields[i]]] + (b[i] - 128L) * 7L\n"
            "    class(lt) <- c(\"POSIXlt\", \"POSIXt\")\n"
            "    bal <- balancePOSIXlt(lt)\n"
            "    ct <- as.POSIXct(lt)\n"
            "    invisible(list(as.POSIXlt(ct, tz = tz), as.Date(lt),\n"
            "                   format(bal, fmt, usetz = TRUE), format(ct)))\n"
            "}";
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(source));
        Rf_protect(calls[k] = Rf_lang4(wrapper, x_str, fmt_str, tz_utc));
        k++;
        Rf_protect(calls[k] = Rf_lang4(wrapper, x_str, fmt_str, tz_london));
        k++;
    }

    /* [15], [16] The same strptime and format calls, run under a UTF-8
     * LC_CTYPE (see set_ctype). */
    calls[k++] = calls[N_FIXED_CALLS];
    calls[k++] = calls[N_FIXED_CALLS + 1];

    if (k != N_CALLS)
        abort();

    const char *utf8_locale = find_utf8_locale();
    if (utf8_locale != NULL) {
        call_ctype_utf8 = make_setlocale_call(utf8_locale);
        call_ctype_c = make_setlocale_call("C");
    }

    /* Warmup: prime datetime internals. */
    {
        int error = 0;
        SET_STRING_ELT(x_str, 0, Rf_mkChar("2024-01-15 12:30:00"));
        SET_STRING_ELT(fmt_str, 0, Rf_mkChar(DEFAULT_FORMAT));
        for (int i = 0; i < N_CALLS; i++) {
            R_tryEval(calls[i], R_GlobalEnv, &error);
            error = 0;
        }
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT || memchr(data + 1, '\0', size - 1))
        return 0;

    int selected = data[0] % N_CALLS;
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    char buf[FUZZ_MAX_INPUT + 1];
    const char *fmt = DEFAULT_FORMAT;
    const char *value = buf;

    if (selected < N_FIXED_CALLS) {
        memcpy(buf, payload, payload_size);
        buf[payload_size] = '\0';
    } else {
        /* "<format>\n<datetime>"; the NUL replacing the newline splits
         * the one buffer into both strings. */
        memcpy(buf, payload, payload_size);
        buf[payload_size] = '\0';
        char *nl = memchr(buf, '\n', payload_size);
        if (nl != NULL) {
            *nl = '\0';
            fmt = buf;
            value = nl + 1;
        }
    }

    if (!fuzz_set_string(x_str, value))
        return 0;
    if (!fuzz_set_string(fmt_str, fmt))
        return 0;

    set_ctype(selected >= FIRST_UTF8_CALL);

    fuzz_eval_data_t ed = { .call = calls[selected], .env = R_GlobalEnv };
    R_ToplevelExec(fuzz_do_eval, &ed);

    return 0;
}
