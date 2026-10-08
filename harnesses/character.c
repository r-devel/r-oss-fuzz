/*
 * Exercise byte-, character-, width-, substring-, case-, translation- and
 * quoting operations on strings (src/main/character.c, raw.c, and the
 * strsplit entry of grep.c).
 *
 * Input layout: the first byte selects a call slot, the rest is the
 * payload.  Slots 0-8 take the whole payload as the string (the original
 * shape of this target, so the stored corpus keeps its meaning).  Slots 9
 * and up split the payload at its first newline into an auxiliary string
 * (regex or fixed split pattern, chartr translation spec, replacement
 * text) before the newline and the subject string after it; without a
 * newline a default auxiliary string is used.
 *
 * Several slots hand R the same bytes marked as UTF-8 or latin1 instead
 * of native.  R does not validate the mark (users can set it with
 * Encoding<-), so this reaches the multibyte branches and their handling
 * of invalid sequences without changing the process locale.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_FIXED_CALLS 9
#define N_CALLS 34

#define DEFAULT_AUX "[ ,;]+"

/* Which input vectors a slot reads; only those are refilled. */
#define NEED_X      0x01
#define NEED_XU     0x02
#define NEED_XL     0x04
#define NEED_AUX    0x08
#define NEED_AUXU   0x10
#define NEED_REGEX  0x20   /* aux is a regex: apply the repeat guard */

static SEXP input_string;   /* native */
static SEXP input_utf8;     /* same bytes, marked UTF-8 */
static SEXP input_latin1;   /* same bytes, marked latin1 */
static SEXP aux_string;
static SEXP aux_utf8;

static SEXP calls[N_CALLS];
static unsigned needs[N_CALLS];

static SEXP tagged(SEXP call, int pos, const char *tag)
{
    SEXP cell = call;
    for (int i = 0; i < pos; i++)
        cell = CDR(cell);
    SET_TAG(cell, Rf_install(tag));
    return call;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    SEXP bytes, chars, width, true_value, one, end, empty, quote, none;
    Rf_protect(input_string = Rf_allocVector(STRSXP, 1));
    Rf_protect(input_utf8 = Rf_allocVector(STRSXP, 1));
    Rf_protect(input_latin1 = Rf_allocVector(STRSXP, 1));
    Rf_protect(aux_string = Rf_allocVector(STRSXP, 1));
    Rf_protect(aux_utf8 = Rf_allocVector(STRSXP, 1));
    Rf_protect(bytes = Rf_mkString("bytes"));
    Rf_protect(chars = Rf_mkString("chars"));
    Rf_protect(width = Rf_mkString("width"));
    Rf_protect(true_value = Rf_ScalarLogical(TRUE));
    Rf_protect(one = Rf_ScalarInteger(1));
    Rf_protect(end = Rf_ScalarInteger(32));
    Rf_protect(empty = Rf_mkString(""));
    Rf_protect(quote = Rf_mkString("\""));
    Rf_protect(none = Rf_mkString("none"));

    SEXP nchar = Rf_install("nchar");
    Rf_protect(calls[0] = Rf_lang3(nchar, input_string, bytes));
    SET_TAG(CDDR(calls[0]), Rf_install("type"));
    Rf_protect(calls[1] = Rf_lang3(nchar, input_string, chars));
    SET_TAG(CDDR(calls[1]), Rf_install("type"));
    Rf_protect(calls[2] = Rf_lang3(nchar, input_string, width));
    SET_TAG(CDDR(calls[2]), Rf_install("type"));
    Rf_protect(calls[3] = Rf_lang4(Rf_install("substr"), input_string, one, end));
    Rf_protect(calls[4] = Rf_lang4(Rf_install("substring"), input_string, one, end));
    Rf_protect(calls[5] = Rf_lang4(Rf_install("strsplit"), input_string, empty,
                                   true_value));
    SET_TAG(CDDDR(calls[5]), Rf_install("fixed"));
    Rf_protect(calls[6] = Rf_lang5(Rf_install("encodeString"), input_string,
                                   quote, none, true_value));
    SET_TAG(CDDR(calls[6]), Rf_install("quote"));
    SET_TAG(CDDDR(calls[6]), Rf_install("justify"));
    SET_TAG(CDR(CDDDR(calls[6])), Rf_install("na.encode"));
    Rf_protect(calls[7] = Rf_lang3(Rf_install("make.names"), input_string,
                                   true_value));
    SET_TAG(CDDR(calls[7]), Rf_install("unique"));

    SEXP to_raw;
    Rf_protect(to_raw = Rf_lang2(Rf_install("charToRaw"), input_string));
    Rf_protect(calls[8] = Rf_lang3(Rf_install("rawToChar"), to_raw, true_value));
    SET_TAG(CDDR(calls[8]), Rf_install("multiple"));
    for (int i = 0; i < N_FIXED_CALLS; i++)
        needs[i] = NEED_X;

    SEXP strsplit = Rf_install("strsplit");
    SEXP strtoi = Rf_install("strtoi");
    SEXP toupper = Rf_install("toupper");
    SEXP chartr = Rf_install("chartr");
    SEXP utf8ToInt = Rf_install("utf8ToInt");
    SEXP intToUtf8 = Rf_install("intToUtf8");
    SEXP two, three, four, ten, sixteen, thirtysix, scale;
    Rf_protect(two = Rf_ScalarInteger(2));
    Rf_protect(three = Rf_ScalarInteger(3));
    Rf_protect(four = Rf_ScalarInteger(4));
    Rf_protect(ten = Rf_ScalarInteger(10));
    Rf_protect(sixteen = Rf_ScalarInteger(16));
    Rf_protect(thirtysix = Rf_ScalarInteger(36));
    Rf_protect(scale = Rf_ScalarInteger(4099));

    /* Inner calls are built first and protected, since the outer
     * Rf_lang* allocates while holding them. */
    SEXP upper_aux, upper_aux_utf8, codepoints, scaled_bytes;
    Rf_protect(upper_aux = Rf_lang2(toupper, aux_string));
    Rf_protect(upper_aux_utf8 = Rf_lang2(toupper, aux_utf8));
    Rf_protect(codepoints = Rf_lang2(utf8ToInt, input_string));
    Rf_protect(scaled_bytes = Rf_lang2(Rf_install("as.integer"), to_raw));
    Rf_protect(scaled_bytes = Rf_lang3(Rf_install("*"), scaled_bytes, scale));

    int k = N_FIXED_CALLS;

    /* strsplit: TRE, PCRE, fixed and byte-wise matching, on native and
     * UTF-8-marked input.  Only the empty fixed split ran before. */
    Rf_protect(calls[k] = Rf_lang3(strsplit, input_string, aux_string));
    needs[k++] = NEED_X | NEED_AUX | NEED_REGEX;
    Rf_protect(calls[k] = tagged(Rf_lang4(strsplit, input_string, aux_string,
                                          true_value), 3, "perl"));
    needs[k++] = NEED_X | NEED_AUX | NEED_REGEX;
    Rf_protect(calls[k] = tagged(Rf_lang4(strsplit, input_string, aux_string,
                                          true_value), 3, "fixed"));
    needs[k++] = NEED_X | NEED_AUX;
    Rf_protect(calls[k] = tagged(Rf_lang4(strsplit, input_string, aux_string,
                                          true_value), 3, "useBytes"));
    needs[k++] = NEED_X | NEED_AUX | NEED_REGEX;
    Rf_protect(calls[k] = Rf_lang3(strsplit, input_utf8, aux_utf8));
    needs[k++] = NEED_XU | NEED_AUXU | NEED_REGEX;
    Rf_protect(calls[k] = tagged(Rf_lang4(strsplit, input_utf8, aux_utf8,
                                          true_value), 3, "perl"));
    needs[k++] = NEED_XU | NEED_AUXU | NEED_REGEX;
    Rf_protect(calls[k] = tagged(Rf_lang4(strsplit, input_utf8, aux_utf8,
                                          true_value), 3, "fixed"));
    needs[k++] = NEED_XU | NEED_AUXU;

    /* nchar on marked strings: the UTF-8 and latin1 branches of R_nchar,
     * including allowNA for invalid sequences. */
    Rf_protect(calls[k] = tagged(tagged(Rf_lang4(nchar, input_utf8, chars,
                                                 true_value), 2, "type"),
                                 3, "allowNA"));
    needs[k++] = NEED_XU;
    Rf_protect(calls[k] = tagged(tagged(Rf_lang4(nchar, input_utf8, width,
                                                 true_value), 2, "type"),
                                 3, "allowNA"));
    needs[k++] = NEED_XU;
    Rf_protect(calls[k] = tagged(tagged(Rf_lang4(nchar, input_latin1, chars,
                                                 true_value), 2, "type"),
                                 3, "allowNA"));
    needs[k++] = NEED_XL;

    /* chartr(old, new, x): old and new must have the same number of
     * characters, which toupper preserves, so the spec parser (ranges,
     * escapes) runs on fuzzed text while the call stays valid. */
    Rf_protect(calls[k] = Rf_lang4(chartr, aux_string, upper_aux, input_string));
    needs[k++] = NEED_X | NEED_AUX;
    Rf_protect(calls[k] = Rf_lang4(chartr, aux_utf8, upper_aux_utf8, input_utf8));
    needs[k++] = NEED_XU | NEED_AUXU;

    /* strtoi in the bases with distinct digit handling */
    Rf_protect(calls[k] = Rf_lang3(strtoi, input_string, ten));
    needs[k++] = NEED_X;
    Rf_protect(calls[k] = Rf_lang3(strtoi, input_string, sixteen));
    needs[k++] = NEED_X;
    Rf_protect(calls[k] = Rf_lang3(strtoi, input_string, thirtysix));
    needs[k++] = NEED_X;

    Rf_protect(calls[k] = Rf_lang3(Rf_install("strtrim"), input_utf8, ten));
    needs[k++] = NEED_XU;
    Rf_protect(calls[k] = Rf_lang2(toupper, input_utf8));
    needs[k++] = NEED_XU;
    Rf_protect(calls[k] = Rf_lang2(Rf_install("tolower"), input_latin1));
    needs[k++] = NEED_XL;
    Rf_protect(calls[k] = tagged(Rf_lang3(Rf_install("abbreviate"), input_string,
                                          four), 2, "minlength"));
    needs[k++] = NEED_X;

    /* substr(x, 2, 10) <- aux */
    Rf_protect(calls[k] = Rf_lang5(Rf_install("substr<-"), input_utf8, two, ten,
                                   aux_utf8));
    needs[k++] = NEED_XU | NEED_AUXU;

    Rf_protect(calls[k] = Rf_lang3(Rf_install("strrep"), input_string, three));
    needs[k++] = NEED_X;

    /* UTF-8 <-> code point conversion in raw.c, and intToUtf8 fed code
     * points scaled out of the bytes to reach surrogates and 4-byte
     * forms. */
    calls[k] = codepoints;
    needs[k++] = NEED_X;
    Rf_protect(calls[k] = tagged(Rf_lang3(intToUtf8, codepoints, true_value),
                                 2, "multiple"));
    needs[k++] = NEED_X;
    Rf_protect(calls[k] = Rf_lang2(intToUtf8, scaled_bytes));
    needs[k++] = NEED_X;

    Rf_protect(calls[k] = Rf_lang4(Rf_install("substr"), input_utf8, two, end));
    needs[k++] = NEED_XU;

    if (k != N_CALLS)
        abort();

    SET_STRING_ELT(input_string, 0, Rf_mkChar("fuzz"));
    SET_STRING_ELT(input_utf8, 0, Rf_mkCharCE("fuzz", CE_UTF8));
    SET_STRING_ELT(input_latin1, 0, Rf_mkCharCE("fuzz", CE_LATIN1));
    SET_STRING_ELT(aux_string, 0, Rf_mkChar(DEFAULT_AUX));
    SET_STRING_ELT(aux_utf8, 0, Rf_mkCharCE(DEFAULT_AUX, CE_UTF8));
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT || memchr(data + 1, '\0', size - 1))
        return 0;

    int selected = data[0] % N_CALLS;
    unsigned need = needs[selected];

    char buffer[FUZZ_MAX_INPUT];
    memcpy(buffer, data + 1, size - 1);
    buffer[size - 1] = '\0';

    const char *aux = DEFAULT_AUX;
    const char *subject = buffer;
    if (selected >= N_FIXED_CALLS) {
        char *nl = memchr(buffer, '\n', size - 1);
        if (nl != NULL) {
            *nl = '\0';
            aux = buffer;
            subject = nl + 1;
        }
    }

    /* TRE duplicates the AST for counted repeats; see common.h. */
    if ((need & NEED_REGEX) && fuzz_repeat_product_excessive(aux))
        return 0;

    if ((need & NEED_X) && !fuzz_set_string(input_string, subject))
        return 0;
    if ((need & NEED_XU) && !fuzz_set_string_ce(input_utf8, subject, CE_UTF8))
        return 0;
    if ((need & NEED_XL) && !fuzz_set_string_ce(input_latin1, subject, CE_LATIN1))
        return 0;
    if ((need & NEED_AUX) && !fuzz_set_string(aux_string, aux))
        return 0;
    if ((need & NEED_AUXU) && !fuzz_set_string_ce(aux_utf8, aux, CE_UTF8))
        return 0;

    fuzz_eval_silent(calls[selected], R_GlobalEnv);
    return 0;
}
