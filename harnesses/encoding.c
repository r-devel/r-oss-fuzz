/*
 * Exercise R's iconv wrapper (do_iconv in src/main/sysutils.c) and the
 * encoding-mark helpers around it with arbitrary byte strings.
 *
 * The first byte selects a call slot, the rest is the payload.  Slots 0-5
 * hand the payload to iconv() as a raw vector in a list (the original
 * shape of this target).  Later slots pass it as a character vector --
 * native, or the same bytes marked UTF-8 or latin1 without validation,
 * as Encoding<- lets users do -- which is what reaches the substitution
 * modes (sub=NA, "", "byte", "Unicode", "c99"), the mark= handling, the
 * from="" branches keyed on the CHARSXP mark, and enc2utf8/enc2native/
 * validUTF8/validEnc.  A few more raw-list slots use stateful or
 * BOM-carrying encodings so the error and restart handling in R's
 * conversion loop sees EINVAL as well as EILSEQ.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_RAW_CALLS 6
#define N_CALLS 28

/* Which input a slot reads */
#define IN_RAW    0
#define IN_STR    1
#define IN_UTF8   2
#define IN_LATIN1 3

static SEXP x_list;     /* list(<raw>) */
static SEXP x_str;      /* native character */
static SEXP x_utf8;     /* same bytes marked UTF-8 */
static SEXP x_latin1;   /* same bytes marked latin1 */
static SEXP calls[N_CALLS];
static int inputs[N_CALLS];

typedef struct {
    const uint8_t *data;
    size_t size;
} encoding_input_t;

static void set_encoding_input(void *data)
{
    encoding_input_t *input = data;
    SEXP raw = Rf_allocVector(RAWSXP, (R_xlen_t)input->size);
    memcpy(RAW(raw), input->data, input->size);
    SET_VECTOR_ELT(x_list, 0, raw);
}

/* iconv(x, from, to, sub, <extra>) with every argument named.  extra is
 * either mark= or toRaw=, which keeps each call within Rf_lang6. */
static SEXP iconv_call(SEXP x, const char *from, const char *to, SEXP sub,
                       const char *extra_name, SEXP extra)
{
    SEXP from_string, to_string, call;
    Rf_protect(from_string = Rf_mkString(from));
    Rf_protect(to_string = Rf_mkString(to));
    if (extra == NULL)
        call = Rf_lang5(Rf_install("iconv"), x, from_string, to_string, sub);
    else
        call = Rf_lang6(Rf_install("iconv"), x, from_string, to_string, sub,
                        extra);
    Rf_protect(call);

    SET_TAG(CDDR(call), Rf_install("from"));
    SET_TAG(CDR(CDDR(call)), Rf_install("to"));
    SET_TAG(CDR(CDR(CDDR(call))), Rf_install("sub"));
    if (extra != NULL)
        SET_TAG(CDR(CDR(CDR(CDDR(call)))), Rf_install(extra_name));

    /* The caller protects the returned call before anything allocates. */
    Rf_unprotect(3);
    return call;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    static const char *const from[N_RAW_CALLS] = {
        "UTF-8", "latin1", "CP1252", "UTF-16LE", "UTF-16BE", ""
    };
    static const char *const to[N_RAW_CALLS] = {
        "UTF-8", "UTF-8", "UTF-8", "UTF-8", "UTF-8", "ASCII//TRANSLIT"
    };

    Rf_protect(x_list = Rf_allocVector(VECSXP, 1));
    SET_VECTOR_ELT(x_list, 0, Rf_allocVector(RAWSXP, 0));
    Rf_protect(x_str = Rf_allocVector(STRSXP, 1));
    Rf_protect(x_utf8 = Rf_allocVector(STRSXP, 1));
    Rf_protect(x_latin1 = Rf_allocVector(STRSXP, 1));

    SEXP sub_byte, sub_unicode, sub_c99, sub_empty, sub_na, sub_qm;
    SEXP true_val, false_val;
    Rf_protect(sub_byte = Rf_mkString("byte"));
    Rf_protect(sub_unicode = Rf_mkString("Unicode"));
    Rf_protect(sub_c99 = Rf_mkString("c99"));
    Rf_protect(sub_empty = Rf_mkString(""));
    Rf_protect(sub_na = Rf_ScalarString(NA_STRING));
    Rf_protect(sub_qm = Rf_mkString("?"));
    Rf_protect(true_val = Rf_ScalarLogical(TRUE));
    Rf_protect(false_val = Rf_ScalarLogical(FALSE));

    int k = 0;
    for (int i = 0; i < N_RAW_CALLS; i++) {
        Rf_protect(calls[k] = iconv_call(x_list, from[i], to[i], sub_byte,
                                         "toRaw", true_val));
        inputs[k++] = IN_RAW;
    }

    /* Character input, explicit from: the substitution modes */
    Rf_protect(calls[k] = iconv_call(x_str, "UTF-8", "latin1", sub_byte,
                                     NULL, NULL));
    inputs[k++] = IN_STR;
    Rf_protect(calls[k] = iconv_call(x_str, "UTF-8", "ASCII", sub_unicode,
                                     NULL, NULL));
    inputs[k++] = IN_STR;
    Rf_protect(calls[k] = iconv_call(x_str, "UTF-8", "ASCII", sub_c99,
                                     NULL, NULL));
    inputs[k++] = IN_STR;
    Rf_protect(calls[k] = iconv_call(x_str, "UTF-8", "UTF-16LE", sub_byte,
                                     "toRaw", true_val));
    inputs[k++] = IN_STR;
    Rf_protect(calls[k] = iconv_call(x_str, "UTF-8", "latin1", sub_na,
                                     NULL, NULL));
    inputs[k++] = IN_STR;
    Rf_protect(calls[k] = iconv_call(x_str, "UTF-8", "ASCII", sub_empty,
                                     NULL, NULL));
    inputs[k++] = IN_STR;

    /* from="" with marked input: do_iconv keys the converter on the
     * CHARSXP mark, with its own fallback substitutions */
    Rf_protect(calls[k] = iconv_call(x_utf8, "", "latin1", sub_qm,
                                     "mark", true_val));
    inputs[k++] = IN_UTF8;
    Rf_protect(calls[k] = iconv_call(x_latin1, "", "UTF-8", sub_byte,
                                     "mark", true_val));
    inputs[k++] = IN_LATIN1;
    Rf_protect(calls[k] = iconv_call(x_utf8, "", "ASCII//TRANSLIT", sub_byte,
                                     NULL, NULL));
    inputs[k++] = IN_UTF8;
    Rf_protect(calls[k] = iconv_call(x_str, "UTF-8", "UTF-8", sub_unicode,
                                     NULL, NULL));
    inputs[k++] = IN_STR;
    Rf_protect(calls[k] = iconv_call(x_latin1, "latin1", "UTF-8", sub_byte,
                                     "mark", false_val));
    inputs[k++] = IN_LATIN1;

    /* The mark helpers around iconv */
    Rf_protect(calls[k] = Rf_lang2(Rf_install("enc2utf8"), x_latin1));
    inputs[k++] = IN_LATIN1;
    Rf_protect(calls[k] = Rf_lang2(Rf_install("enc2native"), x_utf8));
    inputs[k++] = IN_UTF8;
    Rf_protect(calls[k] = Rf_lang2(Rf_install("validUTF8"), x_str));
    inputs[k++] = IN_STR;
    Rf_protect(calls[k] = Rf_lang2(Rf_install("validEnc"), x_utf8));
    inputs[k++] = IN_UTF8;
    {
        SEXP latin1, set_enc;
        Rf_protect(latin1 = Rf_mkString("latin1"));
        Rf_protect(set_enc = Rf_lang3(Rf_install("Encoding<-"), x_str, latin1));
        Rf_protect(calls[k] = Rf_lang2(Rf_install("enc2utf8"), set_enc));
        inputs[k++] = IN_STR;
    }

    /* Raw input through decoders with BOMs and shift states */
    Rf_protect(calls[k] = iconv_call(x_list, "UTF-16", "UTF-8", sub_byte,
                                     NULL, NULL));
    inputs[k++] = IN_RAW;
    Rf_protect(calls[k] = iconv_call(x_list, "UTF-32", "UTF-8", sub_byte,
                                     NULL, NULL));
    inputs[k++] = IN_RAW;
    Rf_protect(calls[k] = iconv_call(x_list, "UTF-7", "UTF-8", sub_byte,
                                     NULL, NULL));
    inputs[k++] = IN_RAW;
    Rf_protect(calls[k] = iconv_call(x_list, "ISO-2022-JP", "UTF-8", sub_byte,
                                     NULL, NULL));
    inputs[k++] = IN_RAW;
    Rf_protect(calls[k] = iconv_call(x_list, "GB18030", "UTF-8", sub_byte,
                                     NULL, NULL));
    inputs[k++] = IN_RAW;
    Rf_protect(calls[k] = iconv_call(x_list, "UTF-8", "UTF-16", sub_byte,
                                     "toRaw", true_val));
    inputs[k++] = IN_RAW;

    if (k != N_CALLS)
        abort();

    SET_STRING_ELT(x_str, 0, Rf_mkChar("fuzz"));
    SET_STRING_ELT(x_utf8, 0, Rf_mkCharCE("fuzz", CE_UTF8));
    SET_STRING_ELT(x_latin1, 0, Rf_mkCharCE("fuzz", CE_LATIN1));
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT)
        return 0;

    int selected = data[0] % N_CALLS;

    if (inputs[selected] == IN_RAW) {
        encoding_input_t input = { data + 1, size - 1 };
        if (!R_ToplevelExec(set_encoding_input, &input))
            return 0;
    } else {
        /* Character inputs cannot carry a NUL. */
        if (memchr(data + 1, '\0', size - 1))
            return 0;

        char buffer[FUZZ_MAX_INPUT];
        memcpy(buffer, data + 1, size - 1);
        buffer[size - 1] = '\0';

        Rboolean ok;
        switch (inputs[selected]) {
        case IN_UTF8:
            ok = fuzz_set_string_ce(x_utf8, buffer, CE_UTF8);
            break;
        case IN_LATIN1:
            ok = fuzz_set_string_ce(x_latin1, buffer, CE_LATIN1);
            break;
        default:
            ok = fuzz_set_string(x_str, buffer);
            break;
        }
        if (!ok)
            return 0;
    }

    fuzz_eval_silent(calls[selected], R_GlobalEnv);
    return 0;
}
