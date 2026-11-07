/*
 * libFuzzer harness for R's memDecompress / compression wrappers.
 *
 * Feeds raw bytes to memDecompress() for each supported type: gzip,
 * bzip2, xz, and "unknown" (magic-byte auto-detection).  The target is
 * not the compression libraries (OSS-Fuzz fuzzes those directly) but R's
 * wrapper layer in src/main/connections.c: buffer sizing, error recovery,
 * and R_alloc output handling.
 *
 * Adapted from r-afl's decompress harness.
 */

#include <stdint.h>
#include <string.h>

/* The default 1Gb vector limit stays.  memDecompress keeps every
 * doubling retry live on the R_alloc stack and then copies the result
 * into a RAWSXP, so a stream expanding to N bytes holds about 3N: a 64KB
 * bzip2 stream of zeros (1.25GB) needs ~3.75GB.  Raising the limit to
 * 4Gb once covered that, but ClusterFuzz runs with -rss_limit_mb=2560,
 * so such inputs were killed as out-of-memory (most decompress sessions
 * in early November 2026) rather than ending in R's clean "cannot
 * allocate" error.  The sizing paths past 2.5GB are unreachable on the
 * bots either way; under 1Gb every retry is exercised for outputs up
 * to roughly 250MB (measured with bzip2 streams of zeros). */

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)

static SEXP calls[4];

int fuzz_target_init(int *argc, char ***argv)
{
    fuzz_init_r();

    SEXP sym_memDecompress = Rf_install("memDecompress");

    SEXP str_gzip, str_bzip2, str_xz, str_unknown;
    Rf_protect(str_gzip    = Rf_mkString("gzip"));
    Rf_protect(str_bzip2   = Rf_mkString("bzip2"));
    Rf_protect(str_xz      = Rf_mkString("xz"));
    Rf_protect(str_unknown = Rf_mkString("unknown"));

    /* One call per compression type, sharing a placeholder RAWSXP that
     * each iteration swaps out via SETCADR. */
    SEXP placeholder;
    Rf_protect(placeholder = Rf_allocVector(RAWSXP, 1));

    SEXP type_strs[4] = { str_gzip, str_bzip2, str_xz, str_unknown };
    for (int i = 0; i < 4; i++) {
        Rf_protect(calls[i] = Rf_lang3(sym_memDecompress, placeholder,
                                       type_strs[i]));
        SET_TAG(CDDR(calls[i]), Rf_install("type"));
    }

    fuzz_label_calls(calls, 4);

    /* Warmup: a minimal gzip stream (1f 8b header + empty deflate). */
    {
        int error = 0;
        unsigned char gz[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00};
        SEXP w_raw;
        Rf_protect(w_raw = Rf_allocVector(RAWSXP, sizeof(gz)));
        memcpy(RAW(w_raw), gz, sizeof(gz));
        for (int i = 0; i < 4; i++) {
            SETCADR(calls[i], w_raw);
            R_tryEval(calls[i], R_GlobalEnv, &error);
            error = 0;
        }
        Rf_unprotect(1); /* w_raw */
    }

    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT)
        return 0;

    /* First byte selects the decompressor; the rest is the payload.
     * One type per input keeps libFuzzer's coverage feedback clean and
     * avoids cross-library state bleed. */
    int idx = data[0] & 0x03;

    if (!fuzz_set_raw_arg(calls[idx], data + 1, size - 1))
        return 0;

    fuzz_eval_data_t ed = { .call = calls[idx], .env = R_GlobalEnv };
    R_ToplevelExec(fuzz_do_eval, &ed);

    return 0;
}
