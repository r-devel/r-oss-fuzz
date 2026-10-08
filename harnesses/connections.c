/*
 * Exercise R's connection layer (src/main/connections.c) as a reader of
 * untrusted files.
 *
 * memDecompress, readBin and readLines(textConnection) already fuzz their
 * narrow entry points; what they never reach is the machinery around
 * them: the encoding= re-encoding layer (dummy_fgetc), the compressed-file
 * readers (gzfile/bzfile/xzfile/zstdfile and gzcon), rawConnection, the
 * line buffering behind readLines/readChar/scan, seek, pushBack, and the
 * write side (writeLines/writeChar/rawConnectionValue).  Each input is
 * staged in a scratch file and read back through one of those paths.
 *
 * Every slot is an R closure that closes its connection on exit: R caps
 * the connection table at 128, so a leak would quietly turn every later
 * iteration into the same "all connections are in use" error.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)

/* Encodings handed to file(encoding=).  "" means no re-encoding, the
 * others go through iconv in dummy_fgetc; UTF-8-BOM and UCS-2LE take the
 * byte-order-mark branches. */
#define N_ENCODINGS 9
static const char *const encodings[N_ENCODINGS] = {
    "", "UTF-8", "latin1", "UTF-16LE", "UTF-16BE", "UTF-16", "UCS-2LE",
    "CP1252", "UTF-8-BOM"
};

#define N_OPENERS 4
static const char *const openers[N_OPENERS] = {
    "gzfile", "bzfile", "xzfile", "zstdfile"
};

/* Slot layout, in the order the calls are built below:
 *   [0,9)    readLines(file(path, encoding), skipNul = FALSE)
 *   [9,18)   readLines(..., skipNul = TRUE)
 *   [18,27)  readChar(file(path, "r", encoding), useBytes = TRUE)
 *   [27,36)  readChar(..., useBytes = FALSE)
 *   [36,45)  scan(file(path, encoding), what = "")
 *   [45,54)  open(con, "rt") then chunked readLines/seek/readChar
 *   [54,58)  <opener>(path, "rb") + readBin
 *   [58,62)  <opener>(path, "rt") + readLines
 *   62       gzcon(file(path, "rb")) + readBin
 *   63       rawConnection(x) reads, seek, readChar
 *   64       pushBack over a textConnection of the lines
 *   65       write side: rawConnection/textConnection/gzcon writers
 */
#define N_CALLS (6 * N_ENCODINGS + 2 * N_OPENERS + 4)

static SEXP calls[N_CALLS];
static char *scratch_path;

/* Every wrapper takes (x, path, ...) so that fuzz_set_raw_arg can swap the
 * raw vector in at CADR regardless of which slot runs. */
static const char wrapper_lines[] =
    "function(x, path, enc, skip) {"
    "  con <- file(path, encoding = enc); on.exit(close(con));"
    "  readLines(con, n = 1000L, warn = FALSE, skipNul = skip) }";

static const char wrapper_chars[] =
    "function(x, path, enc, ub) {"
    "  con <- file(path, 'r', encoding = enc); on.exit(close(con));"
    "  readChar(con, c(1L, 10L, 100L, 1000L), useBytes = ub) }";

static const char wrapper_scan[] =
    "function(x, path, enc) {"
    "  con <- file(path, encoding = enc); on.exit(close(con));"
    "  scan(con, what = '', quiet = TRUE, nmax = 1000L) }";

static const char wrapper_chunks[] =
    "function(x, path, enc) {"
    "  con <- file(path, encoding = enc); open(con, 'rt'); on.exit(close(con));"
    "  a <- readLines(con, n = 2L, warn = FALSE); isIncomplete(con);"
    "  b <- readLines(con, n = 500L, warn = FALSE);"
    "  if (isSeekable(con)) seek(con, 0L);"
    "  list(a, b, readChar(con, 10L, useBytes = TRUE)) }";

static const char wrapper_compressed_bin[] =
    "function(x, path, opener) {"
    "  con <- opener(path, 'rb'); on.exit(close(con));"
    "  readBin(con, 'raw', 65536L) }";

static const char wrapper_compressed_text[] =
    "function(x, path, opener) {"
    "  con <- opener(path, 'rt'); on.exit(close(con));"
    "  readLines(con, n = 1000L, warn = FALSE) }";

static const char wrapper_gzcon[] =
    "function(x, path) {"
    "  con <- gzcon(file(path, 'rb')); on.exit(close(con));"
    "  readBin(con, 'raw', 65536L) }";

static const char wrapper_raw[] =
    "function(x, path) {"
    "  con <- rawConnection(x); on.exit(close(con));"
    "  a <- readLines(con, n = 1000L, warn = FALSE);"
    "  isSeekable(con); seek(con, 3L);"
    "  b <- readChar(con, c(5L, 50L), useBytes = TRUE);"
    "  seek(con, 0L, 'start');"
    "  list(a, b, readBin(con, 'integer', 100L, size = 2L)) }";

static const char wrapper_pushback[] =
    "function(x, path) {"
    "  con <- rawConnection(x); on.exit(close(con));"
    "  l <- readLines(con, n = 20L, warn = FALSE);"
    "  tc <- textConnection(l); on.exit(close(tc), add = TRUE);"
    "  pushBack(rev(l), tc, newLine = FALSE); pushBack(l, tc);"
    "  pushBackLength(tc); a <- readLines(tc, n = 5L, warn = FALSE);"
    "  clearPushBack(tc); list(a, readLines(tc, warn = FALSE)) }";

static const char wrapper_write[] =
    "function(x, path) {"
    "  l <- readLines(rc <- rawConnection(x), n = 50L, warn = FALSE); close(rc);"
    "  out <- rawConnection(raw(0), 'w'); on.exit(close(out));"
    "  writeLines(l, out); writeChar(l, out, eos = NULL); writeBin(x, out);"
    "  seek(out, 0L); truncate(out); writeLines(l, out, sep = '\\r\\n');"
    "  v <- rawConnectionValue(out);"
    "  tc <- textConnection(NULL, 'w'); on.exit(close(tc), add = TRUE);"
    "  writeLines(l, tc); cat(l, file = tc, sep = '|'); t <- textConnectionValue(tc);"
    "  gz <- gzcon(rawConnection(raw(0), 'w')); writeBin(x, gz); close(gz);"
    "  list(v, t) }";

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    scratch_path = fuzz_scratch_file("connections");
    if (scratch_path == NULL)
        abort();

    SEXP placeholder, path, true_value, false_value;
    Rf_protect(placeholder = Rf_allocVector(RAWSXP, 1));
    Rf_protect(path = Rf_mkString(scratch_path));
    Rf_protect(true_value = Rf_ScalarLogical(TRUE));
    Rf_protect(false_value = Rf_ScalarLogical(FALSE));

    SEXP w_lines, w_chars, w_scan, w_chunks, w_cbin, w_ctext;
    Rf_protect(w_lines = fuzz_make_wrapper(wrapper_lines));
    Rf_protect(w_chars = fuzz_make_wrapper(wrapper_chars));
    Rf_protect(w_scan = fuzz_make_wrapper(wrapper_scan));
    Rf_protect(w_chunks = fuzz_make_wrapper(wrapper_chunks));
    Rf_protect(w_cbin = fuzz_make_wrapper(wrapper_compressed_bin));
    Rf_protect(w_ctext = fuzz_make_wrapper(wrapper_compressed_text));

    int n = 0;
    SEXP enc[N_ENCODINGS];
    for (int i = 0; i < N_ENCODINGS; i++)
        Rf_protect(enc[i] = Rf_mkString(encodings[i]));

    for (int i = 0; i < N_ENCODINGS; i++)
        Rf_protect(calls[n++] = Rf_lang5(w_lines, placeholder, path, enc[i],
                                         false_value));
    for (int i = 0; i < N_ENCODINGS; i++)
        Rf_protect(calls[n++] = Rf_lang5(w_lines, placeholder, path, enc[i],
                                         true_value));
    for (int i = 0; i < N_ENCODINGS; i++)
        Rf_protect(calls[n++] = Rf_lang5(w_chars, placeholder, path, enc[i],
                                         true_value));
    for (int i = 0; i < N_ENCODINGS; i++)
        Rf_protect(calls[n++] = Rf_lang5(w_chars, placeholder, path, enc[i],
                                         false_value));
    for (int i = 0; i < N_ENCODINGS; i++)
        Rf_protect(calls[n++] = Rf_lang4(w_scan, placeholder, path, enc[i]));
    for (int i = 0; i < N_ENCODINGS; i++)
        Rf_protect(calls[n++] = Rf_lang4(w_chunks, placeholder, path, enc[i]));

    /* The openers are base functions looked up once; passing the closure
     * itself keeps the wrapper free of any eval of a name. */
    SEXP opener[N_OPENERS];
    for (int i = 0; i < N_OPENERS; i++)
        Rf_protect(opener[i] = Rf_findFun(Rf_install(openers[i]), R_BaseEnv));
    for (int i = 0; i < N_OPENERS; i++)
        Rf_protect(calls[n++] = Rf_lang4(w_cbin, placeholder, path, opener[i]));
    for (int i = 0; i < N_OPENERS; i++)
        Rf_protect(calls[n++] = Rf_lang4(w_ctext, placeholder, path, opener[i]));

    SEXP w_gzcon, w_raw, w_pushback, w_write;
    Rf_protect(w_gzcon = fuzz_make_wrapper(wrapper_gzcon));
    Rf_protect(w_raw = fuzz_make_wrapper(wrapper_raw));
    Rf_protect(w_pushback = fuzz_make_wrapper(wrapper_pushback));
    Rf_protect(w_write = fuzz_make_wrapper(wrapper_write));
    Rf_protect(calls[n++] = Rf_lang3(w_gzcon, placeholder, path));
    Rf_protect(calls[n++] = Rf_lang3(w_raw, placeholder, path));
    Rf_protect(calls[n++] = Rf_lang3(w_pushback, placeholder, path));
    Rf_protect(calls[n++] = Rf_lang3(w_write, placeholder, path));
    if (n != N_CALLS)
        abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT)
        return 0;

    int selected = data[0] % N_CALLS;
    if (!fuzz_write_scratch(scratch_path, data + 1, size - 1))
        return 0;
    if (!fuzz_set_raw_arg(calls[selected], data + 1, size - 1))
        return 0;

    fuzz_eval_silent(calls[selected], R_GlobalEnv);
    return 0;
}
