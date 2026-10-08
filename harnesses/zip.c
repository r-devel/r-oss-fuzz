/*
 * libFuzzer harness for R's bundled zip reader.
 *
 * src/main/dounzip.c carries a copy of minizip (unzOpen, the central
 * directory search, local-header coherency checks, unzReadCurrentFile)
 * plus R's own listing and extraction loops on top of it.  It runs on
 * every utils::unzip() and unz() call, which is how binary packages
 * and download.file() payloads get unpacked -- the archive is untrusted
 * by construction.  The copy is private to R, so nobody else fuzzes it.
 *
 * The slots cover listing, extraction into a per-process scratch
 * directory, and reading the first entry through an unz() connection in
 * both binary and text mode.  unzip is pinned to "internal" so the
 * harness can never shell out to a system unzip.  The input is staged in
 * a per-process scratch file since the entry points only take paths
 * (see common.h).
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 64)
#define N_CALLS 4

static char *scratch_path;
static SEXP calls[N_CALLS];

/* Extraction needs a directory of its own.  junkpaths = TRUE keeps
 * every entry inside it regardless of the path stored in the archive,
 * and the wrapper empties it again on exit (error or not) so one
 * iteration's files never collide with the next.  Output volume is
 * bounded by the deflate ratio (~1000:1) times the input cap. */
static char *make_scratch_dir(void)
{
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL || *tmpdir == '\0')
        tmpdir = "/tmp";

    char *path = malloc(PATH_MAX);
    if (path == NULL)
        return NULL;
    snprintf(path, PATH_MAX, "%s/fuzz-zip-exdir-XXXXXX", tmpdir);
    if (mkdtemp(path) == NULL) {
        free(path);
        return NULL;
    }
    return path;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    scratch_path = fuzz_scratch_file("zip");
    char *exdir = make_scratch_dir();
    if (scratch_path == NULL || exdir == NULL)
        abort();

    /* [0] listing only: central directory walk (ziplist).
     * [1] extraction: local headers and inflate (zipunzip/extract_one).
     * [2] unz() connection, binary read of the first entry.
     * [3] unz() connection, text read of the first entry.
     * The readBin/readLines caps bound how much of a bomb is inflated. */
    static const char *const sources[N_CALLS] = {
        "function(path, exdir) "
        "utils::unzip(path, list = TRUE, unzip = \"internal\")",

        "function(path, exdir) { "
        "on.exit(unlink(list.files(exdir, all.files = TRUE, "
        "full.names = TRUE, no.. = TRUE), recursive = TRUE)); "
        "utils::unzip(path, exdir = exdir, junkpaths = TRUE, "
        "unzip = \"internal\") }",

        "function(path, exdir) { "
        "l <- utils::unzip(path, list = TRUE, unzip = \"internal\"); "
        "if (nrow(l)) { con <- unz(path, l$Name[1], open = \"rb\"); "
        "on.exit(close(con)); readBin(con, \"raw\", 65536L) } }",

        "function(path, exdir) { "
        "l <- utils::unzip(path, list = TRUE, unzip = \"internal\"); "
        "if (nrow(l)) { con <- unz(path, l$Name[1]); on.exit(close(con)); "
        "readLines(con, n = 1024L, warn = FALSE) } }",
    };
    SEXP path, exdir_string;
    Rf_protect(path = Rf_mkString(scratch_path));
    Rf_protect(exdir_string = Rf_mkString(exdir));
    for (int i = 0; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang3(wrapper, path, exdir_string));
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT)
        return 0;

    if (!fuzz_write_scratch(scratch_path, data + 1, size - 1))
        return 0;

    fuzz_eval_silent(calls[data[0] % N_CALLS], R_GlobalEnv);
    return 0;
}
