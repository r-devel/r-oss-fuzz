/*
 * libFuzzer harness for grDevices' colour parsing and conversion
 * (src/library/grDevices/src/colors.c).
 *
 * col2rgb() is where user-supplied colour strings meet C: str2col()
 * dispatches on the first byte to the "#RRGGBB[AA]" hex parser, a
 * strtod-based palette index, or the case- and space-insensitive name
 * lookup, and palette() swaps the table those indices resolve through.
 * Shiny apps routinely pass web form values straight into these, so a
 * crash here is reachable from a browser.  The numeric constructors
 * (rgb, hsv, hcl, gray, rgb2hsv) scale and range-check doubles into
 * packed colours; they are fed the same payload parsed as numbers.
 *
 * Input layout: the first byte selects a slot; the rest is text whose
 * newline-separated lines are the colour vector.  Numeric slots take
 * as.numeric() of those lines (unparseable lines become NA, which is a
 * value the scalers must handle too) or the raw bytes of the payload.
 *
 * palette() is process-global state, so the slot that sets it restores
 * the default on exit; otherwise one input would change what every later
 * input's index strings resolve to.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (1024 * 16)
#define N_CALLS 16

#define SPLIT "cols <- strsplit(x, \"\\n\", fixed = TRUE)[[1L]]; "

/* The constructors reject the whole vector on the first NA or
 * out-of-range element, so each numeric slot first runs the finite
 * values folded into range (every element reaches the conversion
 * arithmetic) and only then the raw values (the validation paths). */
#define NUMERIC SPLIT "v <- suppressWarnings(as.numeric(cols)); " \
    "w <- abs(v[is.finite(v)]); "

/* Slot layout:
 *   [0,6)    string colours: col2rgb, a fuzzed palette, adjustcolor,
 *            colorRamp (Lab space), hcl.colors, an rgb() round trip
 *   [6,14)   numeric colours: rgb, hsv, hcl (fixup both ways), gray,
 *            rgb2hsv/convertColor, numeric palette indices
 *   [14,16)  byte-derived colours */
static const char *const sources[N_CALLS] = {
    "function(x) { " SPLIT "col2rgb(cols) }",
    "function(x) { " SPLIT "col2rgb(cols, alpha = TRUE) }",
    "function(x) { " SPLIT "on.exit(palette(\"default\")); palette(cols); "
    "list(palette(), col2rgb(seq_len(2L * length(cols))), col2rgb(cols)) }",
    "function(x) { " SPLIT "adjustcolor(cols, alpha.f = 0.5, red.f = 1.5, "
    "offset = c(0.1, 0, -0.1, 0)) }",
    "function(x) { " SPLIT "list(colorRamp(cols, space = \"Lab\")"
    "(seq(0, 1, length.out = 8L)), colorRampPalette(cols, bias = 2)(5L)) }",
    "function(x) { " SPLIT "list(hcl.colors(8L, palette = cols[1L], "
    "rev = TRUE), rgb(t(col2rgb(cols, alpha = TRUE)), maxColorValue = 255, "
    "names = cols)) }",
    "function(x) { " NUMERIC "list(rgb(w %% 256, rev(w) %% 256, "
    "(w / 2) %% 256, maxColorValue = 255), rgb(v, rev(v), v / 2, "
    "maxColorValue = 255)) }",
    "function(x) { " NUMERIC "list(rgb(w %% 1, rev(w) %% 1, w %% 1, w %% 1), "
    "rgb(v, v, v, v, maxColorValue = max(v, 1, na.rm = TRUE))) }",
    "function(x) { " NUMERIC "list(hsv(w %% 1, rev(w) %% 1, w %% 1, "
    "alpha = w %% 1), hsv(v, v, v)) }",
    "function(x) { " NUMERIC "list(hcl(w, w * 10, w %% 100, fixup = TRUE), "
    "hcl(w, rev(w), w, alpha = w %% 1, fixup = FALSE), hcl(v, v, v)) }",
    "function(x) { " NUMERIC "list(gray(w %% 1, rev(w) %% 1), gray(v)) }",
    "function(x) { " NUMERIC "m <- matrix(rep_len(w %% 256, 3L * max(1L, "
    "length(w) %/% 3L)), nrow = 3L); list(rgb2hsv(m, maxColorValue = 255), "
    "convertColor(t(m) / 255, from = \"sRGB\", to = \"Lab\"), "
    "rgb2hsv(v, rev(v), v, maxColorValue = 255)) }",
    "function(x) { " NUMERIC "list(col2rgb(w %% 1e6), "
    "col2rgb(as.integer(w %% 1e6)), col2rgb(v), col2rgb(v > 0)) }",
    "function(x) { " NUMERIC "list(rgb2hsv(w %% 256, rev(w) %% 256, "
    "(w * 3) %% 256, maxColorValue = 255), "
    "rgb2hsv(v, rev(v), v %% 256, maxColorValue = 255)) }",
    "function(x) { b <- as.integer(charToRaw(x)); "
    "list(rgb(b, rev(b), (b * 7L) %% 256L, maxColorValue = 255), "
    "col2rgb(b), hsv(b / 255, 1, b / 255, alpha = rev(b) / 255)) }",
    "function(x) { b <- as.integer(charToRaw(x)); on.exit(palette(\"default\")); "
    "palette(gray(b / 255)); list(palette(), col2rgb(b), "
    "adjustcolor(b, alpha.f = 0.3)) }",
};

static SEXP x_text;
static SEXP calls[N_CALLS];

int fuzz_target_init(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    /* Reusable text container -- each iteration swaps its CHARSXP. */
    Rf_protect(x_text = Rf_allocVector(STRSXP, 1));

    for (int i = 0; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang2(wrapper, x_text));
    }

    /* Warmup: load grDevices and the colour name table. */
    SET_STRING_ELT(x_text, 0, Rf_mkChar("red\n#FF000080\n3\n0.5\ntransparent"));
    for (int i = 0; i < N_CALLS; i++)
        fuzz_eval_silent(calls[i], R_GlobalEnv);

    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
{
    if (size < 2 || size > FUZZ_MAX_INPUT || memchr(data + 1, '\0', size - 1))
        return 0;

    char buffer[FUZZ_MAX_INPUT];
    memcpy(buffer, data + 1, size - 1);
    buffer[size - 1] = '\0';
    if (!fuzz_set_string(x_text, buffer))
        return 0;

    fuzz_eval_silent(calls[data[0] % N_CALLS], R_GlobalEnv);
    return 0;
}
