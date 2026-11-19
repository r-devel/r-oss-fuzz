/*
 * libFuzzer harness for R's mathematical library, src/nmath: the
 * density, distribution and quantile functions behind d*, p* and q*,
 * and the special functions (gamma and beta families, psigamma,
 * choose, the Bessel functions).
 *
 * These are 8.5k lines of numerical code at 1% line coverage, fed by
 * nothing but R's startup.  Their failure modes are the ones a fuzzer
 * finds well: iterations that never converge for some corner of the
 * parameter space (a hang), and work arrays sized from a parameter
 * (bessel_i/k/j/y's nb, signrank's and wilcox's count tables).  Doubles
 * from raw bytes reach every corner, NaN, infinities, subnormals and
 * huge magnitudes included.  The random variate generators (r*) are
 * left out: they would also fuzz the RNG state, which is a target of
 * its own.
 *
 * Input layout: byte 0 selects the function, byte 1 holds flags (log,
 * lower.tail, whether an optional ncp/nranges parameter is passed), and
 * the rest is little-endian doubles: one per parameter, then the x (or
 * q or p) vector, at most 64 of them.
 *
 * Some functions are slow by design in parts of their domain, and the
 * slot skips those inputs rather than time out on them: phyper/qhyper
 * walk the support one term at a time (qhyper.c says "Slow, but safe"),
 * the signrank and wilcox count tables grow with the square of n
 * (m * n for wilcox) and take time to match.  qnbinom has two: with
 * size < 1 it searches in time linear in the quantile (0.3 s for
 * mu = 1e8, no answer within minutes for mu = 1e10, in R 4.6.1), and
 * for any size it never returns once mu passes somewhere between 1e150
 * and 1e170, about where the variance overflows; so its mean is kept
 * under 1e6 and 1e150 respectively.  The non-central densities sum a series
 * whose length grows with the square root of ncp (dchisq: 0.6 s at
 * ncp = 1e16, over 15 s at 1e20), so ncp is kept under 1e10.
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT (2 + 8 * (3 + 64))

static const char nmath_source[] = R"(
local({
    dists <- list(
        norm = c("mean", "sd"), lnorm = c("meanlog", "sdlog"),
        unif = c("min", "max"), exp = "rate", gamma = c("shape", "rate"),
        beta = c("shape1", "shape2", "ncp"), chisq = c("df", "ncp"),
        t = c("df", "ncp"), f = c("df1", "df2", "ncp"),
        cauchy = c("location", "scale"), logis = c("location", "scale"),
        weibull = c("shape", "scale"), binom = c("size", "prob"),
        nbinom = c("size", "prob"), nbinom = c("size", "mu"),
        pois = "lambda", geom = "prob", hyper = c("m", "n", "k"),
        signrank = "n", wilcox = c("m", "n"))
    specs <- list()
    for (i in seq_along(dists))
        for (kind in c("d", "p", "q"))
            specs[[length(specs) + 1L]] <- list(
                fun = get(paste0(kind, names(dists)[i])), kind = kind,
                dist = names(dists)[i], params = dists[[i]])
    specs <- c(specs, list(
        list(fun = ptukey, kind = "p", dist = "tukey",
             params = c("nmeans", "df", "nranges")),
        list(fun = qtukey, kind = "q", dist = "tukey",
             params = c("nmeans", "df", "nranges"))))
    special <- list(
        gamma = NULL, lgamma = NULL, digamma = NULL, trigamma = NULL,
        factorial = NULL, lfactorial = NULL, beta = "b", lbeta = "b",
        choose = "k", lchoose = "k", psigamma = "deriv",
        besselJ = "nu", besselY = "nu", besselI = "nu", besselK = "nu")
    for (f in names(special))
        specs[[length(specs) + 1L]] <- list(fun = get(f), kind = "s",
                                            dist = f, params = special[[f]])
    optional <- c("ncp", "nranges")

    function(k, flags, raw) {
        s <- specs[[k %% length(specs) + 1L]]
        d <- readBin(raw, "double", n = length(raw) %/% 8L, size = 8L,
                     endian = "little")
        params <- s$params
        if (flags %/% 4L %% 2L == 1L && any(params %in% optional))
            params <- params[!params %in% optional]
        np <- length(params)
        if (length(d) <= np)
            return(NULL)
        p <- d[seq_len(np)]
        x <- d[-seq_len(np)]

        if (s$dist == "hyper" && any(!is.finite(c(p, x)) | abs(c(p, x)) > 1e6))
            return(NULL)
        if ("ncp" %in% params && !(abs(p[params == "ncp"]) <= 1e10))
            return(NULL)
        if (s$kind == "q" && s$dist == "nbinom") {
            mean <- if (params[2L] == "mu") p[2L]
                    else p[1L] * (1 - p[2L]) / p[2L]
            if (!(abs(mean) <= if (p[1L] >= 1) 1e150 else 1e6))
                return(NULL)
        }
        if (s$dist == "signrank" && !(abs(p[1L]) <= 1000))
            return(NULL)
        if (s$dist == "wilcox" && !all(abs(p) <= 200))
            return(NULL)

        args <- c(list(x), as.list(p))
        names(args) <- c("", params)
        if (s$kind == "s" && s$dist %in% c("besselI", "besselK"))
            args$expon.scaled <- flags %% 2L == 1L
        else if (s$kind == "d")
            args$log <- flags %% 2L == 1L
        else if (s$kind != "s") {
            args$lower.tail <- flags %/% 2L %% 2L == 1L
            args$log.p <- flags %% 2L == 1L
        }
        do.call(s$fun, args)
    }
})
)";

static SEXP call;

int fuzz_target_init(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    SEXP fn, function_index, flags;
    Rf_protect(fn = fuzz_make_wrapper(nmath_source));
    Rf_protect(function_index = Rf_ScalarInteger(0));
    Rf_protect(flags = Rf_ScalarInteger(0));
    Rf_protect(call = Rf_lang4(fn, function_index, flags, R_NilValue));
    fuzz_label_calls(&call, 1);

    /* Warmup: load stats and its distribution code. */
    SEXP raw;
    Rf_protect(raw = Rf_allocVector(RAWSXP, 16));
    memset(RAW(raw), 0, 16);
    SETCADDDR(call, raw);
    fuzz_eval_silent(call, R_GlobalEnv);
    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
{
    if (size < 2 + 16 || size > FUZZ_MAX_INPUT)
        return 0;

    INTEGER(CADR(call))[0] = data[0];
    INTEGER(CADDR(call))[0] = data[1];

    /* fuzz_set_raw_arg sets the argument after the cell it is given, so
     * passing the flags' cell stages the raw vector as the third. */
    if (!fuzz_set_raw_arg(CDDR(call), data + 2, size - 2))
        return 0;

    fuzz_eval_silent(call, R_GlobalEnv);
    return 0;
}
