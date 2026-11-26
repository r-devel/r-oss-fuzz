/*
 * libFuzzer harness for model formulas and symbolic differentiation:
 * stats' C code in src/library/stats/src/model.c (termsform, updateform,
 * modelframe, modelmatrix) and deriv.c (D, deriv).
 *
 * Every modelling function in R starts by taking a formula apart with
 * terms(), which in C encodes each variable as a bit, expands *, ^, /,
 * %in% and - into bit-pattern terms and sorts them; model.frame() and
 * model.matrix() then turn the terms into columns, contrasts included.
 * Formulas reach these from user input more often than one might hope
 * (as.formula(paste(...)) of web form fields, reformulate()).  D() and
 * deriv() rewrite expressions the same way, without evaluating them.
 *
 * Input layout: byte 0 selects the slot, byte 1 is a variant v that
 * each slot splits into its own options, the rest is R source text.
 * The text is parsed here in C, not evaluated; it must be exactly one
 * expression, which becomes the formula (wrapped in ~ when it is not
 * already one) or the expression to differentiate.
 *
 * Guards, applied to the parsed expression before R sees it:
 *
 *  - Formula algebra is exponential by design: (a+b+...+z)^26 really has
 *    2^26 terms, and (a+b):(c+d):(e+f)... doubles with every factor.
 *    term_bound() computes an upper bound on the number of terms and
 *    the terms slots skip inputs over FORMULA_MAX_TERMS, or with an
 *    exponent over FORMULA_MAX_POWER (see term_bound).
 *  - So is differentiation: d(u^v) contains u and v twice over, so
 *    x^x^x^... grows by a factor of two per level.  The D/deriv slot
 *    skips expressions nested deeper than DERIV_MAX_DEPTH.
 *  - model.frame() evaluates every variable expression in the formula.
 *    The model slot runs only when every name in the input is in
 *    eval_names (operators, a few pure functions, and the columns of
 *    the fixed data frame), so the input can call nothing else.
 *  - The data's ten rows do not bound what those calls build, so the
 *    model slot bounds `:`, interaction() and the columns of
 *    model.matrix() itself (see model_source).
 */

#include <math.h>
#include <stdint.h>
#include <string.h>

#include "common.h"

#define FUZZ_MAX_INPUT 4096
#define FUZZ_HEADER 2
#define N_CALLS 4

#define FORMULA_MAX_TERMS 4096.0
#define FORMULA_MAX_POWER 64.0
#define DERIV_MAX_DEPTH 12

/* The data frame's columns: numeric, factor, ordered, logical and a
 * matrix column, with an NA in most, so na.action has work to do. */
static const char data_source[] = R"(
data.frame(
    y = c(1.5, -2, 3, NA, 0, 1e300, -Inf, 4, 2, 7),
    x = c(1:9, NA) / 3,
    z = c(rep(c(0.1, 1, 10), 3), -1),
    w = c(rep(1, 9), 0),
    f = factor(c("a", "b", "c", "a", "b", NA, "c", "a", "b", "c")),
    g = factor(rep(c("u", "v"), 5)),
    o = factor(c(1, 2, 3, 1, 2, 3, 1, 2, 3, 1), ordered = TRUE),
    l = c(TRUE, FALSE, NA, TRUE, FALSE, TRUE, TRUE, FALSE, TRUE, FALSE),
    m = I(matrix(c(1:19, NA), 10))
)
)";

/* The names model.frame() may evaluate: the data's columns and "."
 * (both looked up in the data first), the formula operators, and
 * functions without side effects whose cost is bounded by their
 * arguments' lengths, which the 10-row data bounds in turn. */
static const char *const eval_names[] = {
    "y", "x", "z", "w", "f", "g", "o", "l", "m", ".",
    "~", "+", "-", "*", "/", ":", "^", "%in%", "(", "|", "&", "==",
    "I", "log", "exp", "sqrt", "abs", "sin", "cos", "offset", "cbind",
    "factor", "as.numeric", "interaction",
};
#define N_EVAL_NAMES (sizeof(eval_names) / sizeof(eval_names[0]))

/* fo(e): e as a formula object, without evaluating it.  Its
 * environment is the global one, where nothing but the search path
 * resolves; the model slot additionally checks every name first. */
static const char as_formula_source[] = R"(
function(e) {
    if (!(is.call(e) && identical(e[[1L]], as.name("~"))))
        e <- call("~", e)
    structure(e, class = "formula", .Environment = globalenv())
}
)";

/* [0] terms(): term expansion and ordering, specials, the "." in the
 * data, and the R-level editors built on the result. */
static const char terms_source[] = R"(
function(e, v, fo, data) {
    t <- terms(fo(e), specials = c("s", "strata", "offset"),
               keep.order = v %% 2L == 1L,
               simplify = v %/% 2L %% 2L == 1L,
               allowDotAsName = v %/% 4L %% 2L == 1L,
               data = if (v %/% 8L %% 2L) data)
    labels <- attr(t, "term.labels")
    if (length(labels)) {
        drop.terms(t, 1L, keep.response = v %/% 16L %% 2L == 1L)
        reformulate(labels, response = if (v %/% 32L %% 2L) "y",
                    intercept = v %/% 64L %% 2L == 0L)
    }
    delete.response(t)
    all.vars(t)
}
)";

/* [1] update(): the input as the new formula over a fixed old one, or
 * as the old one under a fixed new one.  The fixed formulas contain no
 * ^, so substituting one into the other keeps the term bound. */
static const char update_source[] = R"(
local({
    old <- list(y ~ x + f, cbind(y, z) ~ x * f + offset(w), ~ f:g - 1,
                log(y) ~ (x + z) %in% g)
    new <- list(. ~ . + z, ~ . - x, . ~ .:f, log(.) ~ . * g, y ~ .)
    function(e, v, fo, data) {
        e <- fo(e)
        if (v %% 2L)
            update.formula(old[[v %/% 2L %% 4L + 1L]], e)
        else
            update.formula(e, new[[v %/% 2L %% 5L + 1L]])
    }
})
)";

/* [2] model.frame() and model.matrix() over the fixed data: contrasts,
 * interactions of factors with matrices, na.action, zero-row data.
 *
 * The data has ten rows, but a few bytes of the input can make far more
 * work than that.  `:` builds a sequence of any length (oss-fuzz testcase
 * 5546078118936576: 7022242 elements inside interaction(), 9.6 s in
 * release R), and on two factors, like interaction(), a factor whose
 * levels multiply with every argument: 14 copies of the three-level f
 * took 13 s.  The variables are evaluated in the formula's environment,
 * where both are bounded versions, to 1000 elements or levels (a
 * factor's contrast matrix has its levels squared in cells); `:` is
 * bounded on the first element of each argument, as in the eval target.
 * model.matrix() then gives each term the product of its variables'
 * widths in columns, a factor's levels or a matrix's columns (seven
 * factor() variables in one term made 944785), so the slot stops before
 * it past 4096 columns. */
static const char model_source[] = R"(
local({
    contrasts <- c("contr.treatment", "contr.sum", "contr.helmert",
                   "contr.SAS", "contr.poly")
    actions <- list(na.omit, na.exclude, na.pass, na.fail)
    bounded <- new.env(parent = globalenv())
    bounded[[":"]] <- function(from, to) {
        if (is.factor(from) && is.factor(to)) {
            if (nlevels(from) * nlevels(to) > 1000)
                stop("too many levels for the formula target")
        } else if (length(from) >= 1L && length(to) >= 1L) {
            f <- as.double(from[[1L]])
            t <- as.double(to[[1L]])
            if (is.finite(f) && is.finite(t) && abs(t - f) >= 1000)
                stop("sequence too long for the formula target")
        }
        base::`:`(from, to)
    }
    bounded$interaction <- function(...) {
        args <- list(...)
        if (length(args) == 1L && is.list(args[[1L]]))
            args <- args[[1L]]
        n <- 1
        for (a in args)
            n <- n * nlevels(as.factor(a))
        if (n > 1000)
            stop("too many levels for the formula target")
        base::interaction(...)
    }
    function(e, v, fo, data) {
        e <- fo(e)
        environment(e) <- bounded
        d <- data[seq_len(v %% 11L), , drop = FALSE]
        v <- v %/% 11L
        mf <- model.frame(e, data = d, na.action = actions[[v %% 4L + 1L]],
                          drop.unused.levels = v %/% 4L %% 2L == 1L)

        ## model.matrix() turns a logical variable into a factor with
        ## levels FALSE and TRUE, and a character one into a factor of
        ## its values.
        width <- vapply(mf, NCOL, 0L)
        width[vapply(mf, is.logical, NA)] <- 2L
        is_character <- vapply(mf, is.character, NA)
        width[is_character] <- lengths(lapply(mf[is_character], unique))
        is_factor <- vapply(mf, is.factor, NA)
        width[is_factor] <- vapply(mf[is_factor], nlevels, 0L)
        factors <- attr(attr(mf, "terms"), "factors")
        if (length(factors)) {
            columns <- apply(factors != 0, 2L, function(k)
                prod(width[rownames(factors)[k]]))
            if (sum(columns) > 4096)
                stop("too many columns for the formula target")
        }

        ct <- contrasts[v %/% 8L %% 5L + 1L]
        model.matrix(e, mf, contrasts.arg = list(f = ct, g = ct, o = ct))
        model.response(mf)
        model.offset(mf)
    }
})
)";

/* [3] symbolic derivatives in x and y; deriv() also builds the
 * gradient (and Hessian) code it would return as a function. */
static const char deriv_source[] = R"(
function(e, v, fo, data) {
    D(e, c("x", "y")[v %% 2L + 1L])
    deriv(e, c("x", "y"), hessian = v %/% 2L %% 2L == 1L,
          function.arg = v %/% 4L %% 2L == 1L)
}
)";

static const char *const sources[N_CALLS] = {
    terms_source,
    update_source,
    model_source,
    deriv_source,
};

enum { SLOT_TERMS, SLOT_UPDATE, SLOT_MODEL, SLOT_DERIV };

static SEXP calls[N_CALLS];
static SEXP expr_cell, variant;

/* Upper bound on the number of terms terms() expands e into.  Anything
 * that is not one of the formula operators is a single variable; "."
 * stands for the data's nine columns.  l^k has at most every subset of
 * l's terms, and at most (l + 1)^k of them when k is a number.
 * Doubles saturate at Inf, which compares above any limit. */
static double term_bound(SEXP e)
{
    if (TYPEOF(e) == SYMSXP)
        return strcmp(CHAR(PRINTNAME(e)), ".") == 0 ? 9.0 : 1.0;
    if (TYPEOF(e) != LANGSXP || TYPEOF(CAR(e)) != SYMSXP)
        return 1.0;

    const char *op = CHAR(PRINTNAME(CAR(e)));
    SEXP args = CDR(e);
    SEXP right = args != R_NilValue && CDR(args) != R_NilValue
        ? CADR(args) : NULL;
    double l = args != R_NilValue ? term_bound(CAR(args)) : 1.0;
    double r = right != NULL ? term_bound(right) : 0.0;

    if (strcmp(op, "~") == 0 || strcmp(op, "+") == 0 || strcmp(op, "-") == 0)
        return l + r;
    if (strcmp(op, ":") == 0 || strcmp(op, "%in%") == 0)
        return l * (r > 0 ? r : 1.0);
    if (strcmp(op, "*") == 0 || strcmp(op, "/") == 0)
        return l + r + l * r;
    if (strcmp(op, "^") == 0) {
        double bound = pow(2.0, l);
        if (right != NULL && (TYPEOF(right) == REALSXP
                              || TYPEOF(right) == INTSXP)
            && XLENGTH(right) == 1) {
            double k = Rf_asReal(right);
            /* PowerTerms crosses once per unit of the exponent even after
             * every term exists, so the cost grows with k itself:
             * .^4662 took 13 s with nine data columns. */
            if (k > FORMULA_MAX_POWER)
                return R_PosInf;
            if (k >= 1 && pow(l + 1.0, k) < bound)
                bound = pow(l + 1.0, k);
        }
        return bound;
    }
    if (strcmp(op, "(") == 0)
        return l;
    return 1.0;
}

static int max_depth(SEXP e)
{
    if (TYPEOF(e) != LANGSXP)
        return 0;
    int deepest = 0;
    for (SEXP a = e; a != R_NilValue; a = CDR(a)) {
        int d = max_depth(CAR(a));
        if (d > deepest)
            deepest = d;
    }
    return deepest + 1;
}

static int is_eval_name(SEXP sym)
{
    const char *name = CHAR(PRINTNAME(sym));
    for (size_t i = 0; i < N_EVAL_NAMES; i++)
        if (strcmp(name, eval_names[i]) == 0)
            return 1;
    return 0;
}

/* TRUE when every symbol in e, call heads and argument names included,
 * is in eval_names. */
static int only_eval_names(SEXP e)
{
    switch (TYPEOF(e)) {
    case SYMSXP:
        return e == R_MissingArg || is_eval_name(e);
    case LANGSXP:
    case LISTSXP:
        for (SEXP a = e; a != R_NilValue; a = CDR(a)) {
            if (TAG(a) != R_NilValue && !is_eval_name(TAG(a)))
                return 0;
            if (!only_eval_names(CAR(a)))
                return 0;
        }
        return 1;
    case NILSXP:
    case LGLSXP:
    case INTSXP:
    case REALSXP:
    case CPLXSXP:
    case STRSXP:
        return 1;
    default:
        return 0;
    }
}

/* Parse the text into expr_cell's single element under a toplevel
 * context; the parser can raise R errors (memory, nesting) itself. */
typedef struct {
    const char *text;
    int ok;
} parse_job_t;

static void do_parse(void *data)
{
    parse_job_t *job = data;
    ParseStatus status;
    SEXP text, parsed;
    Rf_protect(text = Rf_mkString(job->text));
    Rf_protect(parsed = R_ParseVector(text, -1, &status, R_NilValue));
    if (status == PARSE_OK && XLENGTH(parsed) == 1) {
        SETCAR(expr_cell, VECTOR_ELT(parsed, 0));
        job->ok = 1;
    }
    Rf_unprotect(2);
}

int fuzz_target_init(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    SEXP fo, data, quote_call;
    Rf_protect(fo = fuzz_make_wrapper(as_formula_source));
    Rf_protect(data = fuzz_make_wrapper(data_source));
    Rf_protect(variant = Rf_ScalarInteger(0));

    /* The expression reaches each slot as quote(<expr>), so evaluating
     * the argument hands it over unevaluated.  All slots share the one
     * quote() call, and expr_cell is its argument cell: a SETCAR there
     * stages the parsed input for whichever slot runs. */
    Rf_protect(quote_call = Rf_lang2(Rf_install("quote"), R_NilValue));
    expr_cell = CDR(quote_call);
    for (int i = 0; i < N_CALLS; i++) {
        SEXP wrapper;
        Rf_protect(wrapper = fuzz_make_wrapper(sources[i]));
        Rf_protect(calls[i] = Rf_lang5(wrapper, quote_call, variant, fo, data));
    }
    fuzz_label_calls(calls, N_CALLS);

    /* Warmup: load stats' model code and the deriv tables. */
    SETCAR(expr_cell, Rf_install("x"));
    for (int i = 0; i < N_CALLS; i++)
        fuzz_eval_silent(calls[i], R_GlobalEnv);
    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
{
    if (size < FUZZ_HEADER + 1 || size > FUZZ_MAX_INPUT
        || memchr(data + FUZZ_HEADER, '\0', size - FUZZ_HEADER))
        return 0;

    char buffer[FUZZ_MAX_INPUT];
    memcpy(buffer, data + FUZZ_HEADER, size - FUZZ_HEADER);
    buffer[size - FUZZ_HEADER] = '\0';

    parse_job_t job = { buffer, 0 };
    SETCAR(expr_cell, R_NilValue);
    if (!R_ToplevelExec(do_parse, &job) || !job.ok)
        return 0;

    int slot = data[0] % N_CALLS;
    SEXP e = CAR(expr_cell);
    if ((slot == SLOT_TERMS || slot == SLOT_UPDATE || slot == SLOT_MODEL)
        && !(term_bound(e) <= FORMULA_MAX_TERMS))
        return 0;
    if (slot == SLOT_MODEL && !only_eval_names(e))
        return 0;
    if (slot == SLOT_DERIV && max_depth(e) > DERIV_MAX_DEPTH)
        return 0;

    INTEGER(variant)[0] = data[1];
    fuzz_eval_silent(calls[slot], R_GlobalEnv);
    return 0;
}
