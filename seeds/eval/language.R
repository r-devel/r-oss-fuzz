f <- function(expr, ...) {
    e <- substitute(expr)
    if (missing(expr) || nargs() > 2) return(quote(none))
    e[[1L]] <- quote(c)
    switch(as.character(e[[1L]]), c = length(e), sum = , prod = 1, 0)
}
g <- function(x) {
    on.exit(x <- x + 1)
    on.exit(invisible(x), add = TRUE, after = FALSE)
    x
}
list(f(sum(1, 2, 3)), f(a + b, 1, 2), f(), g(41), quote(h(y)) [[2L]])
