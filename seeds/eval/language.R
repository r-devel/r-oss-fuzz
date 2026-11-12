f <- function(expr, ...) {
    e <- substitute(expr)
    if (missing(expr) || nargs() > 2) return(quote(none))
    e[[1L]] <- quote(c)
    switch(as.character(e[[1L]]), c = length(e), sum = , prod = 1, 0)
}
g <- function(x, y) if (missing(y)) nargs() else x + y
list(f(sum(1, 2, 3)), f(a + b, 1, 2), f(), g(41), g(40, 1), quote(h(y)) [[2L]])
