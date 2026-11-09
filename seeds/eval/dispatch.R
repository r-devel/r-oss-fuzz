area <- function(shape, ...) UseMethod("area")
area.default <- function(shape, ...) -1
area.numeric <- function(shape, scale = 1, ...) sum(shape * shape) * scale
area.matrix <- function(shape, ...) prod(dim(shape)) + area(unclass(shape)[1])
area.function <- function(shape, ...) area(shape(2))
area.list <- function(shape, ...) { s <- 0; for (e in shape) s <- s + area(e); s }
m <- 1:6
dim(m) <- c(2L, 3L)
f <- function(n) rep(n, 3)
area(list(1:3, m, f, "text", function(x) x), scale = 2)
