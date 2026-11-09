x <- 1:6
names(x) <- c("a", "b", "c", "d", "e", "f")
dim(x) <- c(2L, 3L)
dimnames(x) <- list(c("r1", "r2"), c("c1", "c2", "c3"))
attr(x, "unit") <- "cm"
y <- x["r2", "c3"] + x[2, 3]
attributes(y) <- list(names = "z")
levels(y) <- c("lo", "hi")
attributes(x) <- NULL
list(y, dim(x), attr(y, "levels"), class(x), oldClass(y), unclass(y))
