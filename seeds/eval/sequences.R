n <- 7L
s <- seq_len(n)
t <- seq.int(from = 2, to = 20, by = 3)
u <- seq.int(0, 1, length.out = 5)
v <- rep(c(1L, 2L), times = 3)
w <- rep(s, each = 2, length.out = 10)
total <- 0
for (i in seq_along(t)) total <- total + t[[i]] * s[i %% n + 1L]
c(total, sum(u), max(v), length(w), prod(seq_len(5)))
