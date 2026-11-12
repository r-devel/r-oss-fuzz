/*
 * Exercise R's socket connections as a state machine: sockconn.c, Rsock.c
 * and sock.c in the internet module, and do_sockselect / do_socktimeout in
 * src/main/connections.c.
 *
 * The other targets hand one R function one hostile value.  Sockets fail
 * differently: the bugs are in what a connection lets you do in a state
 * it was not written for (never opened, open failed, peer gone, half a
 * line buffered).  So each input is a short program of socket calls over
 * four connection slots and one listening socket, all in this process and
 * all on the loopback interface (instrumentation/0006 binds R's server
 * sockets to 127.0.0.1); see `interpreter` below for the calls.
 *
 * Two things here are unlike the other harnesses.
 *
 * Nothing may wait.  R's socket code waits in select() for up to the
 * connection's timeout, and a wait of even a second per call would starve
 * the fuzzer and report as a timeout.  Every connection is therefore
 * created with timeout = 0, which makes each read and write a poll, and
 * the interpreter only connects where the answer is immediate (the
 * process's own listener, or port 0, which refuses) and only accepts a
 * connection that is already queued.  sock_open() replaces a timeout of 0
 * by 60 seconds for connect() and accept(), which is why those two are
 * guarded rather than left to time out.
 *
 * The internet module is needed.  ossfuzz.sh removes it from the bundled
 * R so that no other target can reach the network, and keeps a copy for
 * this one; see sockets_load_module().
 */

#include <stdint.h>
#include <string.h>

#include "common.h"

/* 64 three-byte operations; keep options/sockets.options in step. */
#define FUZZ_MAX_INPUT 192

#define N_CALLS 1

static SEXP calls[N_CALLS];

/*
 * Each operation is three bytes: op, a, b.  op %% 13 picks the call and
 * op %/% 13 %% 4 the slot it applies to; a and b are its arguments.  The
 * whole input doubles as the pool that written data is taken from.
 *
 * State kept between inputs is the listener's port alone: if another
 * fuzzing process holds it, the next free one is used from then on.
 * Everything else is closed when the input ends, so a connection table
 * of 128 entries never fills up.
 */
static const char interpreter[] = R"(
local({
    encodings <- c("native.enc", "UTF-8", "latin1", "UTF-16LE")
    modes <- c("r", "w", "a+", "r+", "rb", "wb", "a+b", "r+b")

    # Lengths either side of the 4096-byte input buffer of a socket.
    sizes <- c(1L, 100L, 4095L, 4096L, 4097L, 9000L)

    # For connections made with server = TRUE, which are never opened.
    passive_ports <- c(0L, 1L, 65535L, 65536L, 1000000L)

    port <- 0L
    listener <- NULL
    pending <- 0L                # connected to the listener, not yet accepted
    written <- 0L
    cons <- vector("list", 4L)
    dest <- integer(4L)          # port a slot connects to; 0 refuses at once
    passive <- logical(4L)       # opening would wait for a peer: never done

    drop <- function(k) {
        con <- cons[[k]]
        cons[k] <<- list(NULL)
        if (!is.null(con))
            close(con)
    }

    listen <- function() {
        if (!is.null(listener))
            return(invisible())

        for (p in port + 0:15) {
            s <- tryCatch(serverSocket(p), error = function(e) NULL)
            if (!is.null(s)) {
                port <<- p
                listener <<- s
                pending <<- 0L
                break
            }
        }
    }

    unlisten <- function() {
        s <- listener
        listener <<- NULL
        pending <<- 0L
        if (!is.null(s))
            close(s)
    }

    # Can slot k be opened without waiting?  Port 0 refuses at once, and
    # this process's listener answers at once while its queue has room.
    # Any other port may be closed, or another process's listener.
    prompt <- function(k) {
        if (dest[k] == 0L)
            return(TRUE)

        !is.null(listener) && dest[k] == port && pending < 8L
    }

    # Can slot k be read, written or opened?  Reads and writes open an
    # unopened connection, so they are held to the same rule.
    usable <- function(k) {
        con <- cons[[k]]
        if (is.null(con) || passive[k])
            return(FALSE)

        isOpen(con) || prompt(k)
    }

    # Count a connection that slot k has just made to the listener.
    note_open <- function(k, was_open) {
        con <- cons[[k]]
        if (!was_open && !is.null(con) && dest[k] != 0L && isOpen(con))
            pending <<- pending + 1L
    }

    client <- function(k, a, mode) {
        drop(k)
        dest[k] <<- if (bitwAnd(a, 2L) != 0L) port else 0L
        passive[k] <<- FALSE
        if (!prompt(k))
            mode <- ""

        cons[[k]] <<- socketConnection(
            "127.0.0.1",
            dest[k],
            server = FALSE,
            blocking = bitwAnd(a, 1L) != 0L,
            open = mode,
            encoding = encodings[bitwAnd(a, 12L) %/% 4L + 1L],
            timeout = 0L,
            options = if (bitwAnd(a, 16L) != 0L) "no-delay"
        )
        note_open(k, FALSE)
    }

    passive_connection <- function(k, a) {
        drop(k)
        dest[k] <<- 0L
        passive[k] <<- TRUE

        cons[[k]] <<- socketConnection(
            port = passive_ports[a %% 5L + 1L],
            server = TRUE,
            blocking = bitwAnd(a, 8L) != 0L,
            open = "",
            timeout = 0L
        )
    }

    open_slot <- function(k, b) {
        if (!usable(k))
            return(invisible())

        con <- cons[[k]]
        was_open <- isOpen(con)
        on.exit(note_open(k, was_open))

        open(con, modes[b %% 8L + 1L])
    }

    # Only a connection this input made, and only once it is queued:
    # socketAccept() would otherwise wait for one.
    accept <- function(k, a, b) {
        if (is.null(listener) || pending == 0L)
            return(invisible())
        if (!socketSelect(list(listener), timeout = 0))
            return(invisible())

        drop(k)
        con <- socketAccept(
            listener,
            blocking = bitwAnd(a, 1L) != 0L,
            open = modes[b %% 8L + 1L],
            encoding = encodings[bitwAnd(a, 12L) %/% 4L + 1L],
            timeout = 0L,
            options = if (bitwAnd(a, 16L) != 0L) "no-delay"
        )

        pending <<- pending - 1L
        dest[k] <<- 0L
        passive[k] <<- FALSE
        cons[[k]] <<- con
    }

    # Any mix of slots, open or not, the listener, the same socket twice
    # and something that is not a socket.
    select <- function(a, b) {
        socks <- cons[bitwAnd(a, c(1L, 2L, 4L, 8L)) != 0L]
        socks <- socks[!vapply(socks, is.null, NA)]
        if (bitwAnd(a, 16L) != 0L && !is.null(listener))
            socks <- c(socks, list(listener))
        if (bitwAnd(a, 32L) != 0L && length(socks) > 0L)
            socks <- c(socks, socks[1L])
        if (bitwAnd(a, 64L) != 0L)
            socks <- c(socks, list(stdin()))

        write <- as.logical(intToBits(b)[seq_along(socks)])
        socketSelect(socks, write, timeout = 0)
    }

    # Never a positive timeout: reads and writes would start to wait.
    set_timeout <- function(k, a) {
        con <- if (bitwAnd(a, 4L) != 0L) listener else cons[[k]]
        socketTimeout(con, c(0L, -1L, NA)[a %% 3L + 1L])
    }

    # The cap keeps the loopback buffers from filling when nothing reads.
    send <- function(k, a, b, x) {
        if (!usable(k) || written > 32768L)
            return(invisible())

        con <- cons[[k]]
        was_open <- isOpen(con)
        on.exit(note_open(k, was_open))

        from <- (b + seq_len(a %/% 8L + 1L) - 1L) %% length(x) + 1L
        payload <- x[from]
        text <- rawToChar(payload[payload != as.raw(0L)])
        long <- rep_len(payload, sizes[b %% 6L + 1L])
        written <<- written + length(long)

        switch(a %% 4L + 1L,
            writeBin(payload, con),
            writeBin(long, con),
            writeLines(text, con),
            writeChar(text, con, eos = NULL)
        )
    }

    receive <- function(k, a, b) {
        if (!usable(k))
            return(invisible())

        con <- cons[[k]]
        was_open <- isOpen(con)
        on.exit(note_open(k, was_open))

        switch(a %% 5L + 1L,
            readLines(con, n = b %% 4L, warn = FALSE),
            readBin(con, "raw", sizes[b %% 6L + 1L]),
            readChar(con, c(1L, b %% 64L), useBytes = TRUE),
            readChar(con, b %% 64L, useBytes = FALSE),
            readBin(con, "integer", 3L, size = 2L)
        )
        isIncomplete(con)
    }

    # None of these opens a connection, so any slot will do.
    status <- function(k, a) {
        con <- cons[[k]]
        if (is.null(con))
            return(invisible())

        switch(a %% 6L + 1L,
            summary(con),
            isIncomplete(con),
            flush(con),
            seek(con, 0L),
            truncate(con),
            pushBack("pushed back", con)
        )
    }

    step <- function(op, k, a, b, x) {
        switch(op + 1L,
            client(k, a, ""),
            client(k, a, modes[b %% 8L + 1L]),
            passive_connection(k, a),
            listen(),
            unlisten(),
            open_slot(k, b),
            accept(k, a, b),
            select(a, b),
            set_timeout(k, a),
            send(k, a, b, x),
            receive(k, a, b),
            drop(k),
            status(k, a)
        )
    }

    reset <- function() {
        for (k in seq_along(cons))
            tryCatch(drop(k), error = function(e) NULL)
        tryCatch(unlisten(), error = function(e) NULL)
    }

    function(x, base) {
        if (port == 0L)
            port <<- base
        written <<- 0L
        on.exit(reset())

        for (i in seq_len(min(length(x) %/% 3L, 64L))) {
            op <- as.integer(x[3L * i - 2L])
            a <- as.integer(x[3L * i - 1L])
            b <- as.integer(x[3L * i])
            tryCatch(
                step(op %% 13L, op %/% 13L %% 4L + 1L, a, b, x),
                error = function(e) NULL
            )
        }
    }
})
)";

/* Creating a socket connection is what loads the module; nothing is
 * opened, so this touches no network. */
static const char module_probe[] = R"(
function() {
    close(socketConnection("127.0.0.1", 0L, open = ""))
}
)";

/*
 * Load R's internet module, which ossfuzz.sh keeps out of every other
 * target's reach.
 *
 * R loads it on the first socket call from $R_HOME/modules, reading
 * R_HOME from the environment at that moment (R_moduleCdynload).  The
 * build moves the module to $R_HOME/fuzz-internet/modules instead, so
 * pointing R_HOME there for that one call loads it, and for every other
 * target the same call fails with "internet routines cannot be loaded".
 * A local R build has the module in the usual place and needs none of
 * this.
 *
 * R remembers a failed load and never retries, so a build that cannot
 * load the module would run every input as a no-op and report nothing.
 * That is a build error, not an input to skip: abort.
 */
static void sockets_load_module(void)
{
    const char *home = getenv("R_HOME");
    char *real_home = NULL;

    if (home != NULL) {
        char stash[PATH_MAX], module[PATH_MAX];
        snprintf(stash, sizeof stash, "%s/fuzz-internet", home);
        snprintf(module, sizeof module, "%s/modules/internet.so", stash);
        if (access(module, R_OK) == 0) {
            real_home = strdup(home);
            if (real_home == NULL)
                abort();
            setenv("R_HOME", stash, 1);
        }
    }

    int error = 0;
    SEXP probe;
    Rf_protect(probe = Rf_lang1(fuzz_make_wrapper(module_probe)));
    R_tryEvalSilent(probe, R_GlobalEnv, &error);
    Rf_unprotect(1);

    if (real_home != NULL) {
        setenv("R_HOME", real_home, 1);
        free(real_home);
    }

    if (error) {
        fprintf(stderr, "sockets: cannot load R's internet module: %s\n",
                R_curErrorBuf());
        abort();
    }
}

int fuzz_target_init(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();
    sockets_load_module();

    /* Spread concurrent fuzzing processes over the ports below the
     * ephemeral range; the interpreter moves on if one is taken. */
    int base = 10000 + (int)((unsigned)getpid() * 7919u % 20000u);

    SEXP placeholder, port, wrapper;
    Rf_protect(placeholder = Rf_allocVector(RAWSXP, 1));
    Rf_protect(port = Rf_ScalarInteger(base));
    Rf_protect(wrapper = fuzz_make_wrapper(interpreter));
    Rf_protect(calls[0] = Rf_lang3(wrapper, placeholder, port));

    fuzz_label_calls(calls, N_CALLS);
    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
{
    if (size < 3 || size > FUZZ_MAX_INPUT)
        return 0;

    if (!fuzz_set_raw_arg(calls[0], data, size))
        return 0;

    fuzz_eval_silent(calls[0], R_GlobalEnv);
    return 0;
}
