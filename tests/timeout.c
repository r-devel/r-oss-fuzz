/* Standalone checks of common.h's timeout diagnostics.  libFuzzer's alarm
 * needs libFuzzer's main, so a stand-in plays its part: an SA_SIGINFO
 * SIGALRM handler on a periodic timer that exits with libFuzzer's timeout
 * code once the input has run for the timeout.  Each scenario runs in a
 * child whose stderr the parent inspects. */
#include <assert.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "../harnesses/common.h"

#define TIMEOUT 3
#define STR_(x) #x
#define STR(x) STR_(x)
#define TIMEOUT_EXIT 70
#define OUTPUT_MAX 65536

/* The harness under test: the input is R source.  A scenario may ask
 * for the dump signal to be unblocked as the next input begins. */
static int unblock_on_next_input;

static void set_dump_signal(int how)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, FUZZ_DUMP_SIGNAL);
    pthread_sigmask(how, &set, NULL);
}

int fuzz_target_init(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();
    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
{
    if (unblock_on_next_input) {
        unblock_on_next_input = 0;
        set_dump_signal(SIG_UNBLOCK);
    }

    SEXP text, exprs;
    ParseStatus status;
    Rf_protect(text = Rf_mkString((const char *)data));
    Rf_protect(exprs = R_ParseVector(text, -1, &status, R_NilValue));
    if (status == PARSE_OK)
        for (R_xlen_t i = 0; i < XLENGTH(exprs); i++)
            fuzz_eval_silent(VECTOR_ELT(exprs, i), R_GlobalEnv);
    Rf_unprotect(2);
    (void)size;
    return 0;
}

/* The stand-in for libFuzzer's alarm. */
static struct timespec unit_start;
static int unit_running;

static void standin_alarm(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    (void)context;
    if (!unit_running)
        return;
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    long seconds = now.tv_sec - unit_start.tv_sec;
    if (now.tv_nsec < unit_start.tv_nsec)
        seconds--;
    if (seconds >= TIMEOUT) {
        fuzz_write_stderr("STANDIN: timeout\n");
        _Exit(TIMEOUT_EXIT);
    }
}

/* In libFuzzer's order: the harness initializes, then the alarm goes in. */
static void standin_start(void)
{
    int argc = 2;
    char *args[] = { "check-timeout", "-timeout=" STR(TIMEOUT), NULL };
    char **argv = args;
    LLVMFuzzerInitialize(&argc, &argv);

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = standin_alarm;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGALRM, &action, NULL) == 0);

    struct itimerval timer = { { TIMEOUT / 2 + 1, 0 }, { TIMEOUT / 2 + 1, 0 } };
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
}

static void standin_run(const char *source)
{
    clock_gettime(CLOCK_REALTIME, &unit_start);
    unit_running = 1;
    LLVMFuzzerTestOneInput((const uint8_t *)source, strlen(source) + 1);
    unit_running = 0;
}

/* Sleep on the main thread through the alarm ticks. */
static void standin_idle(double seconds)
{
    struct timespec left = { (time_t)seconds, (long)((seconds - (time_t)seconds) * 1e9) };
    while (nanosleep(&left, &left) != 0)
        continue;
}

static void block_dump_signal(void *unused)
{
    (void)unused;
    set_dump_signal(SIG_BLOCK);
}

/* Scenarios, each the body of a child process. */
static void scenario_slow(void)
{
    standin_start();
    standin_run("Sys.sleep(60)");
}

static void scenario_fast(void)
{
    standin_start();
    /* 5 s: at least two alarm ticks land mid-input. */
    for (int i = 0; i < 25; i++)
        standin_run("Sys.sleep(0.2)");
}

/* The R thread never answers the dump request. */
static void scenario_no_answer(void)
{
    standin_start();
    fuzz_run_on_r_thread(block_dump_signal, NULL);
    standin_run("Sys.sleep(60)");
}

/* The wrapper's clock runs ahead of the stand-in's by an idle spell, so
 * a tick finds the input past the timeout by the one and within it by
 * the other; with the dump unanswered, the input must still finish and
 * the stand-in must not be held past its own deadline. */
static void run_unanswered_within_timeout(void)
{
    fuzz_run_on_r_thread(block_dump_signal, NULL);
    standin_idle(TIMEOUT);
    /* Longer than a tick, so one lands while the input runs. */
    standin_run("Sys.sleep(" STR(TIMEOUT) " - 0.5)");
}

static void scenario_finishes_in_time(void)
{
    standin_start();
    run_unanswered_within_timeout();
}

/* The dump left outstanding above is delivered as the next input begins,
 * after the handoff; the next input must still get a dump of its own. */
static void scenario_stale_dump(void)
{
    standin_start();
    run_unanswered_within_timeout();
    unblock_on_next_input = 1;
    standin_run("Sys.sleep(60)");
}

typedef struct {
    int status;
    double seconds;
    char output[OUTPUT_MAX];
} result_t;

static void run_scenario(const char *name, void (*body)(void), result_t *result)
{
    int fds[2];
    assert(pipe(fds) == 0);

    struct timespec started;
    clock_gettime(CLOCK_MONOTONIC, &started);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        dup2(fds[1], STDERR_FILENO);
        close(fds[0]);
        close(fds[1]);
        body();
        _Exit(0);
    }
    close(fds[1]);

    size_t used = 0;
    for (;;) {
        ssize_t n = read(fds[0], result->output + used, OUTPUT_MAX - 1 - used);
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    result->output[used] = '\0';
    close(fds[0]);
    assert(waitpid(child, &result->status, 0) == child);

    struct timespec finished;
    clock_gettime(CLOCK_MONOTONIC, &finished);
    result->seconds = (double)(finished.tv_sec - started.tv_sec) +
                      (double)(finished.tv_nsec - started.tv_nsec) / 1e9;
    fprintf(stderr, "%s: exit %d in %.1f s\n", name,
            WIFEXITED(result->status) ? WEXITSTATUS(result->status) : -1,
            result->seconds);
    if (getenv("CHECK_TIMEOUT_VERBOSE") != NULL)
        fputs(result->output, stderr);
}

static void expect(int condition, const char *what, const result_t *result)
{
    if (condition)
        return;
    fprintf(stderr, "FAILED: %s\nchild output:\n%s\n", what, result->output);
    abort();
}

static int exited_with(const result_t *result, int code)
{
    return WIFEXITED(result->status) && WEXITSTATUS(result->status) == code;
}

static const char *header = "==fuzz== R thread, where the input is running:\n";
static const char *standin = "STANDIN: timeout\n";
static const char *frame = "    #0 ";

/* The dump from `at` on holds the R thread's frames, or says why not. */
static void expect_frames(const char *at, const char *what, const result_t *result)
{
    if (__sanitizer_print_stack_trace)
        expect(strstr(at, frame) != NULL, what, result);
    else
        expect(strstr(at, "no sanitizer runtime") != NULL, what, result);
}

int main(void)
{
    static result_t result;
    const char *dump, *report, *second;

    /* A timed-out input: the R thread's stack, then libFuzzer's report. */
    run_scenario("slow", scenario_slow, &result);
    expect(exited_with(&result, TIMEOUT_EXIT), "slow: chained to the alarm", &result);
    dump = strstr(result.output, header);
    report = strstr(result.output, standin);
    expect(dump != NULL, "slow: R thread header printed", &result);
    expect(report != NULL && report > dump, "slow: report follows the dump", &result);
    expect_frames(dump, "slow: R thread frames printed", &result);
    expect(strstr(dump + 1, header) == NULL, "slow: dumped once", &result);

    /* Fast inputs under alarm ticks: nothing. */
    run_scenario("fast", scenario_fast, &result);
    expect(exited_with(&result, 0), "fast: no timeout", &result);
    expect(strstr(result.output, "==fuzz==") == NULL, "fast: nothing printed", &result);

    /* No answer from the R thread: the report still comes, within the wait. */
    run_scenario("no-answer", scenario_no_answer, &result);
    expect(exited_with(&result, TIMEOUT_EXIT), "no-answer: chained to the alarm", &result);
    expect(strstr(result.output, header) != NULL, "no-answer: header printed", &result);
    expect(strstr(result.output, frame) == NULL, "no-answer: no frames", &result);
    expect(strstr(result.output, standin) != NULL, "no-answer: report printed", &result);
    expect(result.seconds < TIMEOUT + (TIMEOUT / 2 + 1) + 5 + 3, "no-answer: wait bounded", &result);

    /* A finishing input is released as soon as it finishes. */
    run_scenario("finishes-in-time", scenario_finishes_in_time, &result);
    expect(strstr(result.output, header) != NULL, "finishes-in-time: dump requested", &result);
    expect(exited_with(&result, 0), "finishes-in-time: no timeout", &result);
    expect(strstr(result.output, standin) == NULL, "finishes-in-time: no report", &result);
    expect(result.seconds < 2 * TIMEOUT + 1, "finishes-in-time: not held for the wait", &result);

    /* A dump outstanding from one input does not serve the next. */
    run_scenario("stale-dump", scenario_stale_dump, &result);
    expect(exited_with(&result, TIMEOUT_EXIT), "stale-dump: chained to the alarm", &result);
    dump = strstr(result.output, header);
    second = dump == NULL ? NULL : strstr(dump + 1, header);
    report = strstr(result.output, standin);
    expect(dump != NULL && second != NULL, "stale-dump: both inputs dumped", &result);
    expect_frames(second, "stale-dump: the second input's frames printed", &result);
    expect(report != NULL && report > second, "stale-dump: report follows the second dump", &result);

    puts("timeout diagnostics checks passed");
    return 0;
}
