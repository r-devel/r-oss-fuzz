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
    /* Ticks while idle, with the clock since idle past the timeout, find
     * nothing to dump; the input then gets the one dump. */
    standin_idle(TIMEOUT);
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

/* A tick just before the deadline starts a wait the input finishes
 * during, just after the stand-in's deadline: as when the alarm runs
 * unhindered and finds the input young, nothing is reported. */
static void scenario_finishes_during_wait(void)
{
    standin_start();
    fuzz_run_on_r_thread(block_dump_signal, NULL);

    struct itimerval timer = {
        { TIMEOUT / 2 + 1, 0 },
        { TIMEOUT - 1, 700 * 1000 }  /* 0.7 s in: a tick inside the last second */
    };
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    standin_run("Sys.sleep(" STR(TIMEOUT) " + 0.3)");
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

/* A tick queues up while another is held; the input then finishes just
 * past the stand-in's deadline.  The queued tick, delivered as the held
 * one returns, must not report the finished input. */
static void scenario_pending_tick(void)
{
    standin_start();
    fuzz_run_on_r_thread(block_dump_signal, NULL);
    standin_idle(TIMEOUT);

    /* Ticks at 0.5 s and 2.5 s into the input. */
    struct itimerval timer = { { TIMEOUT / 2 + 1, 0 }, { 0, 500 * 1000 } };
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    standin_run("Sys.sleep(" STR(TIMEOUT) " + 0.3)");
}

/* A stack printer that takes its time, as symbolizing can. */
static struct sigaction prompt_dump;

static void slow_dump_handler(int sig, siginfo_t *info, void *context)
{
    struct timespec pause = { 0, 500 * 1000 * 1000 };
    nanosleep(&pause, NULL);
    prompt_dump.sa_sigaction(sig, info, context);
}

/* Once the wrapper is in (after the first input), slow its dump. */
static void install_slow_dump(void)
{
    assert(sigaction(FUZZ_DUMP_SIGNAL, NULL, &prompt_dump) == 0);
    assert(prompt_dump.sa_flags & SA_SIGINFO);
    struct sigaction slow = prompt_dump;
    slow.sa_sigaction = slow_dump_handler;
    assert(sigaction(FUZZ_DUMP_SIGNAL, &slow, NULL) == 0);
}

/* A tick in the last second of an input that finishes in time: a dump
 * would pause the R thread past the deadline, so none may be taken. */
static void scenario_slow_dump_finishes_in_time(void)
{
    standin_start();
    standin_run("1");
    install_slow_dump();

    struct itimerval timer = {
        { TIMEOUT / 2 + 1, 0 },
        { TIMEOUT - 1, 600 * 1000 }  /* 0.6 s into the last second */
    };
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    standin_run("Sys.sleep(" STR(TIMEOUT) " - 0.1)");
}

/* The slow dump still comes, in full, for an input that times out. */
static void scenario_slow_dump_times_out(void)
{
    standin_start();
    standin_run("1");
    install_slow_dump();
    standin_run("Sys.sleep(60)");
}

/* The wait loop on its own: a helper thread plays the R thread, landing
 * the dump 50 ms in and, if asked, finishing the input in the same
 * breath; the chained handler is a recorder.  No R is needed. */
static void record_chained(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    (void)context;
    fuzz_write_stderr("CHAINED\n");
}

static void *land_dump(void *data)
{
    int input_finishes = *(int *)data;
    struct timespec pause = { 0, 50 * 1000 * 1000 };
    nanosleep(&pause, NULL);
    /* The input is seen to finish no later than the dump, whichever poll
     * looks first. */
    if (input_finishes)
        atomic_store(&fuzz_alarm.running, 0);
    atomic_store(&fuzz_alarm.done, atomic_load(&fuzz_alarm.input));
    return NULL;
}

static void run_wait_loop(int input_finishes)
{
    fuzz_alarm.timeout = TIMEOUT;
    fuzz_alarm.chain.sa_sigaction = record_chained;
    clock_gettime(CLOCK_REALTIME, &fuzz_alarm.armed);
    fuzz_alarm.armed.tv_sec -= TIMEOUT;
    atomic_store(&fuzz_alarm.input, 7);
    atomic_store(&fuzz_alarm.requested, 7);  /* asked for on an earlier tick */
    atomic_store(&fuzz_alarm.done, 6);
    atomic_store(&fuzz_alarm.running, 1);

    pthread_t helper;
    assert(pthread_create(&helper, NULL, land_dump, &input_finishes) == 0);
    fuzz_alarm_handler(SIGALRM, NULL, NULL);
    assert(pthread_join(helper, NULL) == 0);
}

static void scenario_dump_lands_input_runs(void)
{
    run_wait_loop(0);
}

static void scenario_dump_lands_input_done(void)
{
    run_wait_loop(1);
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

    /* An input finishing during the wait is not blamed for the wait. */
    run_scenario("finishes-during-wait", scenario_finishes_during_wait, &result);
    expect(strstr(result.output, header) != NULL, "finishes-during-wait: dump requested", &result);
    expect(exited_with(&result, 0), "finishes-during-wait: no timeout", &result);
    expect(strstr(result.output, standin) == NULL, "finishes-during-wait: no report", &result);
    expect(result.seconds < TIMEOUT + 2, "finishes-during-wait: released at once", &result);

    /* A tick queued during the hold does not report the finished input. */
    run_scenario("pending-tick", scenario_pending_tick, &result);
    expect(strstr(result.output, header) != NULL, "pending-tick: dump requested", &result);
    expect(exited_with(&result, 0), "pending-tick: no timeout", &result);
    expect(strstr(result.output, standin) == NULL, "pending-tick: no report", &result);

    /* An input that may still finish is not paused for a dump. */
    run_scenario("slow-dump-finishes-in-time", scenario_slow_dump_finishes_in_time, &result);
    expect(exited_with(&result, 0), "slow-dump-finishes-in-time: no timeout", &result);
    expect(strstr(result.output, header) == NULL, "slow-dump-finishes-in-time: not dumped", &result);
    expect(strstr(result.output, standin) == NULL, "slow-dump-finishes-in-time: no report", &result);

    /* A slow dump is waited for and precedes the report. */
    run_scenario("slow-dump-times-out", scenario_slow_dump_times_out, &result);
    expect(exited_with(&result, TIMEOUT_EXIT), "slow-dump-times-out: chained to the alarm", &result);
    dump = strstr(result.output, header);
    report = strstr(result.output, standin);
    expect(dump != NULL && report != NULL && report > dump, "slow-dump-times-out: report follows the dump", &result);
    expect_frames(dump, "slow-dump-times-out: frames printed", &result);

    /* The wait ends on the dump and chains while the input still runs... */
    run_scenario("dump-lands-input-runs", scenario_dump_lands_input_runs, &result);
    expect(exited_with(&result, 0), "dump-lands-input-runs: returned", &result);
    expect(strstr(result.output, "CHAINED\n") != NULL, "dump-lands-input-runs: chained", &result);
    expect(result.seconds < 1, "dump-lands-input-runs: on the dump, not the bound", &result);

    /* ...but not when the input finished as the dump landed. */
    run_scenario("dump-lands-input-done", scenario_dump_lands_input_done, &result);
    expect(exited_with(&result, 0), "dump-lands-input-done: returned", &result);
    expect(strstr(result.output, "CHAINED") == NULL, "dump-lands-input-done: not chained", &result);

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
