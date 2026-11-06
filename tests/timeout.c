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

/* A registered call, shared by two slots, that the input "LABELED" runs. */
static SEXP labeled_call;

int fuzz_target_init(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    fuzz_init_r();

    SEXP text, exprs;
    ParseStatus status;
    Rf_protect(text = Rf_mkString("Sys.sleep(60)"));
    Rf_protect(exprs = R_ParseVector(text, -1, &status, R_NilValue));
    assert(status == PARSE_OK);
    R_PreserveObject(labeled_call = VECTOR_ELT(exprs, 0));
    Rf_unprotect(2);
    fuzz_label_call(labeled_call, 2, 6);
    fuzz_label_call(labeled_call, 5, 6);
    return 0;
}

int fuzz_target_run(const uint8_t *data, size_t size)
{
    if (unblock_on_next_input) {
        unblock_on_next_input = 0;
        set_dump_signal(SIG_UNBLOCK);
    }

    if (strcmp((const char *)data, "LABELED") == 0) {
        fuzz_eval_silent(labeled_call, R_GlobalEnv);
        return 0;
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

/* The stand-in for libFuzzer's alarm.  Its clock can be backdated, to
 * stand for a slow handoff, and it can be told to let one timeout pass
 * with a message instead of exiting, so a scenario can go on. */
static struct timespec unit_start;
static int unit_running;
static double standin_backdate;
static int standin_lenient_once;

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
    if (seconds < TIMEOUT)
        return;
    if (standin_lenient_once) {
        standin_lenient_once = 0;
        fuzz_write_stderr("STANDIN: timeout, let pass\n");
        return;
    }
    fuzz_write_stderr("STANDIN: timeout\n");
    _Exit(TIMEOUT_EXIT);
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

/* Re-phase the ticks: the first lands `first` seconds from now. */
static void standin_ticks_at(double first)
{
    struct itimerval timer = {
        { TIMEOUT / 2 + 1, 0 },
        { (time_t)first, (suseconds_t)((first - (time_t)first) * 1e6) }
    };
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
}

static void standin_run(const char *source)
{
    clock_gettime(CLOCK_REALTIME, &unit_start);
    unit_start.tv_sec -= (time_t)standin_backdate;
    unit_start.tv_nsec -= (long)((standin_backdate - (time_t)standin_backdate) * 1e9);
    if (unit_start.tv_nsec < 0) {
        unit_start.tv_nsec += 1000000000L;
        unit_start.tv_sec--;
    }
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

/* Scenarios, each the body of a child process. */

/* Ticks while idle, with the clock since idle past the timeout, find
 * nothing to dump; the input then gets the one dump. */
static void scenario_slow(void)
{
    standin_start();
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

/* An idle spell puts the clock since idle past the timeout while the
 * input's own clock is within it: the tick is held, and the input, which
 * finishes in time, is neither dumped nor reported. */
static void scenario_finishes_in_time(void)
{
    standin_start();
    fuzz_run_on_r_thread(block_dump_signal, NULL);
    standin_idle(TIMEOUT);
    standin_run("Sys.sleep(" STR(TIMEOUT) " - 0.5)");
}

/* As above, with a second tick queueing up during the hold and the
 * stand-in's clock running half a second ahead of the input's, as after
 * a slow handoff: the queued tick, delivered as the held one returns,
 * finds the input over and must not report it. */
static void scenario_pending_tick(void)
{
    standin_start();
    fuzz_run_on_r_thread(block_dump_signal, NULL);
    standin_idle(TIMEOUT);
    standin_backdate = 0.5;
    standin_ticks_at(0.5);  /* then 2.5 s, while the first is held */
    standin_run("Sys.sleep(" STR(TIMEOUT) " - 0.2)");
}

/* A tick in the last second of an input that goes on past the timeout:
 * held to the timeout, then the input is dumped (unanswered here) and
 * reported, though it finishes while the dump is awaited. */
static void scenario_finishes_during_dump(void)
{
    standin_start();
    fuzz_run_on_r_thread(block_dump_signal, NULL);
    standin_ticks_at(TIMEOUT - 0.3);
    standin_run("Sys.sleep(" STR(TIMEOUT) " + 0.3)");
}

/* A tick in the last second of an input that finishes in time, after an
 * idle spell that puts the clock since idle past the timeout: a dump
 * would pause the R thread past the deadline, so none may be taken. */
static void scenario_slow_dump_finishes_in_time(void)
{
    standin_start();
    standin_run("1");
    install_slow_dump();
    standin_idle(1);
    standin_ticks_at(TIMEOUT - 0.4);
    standin_run("Sys.sleep(" STR(TIMEOUT) " - 0.1)");
}

/* A registered call times out: its slots and source precede the frames. */
static void scenario_labeled(void)
{
    standin_start();
    standin_run("LABELED");
}

/* The slow dump still comes, in full, for an input that times out. */
static void scenario_slow_dump_times_out(void)
{
    standin_start();
    standin_run("1");
    install_slow_dump();
    standin_run("Sys.sleep(60)");
}

/* A dump request left pending by one input (blocked, and the stand-in
 * let that timeout pass) is delivered as the next input begins, after
 * the handoff; the next input must still get a dump of its own. */
static void scenario_stale_dump(void)
{
    standin_start();
    fuzz_run_on_r_thread(block_dump_signal, NULL);
    standin_lenient_once = 1;
    standin_ticks_at(TIMEOUT - 0.3);
    standin_run("Sys.sleep(" STR(TIMEOUT) " + 0.3)");
    unblock_on_next_input = 1;
    standin_run("Sys.sleep(60)");
}

/* The handler on its own, from the hold on: a helper thread plays the R
 * thread, landing the dump or finishing the input after a while; the
 * chained handler is a recorder.  No R is needed. */
static void record_chained(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    (void)context;
    fuzz_write_stderr("CHAINED\n");
}

typedef struct {
    double started_ago;      /* the input's age, seconds */
    long poll_ns;            /* the handler's sleep between looks */
    int requested_already;   /* the dump was asked for on an earlier tick */
    int finishes_input;      /* the helper finishes the input, else lands the dump */
    int after_ms;
} hold_case_t;

static void *play_r_thread(void *data)
{
    hold_case_t *c = data;
    struct timespec pause = { 0, c->after_ms * 1000 * 1000 };
    nanosleep(&pause, NULL);
    if (c->finishes_input)
        atomic_store(&fuzz_alarm.running, 0);
    else
        atomic_store(&fuzz_alarm.done, atomic_load(&fuzz_alarm.input));
    return NULL;
}

static void run_handler(hold_case_t *c)
{
    fuzz_alarm.timeout = TIMEOUT;
    fuzz_alarm.poll_ns = c->poll_ns;
    fuzz_alarm.chain.sa_sigaction = record_chained;
    clock_gettime(CLOCK_REALTIME, &fuzz_alarm.armed);
    fuzz_alarm.armed.tv_sec -= TIMEOUT;
    clock_gettime(CLOCK_REALTIME, &fuzz_alarm.started);
    fuzz_alarm.started.tv_sec -= (time_t)c->started_ago;
    fuzz_alarm.started.tv_nsec -= (long)((c->started_ago - (time_t)c->started_ago) * 1e9);
    if (fuzz_alarm.started.tv_nsec < 0) {
        fuzz_alarm.started.tv_nsec += 1000000000L;
        fuzz_alarm.started.tv_sec--;
    }
    atomic_store(&fuzz_alarm.input, 7);
    atomic_store(&fuzz_alarm.requested, c->requested_already ? 7 : 6);
    atomic_store(&fuzz_alarm.done, 6);
    atomic_store(&fuzz_alarm.running, 1);

    pthread_t helper;
    assert(pthread_create(&helper, NULL, play_r_thread, c) == 0);
    fuzz_alarm_handler(SIGALRM, NULL, NULL);
    assert(pthread_join(helper, NULL) == 0);
}

/* Out of time, dump requested earlier: the wait ends on the dump landing. */
static void scenario_dump_lands(void)
{
    hold_case_t c = { TIMEOUT, 1000 * 1000, 1, 0, 50 };
    run_handler(&c);
}

/* Out of time, dump unanswered: the wait ends on the input finishing. */
static void scenario_input_finishes_unanswered(void)
{
    hold_case_t c = { TIMEOUT, 1000 * 1000, 1, 1, 50 };
    run_handler(&c);
}

/* Held 50 ms short of the timeout with 100 ms between looks, the input
 * finishes 25 ms in: it ends, and the deadline passes, inside the one
 * sleep.  The input was within its time, so no dump and no report. */
static void scenario_finishes_in_final_sleep(void)
{
    hold_case_t c = { TIMEOUT - 0.05, 100 * 1000 * 1000, 0, 1, 25 };
    run_handler(&c);
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
    expect(strstr(result.output, "==fuzz== slot") == NULL, "slow: no slot for an unregistered call", &result);

    /* A registered call: its label, then the frames. */
    run_scenario("labeled", scenario_labeled, &result);
    expect(exited_with(&result, TIMEOUT_EXIT), "labeled: chained to the alarm", &result);
    dump = strstr(result.output, header);
    const char *label = dump == NULL ? NULL :
        strstr(dump, "==fuzz== slot 2, 5 of 6:\n    Sys.sleep(60)\n");
    expect(label != NULL, "labeled: slots and source printed after the header", &result);
    expect_frames(label, "labeled: frames follow the label", &result);

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

    /* A held tick releases a finishing input without dump or report. */
    run_scenario("finishes-in-time", scenario_finishes_in_time, &result);
    expect(exited_with(&result, 0), "finishes-in-time: no timeout", &result);
    expect(strstr(result.output, "==fuzz==") == NULL, "finishes-in-time: not dumped", &result);
    expect(strstr(result.output, "STANDIN") == NULL, "finishes-in-time: no report", &result);
    expect(result.seconds < 2 * TIMEOUT + 1, "finishes-in-time: released at once", &result);

    /* A tick queued during the hold does not report the finished input. */
    run_scenario("pending-tick", scenario_pending_tick, &result);
    expect(exited_with(&result, 0), "pending-tick: no timeout", &result);
    expect(strstr(result.output, "==fuzz==") == NULL, "pending-tick: not dumped", &result);
    expect(strstr(result.output, "STANDIN") == NULL, "pending-tick: no report", &result);

    /* An input out of time by its own clock is dumped and reported, even
     * if it finishes while the dump is awaited. */
    run_scenario("finishes-during-dump", scenario_finishes_during_dump, &result);
    expect(exited_with(&result, TIMEOUT_EXIT), "finishes-during-dump: chained to the alarm", &result);
    dump = strstr(result.output, header);
    report = strstr(result.output, standin);
    expect(dump != NULL && report != NULL && report > dump, "finishes-during-dump: report follows the dump", &result);

    /* An input that may still finish is not paused for a dump. */
    run_scenario("slow-dump-finishes-in-time", scenario_slow_dump_finishes_in_time, &result);
    expect(exited_with(&result, 0), "slow-dump-finishes-in-time: no timeout", &result);
    expect(strstr(result.output, header) == NULL, "slow-dump-finishes-in-time: not dumped", &result);
    expect(strstr(result.output, "STANDIN") == NULL, "slow-dump-finishes-in-time: no report", &result);

    /* A slow dump is waited for and precedes the report. */
    run_scenario("slow-dump-times-out", scenario_slow_dump_times_out, &result);
    expect(exited_with(&result, TIMEOUT_EXIT), "slow-dump-times-out: chained to the alarm", &result);
    dump = strstr(result.output, header);
    report = strstr(result.output, standin);
    expect(dump != NULL && report != NULL && report > dump, "slow-dump-times-out: report follows the dump", &result);
    expect_frames(dump, "slow-dump-times-out: frames printed", &result);

    /* The wait ends on the dump, well before its bound... */
    run_scenario("dump-lands", scenario_dump_lands, &result);
    expect(exited_with(&result, 0), "dump-lands: returned", &result);
    expect(strstr(result.output, "CHAINED\n") != NULL, "dump-lands: chained", &result);
    expect(result.seconds < 1, "dump-lands: on the dump, not the bound", &result);

    /* ...and likewise on the input finishing with the dump unanswered. */
    run_scenario("input-finishes-unanswered", scenario_input_finishes_unanswered, &result);
    expect(exited_with(&result, 0), "input-finishes-unanswered: returned", &result);
    expect(strstr(result.output, "CHAINED\n") != NULL, "input-finishes-unanswered: chained", &result);
    expect(result.seconds < 1, "input-finishes-unanswered: on the input, not the bound", &result);

    /* An input finishing in the hold's last sleep is not dumped or reported. */
    run_scenario("finishes-in-final-sleep", scenario_finishes_in_final_sleep, &result);
    expect(exited_with(&result, 0), "finishes-in-final-sleep: returned", &result);
    expect(strstr(result.output, header) == NULL, "finishes-in-final-sleep: not dumped", &result);
    expect(strstr(result.output, "CHAINED") == NULL, "finishes-in-final-sleep: not chained", &result);

    /* A dump outstanding from one input does not serve the next. */
    run_scenario("stale-dump", scenario_stale_dump, &result);
    expect(exited_with(&result, TIMEOUT_EXIT), "stale-dump: chained to the alarm", &result);
    dump = strstr(result.output, header);
    second = dump == NULL ? NULL : strstr(dump + 1, header);
    report = strstr(result.output, standin);
    expect(strstr(result.output, "STANDIN: timeout, let pass\n") != NULL, "stale-dump: first input reported", &result);
    expect(dump != NULL && second != NULL, "stale-dump: both inputs dumped", &result);
    expect_frames(second, "stale-dump: the second input's frames printed", &result);
    expect(report != NULL && report > second, "stale-dump: report follows the second dump", &result);

    puts("timeout diagnostics checks passed");
    return 0;
}
