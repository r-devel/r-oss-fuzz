/* Standalone checks of the datetime harness's locale switching.  R starts
 * in a UTF-8 locale, as on the OSS-Fuzz bots, and every slot must then run
 * with R's view of LC_CTYPE, which picks R_strptime's narrow or wide path,
 * matching the C library's. */
#include <assert.h>
#include "../harnesses/datetime.c"

static int utf8_available;

/* R's view of the locale: l10n_info()$MBCS. */
static int r_mbcs(void)
{
    SEXP call, info, names;
    int error = 0, mbcs = -1;

    Rf_protect(call = Rf_lang1(Rf_install("l10n_info")));
    Rf_protect(info = R_tryEval(call, R_GlobalEnv, &error));
    assert(!error);

    names = Rf_getAttrib(info, R_NamesSymbol);
    for (R_xlen_t i = 0; i < XLENGTH(info); i++) {
        if (strcmp(CHAR(STRING_ELT(names, i)), "MBCS") == 0)
            mbcs = LOGICAL(VECTOR_ELT(info, i))[0];
    }

    Rf_unprotect(2);
    assert(mbcs != -1);
    return mbcs;
}

/* Run one input through the slot, then compare both views of LC_CTYPE
 * with the setting the slot asks for. */
static void check_slot(int slot)
{
    static const char payload[] = "%Y-%m-%d\n2024-01-15";
    uint8_t input[sizeof(payload)];
    input[0] = (uint8_t)slot;
    memcpy(input + 1, payload, sizeof(payload) - 1);
    fuzz_target_run(input, sizeof(input));

    int want = utf8_available && slot >= FIRST_UTF8_CALL;
    int r = r_mbcs();
    int c = MB_CUR_MAX > 1;
    if (r != want || c != want) {
        fprintf(stderr, "slot %d: R MBCS %d, C MB_CUR_MAX > 1 %d, want %d\n",
                slot, r, c, want);
        abort();
    }
}

static void run_checks(void *unused)
{
    (void)unused;

    /* Slot 0 first: a C slot straight after init is what the bots ran in
     * the wide path while R still believed its startup locale. */
    for (int slot = 0; slot < N_CALLS; slot++)
        check_slot(slot);

    /* And back from the UTF-8 slots to C. */
    check_slot(0);
}

int main(int argc, char **argv)
{
    const char *utf8 = find_utf8_locale();
    utf8_available = utf8 != NULL;
    if (utf8_available)
        setenv("LC_ALL", utf8, 1);
    else
        puts("no UTF-8 locale here; every slot should run in C");

    LLVMFuzzerInitialize(&argc, &argv);
    fuzz_run_on_r_thread(run_checks, NULL);
    puts("datetime harness locale checks passed");
    return 0;
}
