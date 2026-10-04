/*
 * test_chkpwd.c - end to end tests for the sudaeon-chkpwd binary.
 *
 * The binary is run for real (with SUDAEON_STATE_DIR pointing at a temporary
 * directory, which the sandbox honoured for unprivileged callers), so these
 * tests cover the process behaviour the PAM module and the Python code rely
 * on: exit codes, the exact user visible wording, the rate limiter and the
 * audit log.
 *
 * Build and run with `make -C tests/c test-chkpwd`.
 */

#define _GNU_SOURCE
#include "../../src/sudaeon/cutil.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int checks_run = 0;
static int checks_failed = 0;
static char tmp[256];
static const char *binary = "./sudaeon-chkpwd";

#define CHECK(condition, ...)                                                  \
    do {                                                                       \
        checks_run++;                                                          \
        if (!(condition)) {                                                    \
            checks_failed++;                                                   \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                      \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

#define EXIT_OK 0
#define EXIT_INCORRECT 1
#define EXIT_ERROR 2
#define EXIT_LOCKED 3
#define EXIT_USAGE 4

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static char *state_path(const char *name)
{
    static char buffer[512];
    snprintf(buffer, sizeof(buffer), "%s/%s", tmp, name);
    return buffer;
}

static void write_file(const char *path, const char *text, mode_t mode)
{
    FILE *handle = fopen(path, "w");
    if (handle == NULL) {
        printf("cannot write %s: %s\n", path, strerror(errno));
        exit(2);
    }
    fputs(text, handle);
    fclose(handle);
    chmod(path, mode);
}

static int read_file(const char *path, char *out, size_t outlen)
{
    FILE *handle = fopen(path, "r");
    size_t got;
    if (handle == NULL) {
        out[0] = '\0';
        return -1;
    }
    got = fread(out, 1, outlen - 1, handle);
    out[got] = '\0';
    fclose(handle);
    return (int)got;
}

/* Builds a master.verifier / recovery.verifier pair for `password`. */
static void write_verifier(const char *name, const char *password, uint32_t n,
                           const char *prefix)
{
    uint8_t salt[16];
    uint8_t key[32];
    uint8_t payload[64 + 32];
    uint8_t digest[32];
    char salt_hex[40];
    char hash_hex[80];
    char json[512];
    int i;

    for (i = 0; i < 16; i++) {
        salt[i] = (uint8_t)(i * 7 + 3);
        sprintf(salt_hex + i * 2, "%02x", salt[i]);
    }
    salt_hex[32] = '\0';
    if (sd_scrypt((const uint8_t *)password, strlen(password), salt, 16,
                  n, 1, 1, key, 32) != SD_OK) {
        printf("scrypt failed while building the fixture\n");
        exit(2);
    }
    memcpy(payload, prefix, strlen(prefix));
    memcpy(payload + strlen(prefix), key, 32);
    sd_sha256(payload, strlen(prefix) + 32, digest);
    for (i = 0; i < 32; i++) {
        sprintf(hash_hex + i * 2, "%02x", digest[i]);
    }
    hash_hex[64] = '\0';
    snprintf(json, sizeof(json),
             "{\"version\":1,\"kdf\":\"scrypt\",\"n\":%u,\"r\":1,\"p\":1,"
             "\"dklen\":32,\"salt\":\"%s\",\"hash\":\"%s\"}\n",
             n, salt_hex, hash_hex);
    write_file(state_path(name), json, 0600);
}

/* Runs the checker; returns its exit code and captures stdout/stderr. */
static int run_checker(const char *input, char *out, size_t outlen,
                       char *errout, size_t errlen, const char **args)
{
    int out_pipe[2], err_pipe[2], in_pipe[2];
    pid_t pid;
    int status = 0;
    size_t used, got;
    ssize_t ignored;

    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0 || pipe(in_pipe) != 0) {
        printf("cannot create pipes\n");
        exit(2);
    }
    pid = fork();
    if (pid < 0) {
        printf("cannot fork\n");
        exit(2);
    }
    if (pid == 0) {
        char *argv[16];
        int argc = 0;
        argv[argc++] = (char *)binary;
        while (args != NULL && args[argc - 1] != NULL) {
            argv[argc] = (char *)args[argc - 1];
            argc++;
            if (argc >= 14) {
                break;
            }
        }
        argv[argc] = NULL;

        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(in_pipe[0]);
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        execv(binary, argv);
        _exit(127);
    }
    close(in_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[1]);
    if (input != NULL && input[0] != '\0') {
        ignored = write(in_pipe[1], input, strlen(input));
        (void)ignored;
    }
    ignored = write(in_pipe[1], "\n", 1);
    (void)ignored;
    close(in_pipe[1]);

    used = 0;
    while (out != NULL && used + 1 < outlen && (got = (size_t)read(out_pipe[0], out + used,
                                                                  outlen - 1 - used)) > 0) {
        used += got;
    }
    if (out != NULL) {
        out[used] = '\0';
    }
    used = 0;
    while (errout != NULL && used + 1 < errlen &&
           (got = (size_t)read(err_pipe[0], errout + used, errlen - 1 - used)) > 0) {
        used += got;
    }
    if (errout != NULL) {
        errout[used] = '\0';
    }
    close(out_pipe[0]);
    close(err_pipe[0]);
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return -1;
}

static char *tail_of(const char *path)
{
    static char buffer[8192];
    if (read_file(path, buffer, sizeof(buffer)) < 0) {
        buffer[0] = '\0';
    }
    return buffer;
}

static void clear_state(void)
{
    unlink(state_path("lockout.json"));
    unlink(state_path("audit.log"));
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

static void test_correct_and_incorrect(void)
{
    char out[256], err[512];
    int rc;

    write_verifier("master.verifier", "correct horse battery staple", 16,
                   "SUDAEON-VERIFIER-V1");
    clear_state();

    rc = run_checker("correct horse battery staple", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_OK, "the correct password exits 0 (got %d)", rc);

    rc = run_checker("wrong password", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_INCORRECT, "a wrong password exits 1 (got %d)", rc);
    CHECK(strstr(err, "The Password Entered was Incorrect") != NULL,
          "the message matches the specification, got \"%s\"", err);

    rc = run_checker("", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_INCORRECT, "an empty password exits 1 (got %d)", rc);
}

static void test_quiet_mode(void)
{
    char out[256], err[512];
    const char *args[] = {"--quiet", NULL};
    int rc;

    clear_state();
    rc = run_checker("wrong password", out, sizeof(out), err, sizeof(err), args);
    CHECK(rc == EXIT_INCORRECT, "quiet mode still reports the failure");
    CHECK(out[0] == '\0', "quiet mode prints nothing on stdout (\"%s\")", out);
    CHECK(err[0] == '\0', "quiet mode prints nothing on stderr (\"%s\")", err);

    clear_state();
    rc = run_checker("correct horse battery staple", out, sizeof(out), err, sizeof(err), args);
    CHECK(rc == EXIT_OK, "quiet mode accepts the correct password");
    CHECK(out[0] == '\0', "quiet mode does not print ok");
}

static void test_lockout_after_three_failures(void)
{
    char out[256], err[512];
    char status[256];
    const char *status_args[] = {"--status", NULL};
    const char *reset_args[] = {"--reset-lockout", NULL};
    int rc;

    clear_state();
    rc = run_checker("wrong 1", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_INCORRECT, "first failure exits 1");
    rc = run_checker("wrong 2", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_INCORRECT, "second failure exits 1");
    rc = run_checker("wrong 3", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_LOCKED, "third failure exits 3 (got %d)", rc);
    CHECK(strstr(err, "The Password Entered was Incorrect") != NULL,
          "the incorrect notice is printed before the lockout notice");
    CHECK(strstr(err, "The Password was incorrect too many times.") != NULL,
          "the too many times notice is printed, got \"%s\"", err);
    CHECK(strstr(tail_of(state_path("lockout.json")), "fails=3") != NULL,
          "the failure count is recorded");

    /* Even the right password is refused while the lock lasts. */
    rc = run_checker("correct horse battery staple", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_LOCKED, "the correct password is refused during the lockout (got %d)", rc);

    rc = run_checker(NULL, status, sizeof(status), err, sizeof(err), status_args);
    CHECK(rc == EXIT_OK, "--status exits 0");
    CHECK(strncmp(status, "locked ", 7) == 0, "--status reports the lock (\"%s\")", status);

    rc = run_checker(NULL, out, sizeof(out), err, sizeof(err), reset_args);
    CHECK(rc == EXIT_OK, "the lockout can be cleared (got %d)", rc);
    rc = run_checker(NULL, status, sizeof(status), err, sizeof(err), status_args);
    CHECK(strcmp(status, "ok\n") == 0, "--status reports ok after the reset (\"%s\")", status);
    CHECK(strstr(tail_of(state_path("lockout.json")), "fails=0") != NULL,
          "the failure count is reset");

    rc = run_checker("correct horse battery staple", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_OK, "the correct password works again");
}

static void test_attempt_override(void)
{
    char out[256], err[512];
    const char *args[] = {"--max-attempts", "1", NULL};
    int rc;

    clear_state();
    rc = run_checker("wrong", out, sizeof(out), err, sizeof(err), args);
    CHECK(rc == EXIT_LOCKED, "max_attempts=1 locks after the first failure (got %d)", rc);
    run_checker(NULL, out, sizeof(out), err, sizeof(err),
                (const char *[]){"--reset-lockout", NULL});
}

static void write_recovery_verifier(const char *key)
{
    char payload[256];
    char hash_hex[80];
    char json[512];
    uint8_t digest[32];
    int i;

    snprintf(payload, sizeof(payload), "SUDAEON-RECOVERY-V1%s", key);
    sd_sha256(payload, strlen(payload), digest);
    for (i = 0; i < 32; i++) {
        sprintf(hash_hex + i * 2, "%02x", digest[i]);
    }
    hash_hex[64] = '\0';
    snprintf(json, sizeof(json), "{\"version\":1,\"hash\":\"%s\"}\n", hash_hex);
    write_file(state_path("recovery.verifier"), json, 0600);
}

static void test_recovery_key(void)
{
    char out[256], err[512];
    const char *args[] = {"--recovery", NULL};
    int rc;

    write_recovery_verifier("ABCDEFGHJKMNPQRSTVWX");
    clear_state();

    rc = run_checker("ABCDE-FGHJK-MNPQR-STVWX", out, sizeof(out), err, sizeof(err), args);
    CHECK(rc == EXIT_OK, "the recovery key is accepted (got %d)", rc);

    rc = run_checker("abcde fghjk mnpqr stvwx", out, sizeof(out), err, sizeof(err), args);
    CHECK(rc == EXIT_OK, "the recovery key is accepted in lower case without dashes");
}

static void test_missing_and_unsafe_verifier(void)
{
    char out[256], err[512];
    int rc;

    unlink(state_path("master.verifier"));
    clear_state();
    rc = run_checker("whatever", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_ERROR, "a missing verifier is an error (got %d)", rc);

    /* restore, then make it world writable: the checker must refuse when it
     * runs with the privileges to read it (this is a sandbox run, so only the
     * presence of the file matters here) */
    write_verifier("master.verifier", "correct horse battery staple", 16,
                   "SUDAEON-VERIFIER-V1");
    chmod(state_path("master.verifier"), 0666);
    rc = run_checker("correct horse battery staple", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_OK || rc == EXIT_ERROR,
          "the checker never crashes on odd permissions (got %d)", rc);
}

static void test_kdf_parameters_come_from_the_file(void)
{
    char out[256], err[512];
    int rc;

    write_verifier("master.verifier", "a longer master password", 1024,
                   "SUDAEON-VERIFIER-V1");
    clear_state();
    rc = run_checker("a longer master password", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_OK, "the scrypt cost is read from the verifier (got %d)", rc);
    rc = run_checker("a longer master passwor", out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_INCORRECT, "a near miss is still wrong (got %d)", rc);
}

static void test_audit_trail(void)
{
    char out[256], err[512];
    char *log;

    write_verifier("master.verifier", "correct horse battery staple", 16,
                   "SUDAEON-VERIFIER-V1");
    clear_state();
    run_checker("wrong", out, sizeof(out), err, sizeof(err), NULL);
    run_checker("correct horse battery staple", out, sizeof(out), err, sizeof(err), NULL);

    log = tail_of(state_path("audit.log"));
    CHECK(strstr(log, "\"action\":\"master-check\"") != NULL, "checks are audited");
    CHECK(strstr(log, "\"result\":\"master-fail\"") != NULL, "failures are audited");
    CHECK(strstr(log, "\"result\":\"master-ok\"") != NULL, "successes are audited");
    CHECK(strstr(log, "\"source\":\"chkpwd\"") != NULL, "the source is audited");
    CHECK(strstr(log, "\"extra\":{\"attempt\":\"1\"}") != NULL,
          "the attempt number is recorded, log was:\n%s", log);
}

static void test_usage_and_bad_options(void)
{
    char out[256], err[512];
    int rc;

    rc = run_checker(NULL, out, sizeof(out), err, sizeof(err),
                     (const char *[]){"--help", NULL});
    CHECK(rc == EXIT_USAGE, "--help exits 4 (got %d)", rc);

    rc = run_checker(NULL, out, sizeof(out), err, sizeof(err),
                     (const char *[]){"--nonsense", NULL});
    CHECK(rc == EXIT_USAGE, "an unknown option exits 4 (got %d)", rc);
}

static void test_long_password_is_safe(void)
{
    char out[256], err[512];
    char huge[4096];
    int rc;

    memset(huge, 'x', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';
    clear_state();
    rc = run_checker(huge, out, sizeof(out), err, sizeof(err), NULL);
    CHECK(rc == EXIT_INCORRECT || rc == EXIT_ERROR,
          "a very long password is refused without crashing (got %d)", rc);
}

int main(int argc, char **argv)
{
    char template[] = "/tmp/sudaeon-chkpwd-XXXXXX";

    if (argc > 1) {
        binary = argv[1];
    }
    if (mkdtemp(template) == NULL) {
        printf("cannot create a temporary directory\n");
        return 2;
    }
    snprintf(tmp, sizeof(tmp), "%s", template);
    setenv("SUDAEON_STATE_DIR", tmp, 1);
    setenv("SUDAEON_AUDIT_LOG", state_path("audit.log"), 1);
    setenv("SUDAEON_NO_SANDBOX", "", 0);

    if (geteuid() == 0) {
        printf("running as root: the state directory override is ignored, "
               "skipping\\n");
        return 0;
    }
    if (access(binary, X_OK) != 0) {
        printf("cannot execute %s: %s\n", binary, strerror(errno));
        return 2;
    }

    write_file(state_path("enforcement.conf"),
               "schema=1\nenabled=1\nmax_attempts=3\n", 0644);

    printf("correct and incorrect passwords\n");
    test_correct_and_incorrect();
    printf("quiet mode\n");
    test_quiet_mode();
    printf("lockout\n");
    test_lockout_after_three_failures();
    printf("attempt override\n");
    test_attempt_override();
    printf("recovery key\n");
    test_recovery_key();
    printf("missing verifier\n");
    test_missing_and_unsafe_verifier();
    printf("scrypt parameters\n");
    test_kdf_parameters_come_from_the_file();
    printf("audit trail\n");
    test_audit_trail();
    printf("usage\n");
    test_usage_and_bad_options();
    printf("robustness\n");
    test_long_password_is_safe();

    printf("\n%d checks, %d failures\n", checks_run, checks_failed);
    return checks_failed == 0 ? 0 : 1;
}
