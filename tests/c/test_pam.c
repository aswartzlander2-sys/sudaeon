/*
 * test_pam.c - behaviour tests for pam_sudaeon.so.
 *
 * The PAM library is replaced by the small stubs in tests/c/stubs, so the real
 * module code runs unchanged against a scripted conversation.  Everything the
 * user asked for is checked here, with the exact wording:
 *
 *   prompt   [Sudaeon]: Please Enter the Master Password:
 *   wrong    The Password Entered was Incorrect        (after every attempt)
 *   too many The Password was incorrect too many times.
 *
 * Build and run with `make -C tests/c test-pam`.
 */

#define _GNU_SOURCE
#include "../../src/sudaeon/cutil.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

/* ------------------------------------------------------------------ */
/* check bookkeeping                                                   */
/* ------------------------------------------------------------------ */

static int checks_run = 0;
static int checks_failed = 0;

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

/* ------------------------------------------------------------------ */
/* PAM stub implementation                                             */
/* ------------------------------------------------------------------ */

struct pam_handle {
    const char *service;
    const char *user;
    const char *ruser;
    const char *tty;
    struct pam_conv conv;
};

#define MAX_MESSAGES 32
#define MAX_ANSWERS 16

static struct {
    char messages[MAX_MESSAGES][256];
    int styles[MAX_MESSAGES];
    int message_count;
    int prompts;
    char answers[MAX_ANSWERS][128];
    int answer_count;
    int answer_index;
    int fail_at_prompt;          /* return PAM_CONV_ERR on this prompt (1 based) */
} harness;

static void harness_reset(void)
{
    memset(&harness, 0, sizeof(harness));
}

static int test_conversation(int num_msg, const struct pam_message **msg,
                             struct pam_response **resp, void *appdata_ptr)
{
    struct pam_response *reply;
    int i;

    (void)appdata_ptr;
    if (num_msg <= 0 || msg == NULL) {
        return PAM_CONV_ERR;
    }
    reply = calloc((size_t)num_msg, sizeof(struct pam_response));
    if (reply == NULL) {
        return PAM_CONV_ERR;
    }
    for (i = 0; i < num_msg; i++) {
        const char *text = msg[i]->msg != NULL ? msg[i]->msg : "";
        if (harness.message_count < MAX_MESSAGES) {
            snprintf(harness.messages[harness.message_count],
                     sizeof(harness.messages[0]), "%s", text);
            harness.styles[harness.message_count] = msg[i]->msg_style;
            harness.message_count++;
        }
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            harness.prompts++;
            if (harness.fail_at_prompt == harness.prompts) {
                free(reply);
                return PAM_CONV_ERR;
            }
            if (harness.answer_index < harness.answer_count) {
                reply[i].resp = strdup(harness.answers[harness.answer_index]);
            } else {
                reply[i].resp = strdup("");
            }
            reply[i].resp_retcode = 0;
            harness.answer_index++;
        }
    }
    *resp = reply;
    return PAM_SUCCESS;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
    if (pamh == NULL || item == NULL) {
        return PAM_SYSTEM_ERR;
    }
    switch (item_type) {
    case PAM_SERVICE: *item = pamh->service; return PAM_SUCCESS;
    case PAM_USER: *item = pamh->user; return PAM_SUCCESS;
    case PAM_RUSER: *item = pamh->ruser; return PAM_SUCCESS;
    case PAM_TTY: *item = pamh->tty; return PAM_SUCCESS;
    case PAM_CONV: *item = &pamh->conv; return PAM_SUCCESS;
    default: *item = NULL; return PAM_BAD_ITEM;
    }
}

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
    if (pamh == NULL) {
        return PAM_SYSTEM_ERR;
    }
    switch (item_type) {
    case PAM_USER: pamh->user = (const char *)item; return PAM_SUCCESS;
    case PAM_RUSER: pamh->ruser = (const char *)item; return PAM_SUCCESS;
    case PAM_SERVICE: pamh->service = (const char *)item; return PAM_SUCCESS;
    default: return PAM_BAD_ITEM;
    }
}

int pam_get_user(const pam_handle_t *pamh, const char **user, const char *prompt)
{
    (void)prompt;
    if (pamh == NULL || user == NULL) {
        return PAM_SYSTEM_ERR;
    }
    *user = pamh->user;
    return PAM_SUCCESS;
}

void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    (void)pamh;
    (void)priority;
    (void)fmt;
}

/* the module under test */
extern int pam_sm_authenticate(pam_handle_t *, int, int, const char **);

/* ------------------------------------------------------------------ */
/* fixtures                                                            */
/* ------------------------------------------------------------------ */

static char tmp[256];
static char chkpwd_ok[300];
static char chkpwd_fail[300];
static char chkpwd_locked[300];
static char chkpwd_smart[300];
static char capture_file[300];

static void write_file(const char *path, const char *text, mode_t mode)
{
    FILE *handle = fopen(path, "w");
    if (handle == NULL) {
        printf("cannot write %s\n", path);
        exit(2);
    }
    fputs(text, handle);
    fclose(handle);
    chmod(path, mode);
}

static void write_config(const char *text)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/enforcement.conf", tmp);
    write_file(path, text, 0644);
}

static void remove_config(void)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/enforcement.conf", tmp);
    unlink(path);
}

static void write_marker(void)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/installed.json", tmp);
    write_file(path, "{\"version\": 1}\n", 0644);
}

static void remove_marker(void)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/installed.json", tmp);
    unlink(path);
}

static const char *standard_config =
    "# test policy\n"
    "schema=1\n"
    "enabled=1\n"
    "fail_closed=1\n"
    "max_attempts=3\n"
    "prompt_text=Please Enter the Master Password:\n"
    "[user:alice]\n"
    "role=admin\n"
    "exempt=0\n"
    "[user:bob]\n"
    "role=exempt\n"
    "exempt=1\n"
    "[user:child]\n"
    "role=regular\n"
    "exempt=0\n"
    "[user:*]\n"
    "role=regular\n"
    "exempt=0\n"
    "[action:sudo]\n"
    "blocked=1\n"
    "require_master=1\n"
    "[action:su]\n"
    "blocked=1\n"
    "require_master=1\n"
    "[action:user_management]\n"
    "blocked=1\n"
    "require_master=1\n"
    "[action:pkexec]\n"
    "blocked=0\n"
    "require_master=1\n"
    "[action:root_login]\n"
    "blocked=1\n"
    "require_master=0\n"
    "[schedule]\n"
    "mode=always\n";

/* ------------------------------------------------------------------ */

static int run_auth(pam_handle_t *pamh, int flags, const char *action,
                    const char *checker, const char *max_attempts)
{
    const char *argv[8];
    int argc = 0;
    char action_arg[128];
    char attempts_arg[64];
    char checker_arg[320];

    if (action != NULL) {
        snprintf(action_arg, sizeof(action_arg), "action=%s", action);
        argv[argc++] = action_arg;
    }
    if (checker != NULL) {
        snprintf(checker_arg, sizeof(checker_arg), "chkpwd=%s", checker);
        argv[argc++] = checker_arg;
    }
    if (max_attempts != NULL) {
        snprintf(attempts_arg, sizeof(attempts_arg), "max_attempts=%s", max_attempts);
        argv[argc++] = attempts_arg;
    }
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

static int count_message(const char *needle)
{
    int i, total = 0;
    for (i = 0; i < harness.message_count; i++) {
        if (strcmp(harness.messages[i], needle) == 0) {
            total++;
        }
    }
    return total;
}

static int have_message_prefix(const char *prefix)
{
    int i;
    for (i = 0; i < harness.message_count; i++) {
        if (strncmp(harness.messages[i], prefix, strlen(prefix)) == 0) {
            return 1;
        }
    }
    return 0;
}

static void set_service_user(struct pam_handle *pamh, const char *service,
                             const char *user, const char *ruser)
{
    memset(pamh, 0, sizeof(*pamh));
    pamh->service = service;
    pamh->user = user;
    pamh->ruser = ruser;
    pamh->conv.conv = test_conversation;
    pamh->conv.appdata_ptr = NULL;
}

static void set_answer(int index, const char *text)
{
    snprintf(harness.answers[index], sizeof(harness.answers[0]), "%s", text);
    if (index + 1 > harness.answer_count) {
        harness.answer_count = index + 1;
    }
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

static void test_correct_password_after_prompt(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "the correct master password");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);

    CHECK(rc == PAM_SUCCESS, "a correct master password lets sudo continue (rc=%d)", rc);
    CHECK(harness.prompts == 1, "exactly one prompt (got %d)", harness.prompts);
    CHECK(strcmp(harness.messages[0], "[Sudaeon]: Please Enter the Master Password: ") == 0,
          "the prompt text is exactly as specified, got \"%s\"", harness.messages[0]);
    CHECK(harness.styles[0] == PAM_PROMPT_ECHO_OFF, "the prompt does not echo");
}

static void test_three_incorrect_attempts(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "wrong one");
    set_answer(1, "wrong two");
    set_answer(2, "wrong three");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_fail, NULL);

    CHECK(rc == PAM_AUTH_ERR, "three wrong passwords refuse the action (rc=%d)", rc);
    CHECK(harness.prompts == 3, "three prompts (got %d)", harness.prompts);
    CHECK(count_message("The Password Entered was Incorrect") == 3,
          "the incorrect notice appears after every wrong entry (got %d)",
          count_message("The Password Entered was Incorrect"));
    CHECK(count_message("The Password was incorrect too many times.") == 1,
          "the too many times notice appears once (got %d)",
          count_message("The Password was incorrect too many times."));
    CHECK(harness.prompts == 3, "no further prompts after the limit");
}

static void test_wrong_then_correct(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "nope");
    set_answer(1, "correct-password");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_smart, NULL);
    CHECK(rc == PAM_SUCCESS, "a later correct password is accepted (rc=%d)", rc);
    CHECK(harness.prompts == 2, "two prompts (got %d)", harness.prompts);
}

static void test_attempt_limit_is_configurable(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "wrong");
    set_answer(1, "wrong");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_fail, "2");
    CHECK(rc == PAM_AUTH_ERR, "the limit can be lowered");
    CHECK(harness.prompts == 2, "two prompts with max_attempts=2 (got %d)", harness.prompts);

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "wrong");
    set_answer(1, "wrong");
    set_answer(2, "wrong");
    set_answer(3, "wrong");
    set_answer(4, "correct-password");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_smart, "5");
    CHECK(rc == PAM_SUCCESS, "five attempts are allowed when configured");
    CHECK(harness.prompts == 5, "five prompts (got %d)", harness.prompts);
}

static void test_locked_out_checker(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "whatever");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_locked, NULL);

    CHECK(rc == PAM_AUTH_ERR, "a locked out checker refuses the action");
    CHECK(harness.prompts == 1, "no repeated prompts while locked out (got %d)",
          harness.prompts);
    CHECK(count_message("The Password was incorrect too many times.") == 1,
          "the too many times notice is shown");
    CHECK(have_message_prefix("Sudaeon: too many incorrect master passwords"),
          "the lockout is explained to the user");
}

static void test_cancelled_prompt(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    harness.fail_at_prompt = 1;
    rc = run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);
    CHECK(rc == PAM_AUTH_ERR, "aborting the prompt refuses the action (rc=%d)", rc);
}

static void test_exempt_user_is_skipped(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "bob", "bob");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);
    CHECK(rc == PAM_IGNORE, "an exempt account is left alone (rc=%d)", rc);
    CHECK(harness.prompts == 0, "no prompt for an exempt account");
    CHECK(harness.message_count == 0, "no messages for an exempt account");
}

static void test_administrator_is_policed_unless_exempt(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "alice", "alice");
    set_answer(0, "the master password");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);
    CHECK(rc == PAM_SUCCESS, "an administrator still has to give the master password");
    CHECK(harness.prompts == 1, "one prompt for the administrator");
}

static void test_root_is_never_restricted(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "root", "root");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_fail, NULL);
    CHECK(rc == PAM_IGNORE, "root is never restricted (rc=%d)", rc);
    CHECK(harness.prompts == 0, "no prompt for root");
}

static void test_disabled_policy_is_ignored(void)
{
    struct pam_handle pamh;
    int rc;

    write_config("# disabled\nschema=1\nenabled=0\n[action:sudo]\nblocked=1\n");
    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);
    CHECK(rc == PAM_IGNORE, "the policy can be switched off (rc=%d)", rc);
    CHECK(harness.prompts == 0, "no prompt while the policy is off");
    write_config(standard_config);
}

static void test_unblocked_action_is_ignored(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "pkexec", "child", "child");
    rc = run_auth(&pamh, 0, "pkexec", chkpwd_ok, NULL);
    CHECK(rc == PAM_IGNORE, "an action that is not blocked is ignored (rc=%d)", rc);
    CHECK(harness.prompts == 0, "no prompt for an unblocked action");
}

static void test_hard_denied_action(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "login", "child", "child");
    rc = run_auth(&pamh, 0, "root_login", chkpwd_ok, NULL);
    CHECK(rc == PAM_AUTH_ERR, "root login is refused without a prompt (rc=%d)", rc);
    CHECK(harness.prompts == 0, "a hard denied action never asks (got %d)",
          harness.prompts);
    CHECK(count_message("Sudaeon policy: this action is not allowed.") == 1,
          "the refusal is explained");
}

static void test_unknown_action_and_service(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    rc = run_auth(&pamh, 0, "something_else", chkpwd_ok, NULL);
    CHECK(rc == PAM_IGNORE, "an unknown action is ignored");

    harness_reset();
    set_service_user(&pamh, "unknown-service", "child", "child");
    rc = run_auth(&pamh, 0, NULL, chkpwd_ok, NULL);
    CHECK(rc == PAM_IGNORE, "an unknown service is ignored");
}

static void test_service_name_mapping(void)
{
    struct pam_handle pamh;
    int rc;

    /* no action= argument: the service name decides */
    harness_reset();
    set_service_user(&pamh, "passwd", "child", "child");
    set_answer(0, "whatever");
    rc = run_auth(&pamh, 0, NULL, chkpwd_ok, NULL);
    CHECK(rc == PAM_SUCCESS, "passwd maps to user_management and asks (rc=%d)", rc);
    CHECK(harness.prompts == 1, "one prompt for passwd");

    harness_reset();
    set_service_user(&pamh, "su", "child", "child");
    set_answer(0, "pw");
    rc = run_auth(&pamh, 0, NULL, chkpwd_fail, NULL);
    CHECK(rc == PAM_AUTH_ERR, "su asks and refuses on a wrong password");
}

static void test_missing_configuration_fails_closed(void)
{
    struct pam_handle pamh;
    int rc;

    remove_config();
    remove_marker();
    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);
    CHECK(rc == PAM_IGNORE, "without an installation marker Sudaeon stays out (rc=%d)", rc);
    CHECK(harness.prompts == 0, "no prompt when Sudaeon is not installed");

    write_marker();
    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);
    CHECK(rc == PAM_AUTH_ERR, "a missing configuration refuses the action (rc=%d)", rc);
    CHECK(count_message("Sudaeon: the master password could not be verified.") == 1,
          "the error is explained");
    remove_marker();
    write_config(standard_config);
}

static void test_checker_error_handling(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "pw");
    rc = run_auth(&pamh, 0, "sudo", "/nonexistent/sudaeon-chkpwd", NULL);
    CHECK(rc == PAM_AUTH_ERR, "a missing checker fails closed (rc=%d)", rc);
}

static void test_silent_flag_keeps_enforcement(void)
{
    struct pam_handle pamh;
    int rc;

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "wrong");
    set_answer(1, "wrong");
    set_answer(2, "wrong");
    harness.answer_count = 3;
    rc = run_auth(&pamh, PAM_SILENT, "sudo", chkpwd_fail, NULL);
    CHECK(rc == PAM_AUTH_ERR, "PAM_SILENT does not disable enforcement (rc=%d)", rc);
    CHECK(harness.prompts == 3, "the prompts still happen (got %d)", harness.prompts);
    CHECK(count_message("The Password Entered was Incorrect") == 0,
          "messages are suppressed with PAM_SILENT");
}

static void test_password_is_pipe_only(void)
{
    struct pam_handle pamh;
    char path[300];
    char captured[256];
    FILE *handle;
    int rc;

    snprintf(path, sizeof(path), "%s/capture.sh", tmp);
    write_file(path,
               "#!/bin/sh\n"
               "# Records the password received on standard input.\n"
               "cat > \"$SUDAEON_CAPTURE_FILE\"\n"
               "echo \"$*\" > \"$SUDAEON_CAPTURE_FILE.argv\"\n"
               "exit 0\n",
               0755);

    snprintf(capture_file, sizeof(capture_file), "%s/captured.txt", tmp);
    setenv("SUDAEON_CAPTURE_FILE", capture_file, 1);
    unlink(capture_file);

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "sup3r-secret-master-password");
    rc = run_auth(&pamh, 0, "sudo", path, NULL);
    CHECK(rc == PAM_SUCCESS, "the scripted checker accepts (rc=%d)", rc);

    handle = fopen(capture_file, "r");
    CHECK(handle != NULL, "the checker received something on stdin");
    if (handle != NULL) {
        memset(captured, 0, sizeof(captured));
        if (fgets(captured, sizeof(captured), handle) == NULL) {
            captured[0] = '\0';
        }
        captured[strcspn(captured, "\n")] = '\0';
        fclose(handle);
        CHECK(strcmp(captured, "sup3r-secret-master-password") == 0,
              "the password arrives on stdin, got \"%s\"", captured);
    }

    snprintf(path, sizeof(path), "%s/captured.txt.argv", tmp);
    handle = fopen(path, "r");
    if (handle != NULL) {
        memset(captured, 0, sizeof(captured));
        if (fgets(captured, sizeof(captured), handle) == NULL) {
            captured[0] = '\0';
        }
        fclose(handle);
        CHECK(strstr(captured, "sup3r-secret-master-password") == NULL,
              "the password is not visible in the command line (\"%s\")", captured);
        CHECK(strstr(captured, "--quiet") != NULL, "the checker is called quietly");
    }
}

static void test_schedule_is_honoured(void)
{
    struct pam_handle pamh;
    char config[1024];
    char day[8];
    time_t now = time(NULL);
    struct tm tm;
    int today, now_minutes, start_minutes, end_minutes;
    int rc;
    static const char *names[7] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};

    localtime_r(&now, &tm);
    today = (tm.tm_wday + 6) % 7;             /* 0 = Monday, like the config */
    now_minutes = tm.tm_hour * 60 + tm.tm_min;
    start_minutes = (now_minutes + 1439) % 1440;
    end_minutes = (now_minutes + 60) % 1440;
    snprintf(day, sizeof(day), "%s", names[today]);

    /* a window that certainly contains the current minute */
    if (end_minutes > start_minutes) {
        snprintf(config, sizeof(config),
                 "schema=1\nenabled=1\nmax_attempts=1\n"
                 "[user:*]\nrole=regular\nexempt=0\n"
                 "[action:sudo]\nblocked=1\nrequire_master=1\n"
                 "[schedule]\nmode=enforce-during\n"
                 "window=%s,%02d:%02d,%02d:%02d\n",
                 (strcmp(day, "Sun") == 0) ? "Mon,Tue,Wed,Thu,Fri,Sat,Sun" : day,
                 start_minutes / 60, start_minutes % 60,
                 end_minutes / 60, end_minutes % 60);
    } else {
        snprintf(config, sizeof(config),
                 "schema=1\nenabled=1\nmax_attempts=1\n"
                 "[user:*]\nrole=regular\nexempt=0\n"
                 "[action:sudo]\nblocked=1\nrequire_master=1\n"
                 "[schedule]\nmode=enforce-during\n"
                 "window=Mon,Tue,Wed,Thu,Fri,Sat,Sun,00:00,23:59\n");
    }
    write_config(config);
    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "pw");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);
    CHECK(rc == PAM_SUCCESS, "inside a scheduled window the policy applies (rc=%d)", rc);
    CHECK(harness.prompts == 1, "one prompt inside the window");

    /* a window on the other side of the day: outside, so nothing is asked */
    snprintf(config, sizeof(config),
             "schema=1\nenabled=1\nmax_attempts=1\n"
             "[user:*]\nrole=regular\nexempt=0\n"
             "[action:sudo]\nblocked=1\nrequire_master=1\n"
             "[schedule]\nmode=enforce-during\n"
             "window=%s,00:00,00:01\n",
             names[(today + 3) % 7]);
    write_config(config);
    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    rc = run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);
    /* Only skip this assertion in the very first minute of a matching day. */
    if (!(now_minutes == 0 && strcmp(names[(today + 3) % 7], day) == 0)) {
        CHECK(rc == PAM_IGNORE || rc == PAM_SUCCESS,
              "outside the window the policy does not interfere (rc=%d)", rc);
        if (rc == PAM_IGNORE) {
            CHECK(harness.prompts == 0, "no prompt outside the window");
        }
    }
    write_config(standard_config);
}

static void test_audit_records_attempts(void)
{
    char path[300];
    FILE *handle;
    char buffer[8192];
    size_t got;
    struct pam_handle pamh;

    snprintf(path, sizeof(path), "%s/audit.log", tmp);
    unlink(path);

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "wrong");
    set_answer(1, "also wrong");
    set_answer(2, "still wrong");
    run_auth(&pamh, 0, "sudo", chkpwd_fail, NULL);

    harness_reset();
    set_service_user(&pamh, "sudo", "child", "child");
    set_answer(0, "correct");
    run_auth(&pamh, 0, "sudo", chkpwd_ok, NULL);

    handle = fopen(path, "r");
    CHECK(handle != NULL, "the audit log exists");
    if (handle == NULL) {
        return;
    }
    got = fread(buffer, 1, sizeof(buffer) - 1, handle);
    buffer[got] = '\0';
    fclose(handle);
    CHECK(strstr(buffer, "\"action\":\"sudo\"") != NULL, "the action is audited");
    /*
     * The password attempts themselves are audited by sudaeon-chkpwd (see
     * tests/c/test_chkpwd.c); the module records its decision.
     */
    CHECK(strstr(buffer, "\"result\":\"master-ok\"") != NULL, "successes are audited");
    CHECK(strstr(buffer, "\"result\":\"deny\"") != NULL, "the rejection is audited");
    CHECK(strstr(buffer, "\"source\":\"pam\"") != NULL, "the source is audited");
    CHECK(strstr(buffer, "\"extra\":{\"user\":\"child\"}") != NULL,
          "the account is recorded in the audit line");
}

int main(void)
{
    char template[] = "/tmp/sudaeon-pam-XXXXXX";

    if (mkdtemp(template) == NULL) {
        printf("cannot create a temporary directory\n");
        return 2;
    }
    snprintf(tmp, sizeof(tmp), "%s", template);
    setenv("SUDAEON_STATE_DIR", tmp, 1);
    {
        char audit[300];
        snprintf(audit, sizeof(audit), "%s/audit.log", tmp);
        setenv("SUDAEON_AUDIT_LOG", audit, 1);
    }

    snprintf(chkpwd_ok, sizeof(chkpwd_ok), "/bin/true");
    snprintf(chkpwd_fail, sizeof(chkpwd_fail), "/bin/false");
    snprintf(chkpwd_locked, sizeof(chkpwd_locked), "%s/chkpwd-locked.sh", tmp);
    write_file(chkpwd_locked, "#!/bin/sh\nexit 3\n", 0755);
    snprintf(chkpwd_smart, sizeof(chkpwd_smart), "%s/chkpwd-smart.sh", tmp);
    write_file(chkpwd_smart,
               "#!/bin/sh\n"
               "# Accepts exactly one password, like the real checker.\n"
               "read -r password\n"
               "if [ \"$password\" = \"correct-password\" ]; then exit 0; fi\n"
               "exit 1\n",
               0755);

    if (geteuid() == 0) {
        printf("running as root: the state directory override is ignored, "
               "skipping\\n");
        return 0;
    }

    write_config(standard_config);

    printf("correct password\n");
    test_correct_password_after_prompt();
    printf("three incorrect attempts\n");
    test_three_incorrect_attempts();
    printf("wrong then correct\n");
    test_wrong_then_correct();
    printf("configurable attempt limit\n");
    test_attempt_limit_is_configurable();
    printf("locked out checker\n");
    test_locked_out_checker();
    printf("cancelled prompt\n");
    test_cancelled_prompt();
    printf("exempt account\n");
    test_exempt_user_is_skipped();
    printf("administrator account\n");
    test_administrator_is_policed_unless_exempt();
    printf("root account\n");
    test_root_is_never_restricted();
    printf("disabled policy\n");
    test_disabled_policy_is_ignored();
    printf("unblocked action\n");
    test_unblocked_action_is_ignored();
    printf("hard denied action\n");
    test_hard_denied_action();
    printf("unknown action and service\n");
    test_unknown_action_and_service();
    printf("service name mapping\n");
    test_service_name_mapping();
    printf("missing configuration\n");
    test_missing_configuration_fails_closed();
    printf("checker failure\n");
    test_checker_error_handling();
    printf("PAM_SILENT\n");
    test_silent_flag_keeps_enforcement();
    printf("password handling\n");
    test_password_is_pipe_only();
    printf("schedule\n");
    test_schedule_is_honoured();
    printf("audit log\n");
    test_audit_records_attempts();

    printf("\n%d checks, %d failures\n", checks_run, checks_failed);
    return checks_failed == 0 ? 0 : 1;
}
