/*
 * pam_sudaeon.so - ask for the Sudaeon master password inside PAM.
 *
 * Installation
 * ------------
 * The module is added to the *auth* stack of a service, above the normal
 * password line, for example in /etc/pam.d/sudo:
 *
 *     auth  requisite  pam_sudaeon.so action=sudo
 *     @include common-auth
 *
 * With `action=sudo` a user who runs sudo sees
 *
 *     [Sudaeon]: Please Enter the Master Password:
 *
 * before sudo asks for the user's own password.  A wrong master password
 * prints `The Password Entered was Incorrect` and the prompt comes back; after
 * three failures the module prints
 * `The Password was incorrect too many times.` and the command is refused.
 *
 * Decisions are never taken in this module: the policy is rendered by Sudaeon
 * (Python) into /var/lib/sudaeon/enforcement.conf and the password is checked
 * by the setuid helper /usr/lib/sudaeon/sudaeon-chkpwd, so C and Python share
 * exactly one implementation of every rule.
 */

#define _GNU_SOURCE
#include "cutil.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#define PROMPT_PREFIX "[Sudaeon]: "
#define PROMPT_TEXT "Please Enter the Master Password: "
#define MESSAGE_INCORRECT "The Password Entered was Incorrect"
#define MESSAGE_TOO_MANY "The Password was incorrect too many times."
#define MESSAGE_BLOCKED "Sudaeon policy: this action is not allowed."
#define MESSAGE_LOCKED "Sudaeon: too many incorrect master passwords. " \
                       "Please wait before trying again."
#define MESSAGE_ERROR "Sudaeon: the master password could not be verified."
#define DEFAULT_CHKPWD "/usr/lib/sudaeon/sudaeon-chkpwd"

#define EXIT_INCORRECT 1
#define EXIT_ERROR 2
#define EXIT_LOCKED 3

struct module_args {
    const char *action;
    const char *source;
    const char *chkpwd;
    int debug;
    int quiet;
    int max_attempts;
};

/* ------------------------------------------------------------------ */
/* conversation helpers                                                */
/* ------------------------------------------------------------------ */

static int converse(pam_handle_t *pamh, int style, const char *text,
                    struct pam_response **response)
{
    const struct pam_conv *conv = NULL;
    struct pam_message message;
    const struct pam_message *messages[1];
    struct pam_response *reply = NULL;
    int rc;

    rc = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (rc != PAM_SUCCESS || conv == NULL || conv->conv == NULL) {
        return PAM_CONV_ERR;
    }
    message.msg_style = style;
    message.msg = (char *)text;
    messages[0] = &message;
    reply = NULL;
    rc = conv->conv(1, messages, &reply, conv->appdata_ptr);
    if (rc != PAM_SUCCESS) {
        if (reply != NULL) {
            free(reply);
        }
        return rc;
    }
    if (response != NULL) {
        *response = reply;
    } else if (reply != NULL) {
        if (reply[0].resp != NULL) {
            free(reply[0].resp);
        }
        free(reply);
    }
    return PAM_SUCCESS;
}

static void message(pam_handle_t *pamh, const struct module_args *args,
                    const char *text)
{
    if (args->quiet) {
        return;
    }
    converse(pamh, PAM_ERROR_MSG, text, NULL);
}

static char *ask_master_password(pam_handle_t *pamh, const struct module_args *args,
                                 const struct sd_config *cfg)
{
    struct pam_response *response = NULL;
    char prompt[256];
    int rc;

    {
        const char *text = cfg->prompt_text[0] != '\0' ? cfg->prompt_text : PROMPT_TEXT;
        size_t length = strlen(text);
        /*
         * A console prompt always ends in a space so that what the user types
         * does not run into the colon.
         */
        if (snprintf(prompt, sizeof(prompt), "%s%s%s", PROMPT_PREFIX, text,
                     (length > 0 && text[length - 1] == ' ') ? "" : " ")
            >= (int)sizeof(prompt)) {
            return NULL;
        }
    }
    rc = converse(pamh, PAM_PROMPT_ECHO_OFF, prompt, &response);
    if (rc != PAM_SUCCESS || response == NULL) {
        return NULL;
    }
    if (response[0].resp == NULL) {
        free(response);
        return NULL;
    }
    {
        char *password = strdup(response[0].resp);
        memset(response[0].resp, 0, strlen(response[0].resp));
        free(response[0].resp);
        free(response);
        return password;
    }
}

/* ------------------------------------------------------------------ */
/* running the setuid checker                                          */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t child_timed_out;

static void on_alarm(int signal_number)
{
    (void)signal_number;
    child_timed_out = 1;
}

/*
 * Runs sudaeon-chkpwd with the password on its standard input.  The password
 * is never placed on a command line, in the environment or in a temporary
 * file, so it cannot be read by another process.
 */
static int run_checker(const struct module_args *args, const char *password)
{
    int pipes[2];
    pid_t pid;
    int status = 0;
    size_t length;
    ssize_t ignored;
    int saved_errno;
    struct sigaction action, previous;

    if (pipe(pipes) != 0) {
        return EXIT_ERROR;
    }
    pid = fork();
    if (pid < 0) {
        close(pipes[0]);
        close(pipes[1]);
        return EXIT_ERROR;
    }
    if (pid == 0) {
        int null_fd;
        close(pipes[1]);
        if (dup2(pipes[0], STDIN_FILENO) < 0) {
            _exit(EXIT_ERROR);
        }
        close(pipes[0]);
        null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            if (null_fd > STDERR_FILENO) {
                close(null_fd);
            }
        }
        execl(args->chkpwd, args->chkpwd, "--quiet", "--source", args->source,
              (char *)NULL);
        _exit(EXIT_ERROR);
    }

    close(pipes[0]);
    /*
     * The checker may exit before reading (for example when the lockout file
     * says it is locked out), which would raise SIGPIPE here.
     */
    {
        void (*previous_pipe)(int) = signal(SIGPIPE, SIG_IGN);
        length = strlen(password);
        if (length > 0) {
            ignored = write(pipes[1], password, length);
            (void)ignored;
        }
        ignored = write(pipes[1], "\n", 1);
        (void)ignored;
        signal(SIGPIPE, previous_pipe);
    }
    close(pipes[1]);

    memset(&action, 0, sizeof(action));
    action.sa_handler = on_alarm;
    sigaction(SIGALRM, &action, &previous);
    child_timed_out = 0;
    alarm(30);
    if (waitpid(pid, &status, 0) < 0) {
        saved_errno = errno;
        alarm(0);
        sigaction(SIGALRM, &previous, NULL);
        errno = saved_errno;
        return EXIT_ERROR;
    }
    alarm(0);
    sigaction(SIGALRM, &previous, NULL);
    if (child_timed_out) {
        kill(pid, SIGKILL);
        return EXIT_ERROR;
    }
    if (!WIFEXITED(status)) {
        return EXIT_ERROR;
    }
    return WEXITSTATUS(status);
}

/* ------------------------------------------------------------------ */
/* policy helpers                                                      */
/* ------------------------------------------------------------------ */

static void parse_args(int argc, const char **argv, struct module_args *args)
{
    int i;

    memset(args, 0, sizeof(*args));
    args->source = "pam";
    args->max_attempts = -1;
    for (i = 0; i < argc; i++) {
        const char *item = argv[i];
        if (strncmp(item, "action=", 7) == 0) {
            args->action = item + 7;
        } else if (strncmp(item, "source=", 7) == 0) {
            args->source = item + 7;
        } else if (strncmp(item, "chkpwd=", 7) == 0) {
            args->chkpwd = item + 7;
        } else if (strncmp(item, "max_attempts=", 13) == 0) {
            args->max_attempts = atoi(item + 13);
        } else if (strcmp(item, "debug") == 0) {
            args->debug = 1;
        } else if (strcmp(item, "quiet") == 0) {
            args->quiet = 1;
        }
    }
}

/* Maps a PAM service name onto a Sudaeon action when no argument is given. */
static const char *action_for_service(const char *service)
{
    static const struct {
        const char *service;
        const char *action;
    } table[] = {
        {"sudo", "sudo"},
        {"sudo-i", "sudo"},
        {"su", "su"},
        {"su-l", "su"},
        {"pkexec", "pkexec"},
        {"polkit-1", "pkexec"},
        {"passwd", "user_management"},
        {"chpasswd", "user_management"},
        {"chfn", "user_management"},
        {"chsh", "user_management"},
        {"gpasswd", "user_management"},
        {"login", "root_login"},
        {"gdm-password", "root_login"},
        {"lightdm", "root_login"},
        {"sddm", "root_login"},
        {"sshd", "root_login"},
        {NULL, NULL},
    };
    int i;
    if (service == NULL) {
        return NULL;
    }
    for (i = 0; table[i].service != NULL; i++) {
        if (strcmp(table[i].service, service) == 0) {
            return table[i].action;
        }
    }
    return NULL;
}

static const char *subject_user(pam_handle_t *pamh, const char *action)
{
    const void *item = NULL;
    const char *user = NULL;
    const char *ruser = NULL;
    struct passwd *pw;

    pam_get_item(pamh, PAM_USER, &item);
    user = (const char *)item;
    item = NULL;
    pam_get_item(pamh, PAM_RUSER, &item);
    ruser = (const char *)item;

    if (user == NULL || user[0] == '\0') {
        return NULL;
    }
    pw = getpwnam(user);
    /* Someone logging in or switching to root is judged by who they are. */
    if (strcmp(action, "root_login") == 0 && pw != NULL && pw->pw_uid == 0 &&
        ruser != NULL && ruser[0] != '\0') {
        return ruser;
    }
    return user;
}

static int user_is_root(const char *user)
{
    struct passwd *pw = user != NULL ? getpwnam(user) : NULL;
    return pw != NULL && pw->pw_uid == 0;
}

/* ------------------------------------------------------------------ */
/* the PAM entry points                                                */
/* ------------------------------------------------------------------ */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    struct sd_config cfg;
    struct module_args args;
    const struct sd_action_entry *entry;
    const void *item = NULL;
    const char *service = NULL;
    const char *action;
    const char *subject;
    char error[256];
    int attempts;
    int i;
    parse_args(argc, argv, &args);
    if (flags & PAM_SILENT) {
        args.quiet = 1;
    }
    if (args.chkpwd == NULL) {
        const char *override = getenv("SUDAEON_CHKPWD");
        args.chkpwd = (override != NULL && override[0] != '\0') ? override
                                                                : DEFAULT_CHKPWD;
    }
    if (sd_config_load(&cfg, error, sizeof(error)) != SD_OK) {
        if (cfg.marker_present) {
            /*
             * Sudaeon is installed but its configuration cannot be read:
             * refuse rather than silently letting the action through.
             */
            sd_audit("pam", "error", args.source, error);
            pam_syslog(pamh, LOG_CRIT, "Sudaeon: %s", error);
            message(pamh, &args, MESSAGE_ERROR);
            return PAM_AUTH_ERR;
        }
        /* Not installed on this computer: stay out of the way. */
        return PAM_IGNORE;
    }
    if (!cfg.enabled) {
        return PAM_IGNORE;
    }

    pam_get_item(pamh, PAM_SERVICE, &item);
    service = (const char *)item;
    action = args.action != NULL ? args.action : action_for_service(service);
    if (action == NULL) {
        return PAM_IGNORE;
    }
    entry = sd_config_action(&cfg, action);
    if (entry == NULL || !entry->blocked) {
        return PAM_IGNORE;
    }

    subject = subject_user(pamh, action);
    if (subject == NULL) {
        sd_audit(action, "error", args.source, "no user name is available");
        pam_syslog(pamh, LOG_CRIT, "Sudaeon: no user name for action %s", action);
        return PAM_AUTH_ERR;
    }
    if (user_is_root(subject)) {
        return PAM_IGNORE;          /* root is never restricted */
    }
    if (sd_config_user_exempt(&cfg, subject)) {
        sd_audit(action, "allow", args.source, "the account is exempt from policy");
        return PAM_IGNORE;
    }
    if (!sd_schedule_active(&cfg, NULL, NULL)) {
        return PAM_IGNORE;
    }

    sd_audit_set_extra("user", subject);
    if (!entry->require_master) {
        sd_audit(action, "deny", args.source, "blocked by policy, no master password allowed");
        sd_audit_set_extra("", "");
        message(pamh, &args, MESSAGE_BLOCKED);
        return PAM_AUTH_ERR;
    }

    attempts = args.max_attempts > 0 ? args.max_attempts : (int)cfg.max_attempts;
    if (attempts < 1) {
        attempts = 1;
    }

    for (i = 0; i < attempts; i++) {
        char *password = ask_master_password(pamh, &args, &cfg);
        int rc;

        if (password == NULL) {
            /* The user could not be asked (or pressed Ctrl-C): refuse. */
            sd_audit(action, "deny", args.source, "the master password prompt was cancelled");
            sd_audit_set_extra("", "");
            message(pamh, &args, MESSAGE_ERROR);
            return PAM_AUTH_ERR;
        }
        rc = run_checker(&args, password);
        memset(password, 0, strlen(password));
        free(password);

        if (rc == 0) {
            sd_audit(action, "master-ok", args.source, "master password accepted");
            sd_audit_set_extra("", "");
            return PAM_SUCCESS;
        }
        if (rc == EXIT_LOCKED) {
            sd_audit(action, "deny", args.source, "the master password is locked out");
            sd_audit_set_extra("", "");
            message(pamh, &args, MESSAGE_INCORRECT);
            message(pamh, &args, MESSAGE_TOO_MANY);
            message(pamh, &args, MESSAGE_LOCKED);
            return PAM_AUTH_ERR;
        }
        if (rc == EXIT_INCORRECT) {
            /* The notice appears after *every* wrong entry, including the last. */
            message(pamh, &args, MESSAGE_INCORRECT);
            continue;
        }
        /* Any other exit code is an error: fail closed, unless told otherwise. */
        sd_audit(action, "error", args.source, "the master password checker failed");
        sd_audit_set_extra("", "");
        if (!cfg.fail_closed) {
            pam_syslog(pamh, LOG_WARNING, "Sudaeon: checker failed, failing open");
            return PAM_IGNORE;
        }
        message(pamh, &args, MESSAGE_ERROR);
        return PAM_AUTH_ERR;
    }

    sd_audit(action, "deny", args.source, "too many incorrect master passwords");
    sd_audit_set_extra("", "");
    message(pamh, &args, MESSAGE_TOO_MANY);
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
