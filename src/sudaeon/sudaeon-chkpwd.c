/*
 * sudaeon-chkpwd - the one and only master password checker.
 *
 * History
 * -------
 * Based on Debian's pam_unix/support.c (Herve Pion, 1996-2004), which in turn
 * comes from the shadow suite.  Rewritten for Sudaeon: the password is read
 * from standard input (never from a command line argument, so it can never be
 * seen in `ps`), verified against /var/lib/sudaeon/master.verifier, rate
 * limited and audited.
 *
 * Exit codes
 * ----------
 *   0  the password is correct
 *   1  the password is incorrect
 *   2  the check could not be performed (missing verifier, wrong permissions...)
 *   3  too many incorrect attempts, the account is locked out for a while
 *   4  usage error
 *
 * Options
 * -------
 *   --quiet            print nothing (used by the PAM module and by Sudaeon)
 *   --status           print "ok" or "locked <seconds>" and exit 0
 *   --recovery         check a recovery key instead of the master password
 *   --tty              read the secret from the controlling terminal
 *   --max-attempts N   override the configured attempt limit
 *   --reset-lockout    clear the failure counter (root only)
 *   --source NAME      audit source tag (default "chkpwd")
 *   --help             usage
 *
 * The binary is installed mode 4755 (setuid root): only root can read the
 * verifier and write the audit log.  Root is dropped while the key is
 * derived, so a bug in the KDF cannot be turned into a privilege escalation.
 */

#define _GNU_SOURCE
#include "cutil.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EXIT_OK 0
#define EXIT_INCORRECT 1
#define EXIT_ERROR 2
#define EXIT_LOCKED 3
#define EXIT_USAGE 4

#define MAX_SECRET 512

#define MESSAGE_INCORRECT "The Password Entered was Incorrect"
#define MESSAGE_TOO_MANY "The Password was incorrect too many times."
#define MESSAGE_LOCKED "Too many incorrect attempts. Please wait %u seconds and try again."

static void usage(void)
{
    fprintf(stderr,
            "Usage: sudaeon-chkpwd [--quiet] [--status] [--recovery] [--tty]\n"
            "                     [--max-attempts N] [--reset-lockout] [--source NAME]\n"
            "\n"
            "Reads the master password from standard input and checks it against\n"
            "the Sudaeon verifier.  Exit codes: 0 correct, 1 incorrect,\n"
            "2 error, 3 locked out, 4 usage.\n");
}

/* Refuse to use a verifier that anybody but root could have written. */
static int verifier_is_trustworthy(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        return 0;
    }
    if (!S_ISREG(st.st_mode)) {
        return 0;
    }
    if (st.st_uid != 0) {
        return 0;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH | S_ISUID)) != 0) {
        return 0;
    }
    return 1;
}

/*
 * In sandbox mode (unprivileged caller and SUDAEON_STATE_DIR set, which cutil
 * honours only for non-root non-setuid processes) the verifier lives in a
 * temporary directory owned by the caller, so the root ownership check is
 * skipped.  This cannot be reached by an installed, setuid binary.
 */
static int sandbox_mode(void)
{
    const char *state = getenv("SUDAEON_STATE_DIR");
    return state != NULL && state[0] != '\0' &&
           geteuid() == getuid() && geteuid() != 0;
}

static char *state_file(const char *name)
{
    static char buffer[512];
    const char *dir = sandbox_mode() ? getenv("SUDAEON_STATE_DIR") : "/var/lib/sudaeon";
    snprintf(buffer, sizeof(buffer), "%s/%s", dir, name);
    return buffer;
}

static uint32_t configured_max_attempts(uint32_t fallback)
{
    struct sd_config cfg;
    char err[128];
    if (sd_config_load(&cfg, err, sizeof(err)) == SD_OK && cfg.max_attempts > 0) {
        return cfg.max_attempts;
    }
    return fallback;
}

static void report(const char *message, int quiet)
{
    if (!quiet && message != NULL) {
        fprintf(stderr, "%s\n", message);
    }
}


int main(int argc, char **argv)
{
    char secret[MAX_SECRET];
    char detail[256];
    char source[64];
    int quiet = 0;
    int status_only = 0;
    int recovery = 0;
    int use_tty = 0;
    int reset = 0;
    int max_attempts = -1;
    int read_from = 0;
    int dropped_privileges = 0;
    int c;
    int rc;
    uint32_t locked_for = 0;
    uint32_t fails = 0;

    snprintf(source, sizeof(source), "chkpwd");

    for (c = 1; c < argc; c++) {
        if (strcmp(argv[c], "--quiet") == 0) {
            quiet = 1;
        } else if (strcmp(argv[c], "--status") == 0) {
            status_only = 1;
        } else if (strcmp(argv[c], "--recovery") == 0) {
            recovery = 1;
        } else if (strcmp(argv[c], "--tty") == 0) {
            use_tty = 1;
        } else if (strcmp(argv[c], "--reset-lockout") == 0) {
            reset = 1;
        } else if (strcmp(argv[c], "--max-attempts") == 0 && c + 1 < argc) {
            max_attempts = atoi(argv[++c]);
        } else if (strcmp(argv[c], "--source") == 0 && c + 1 < argc) {
            snprintf(source, sizeof(source), "%s", argv[++c]);
        } else if (strcmp(argv[c], "--help") == 0 || strcmp(argv[c], "-h") == 0) {
            usage();
            return EXIT_USAGE;
        } else {
            fprintf(stderr, "sudaeon-chkpwd: unknown option %s\n", argv[c]);
            usage();
            return EXIT_USAGE;
        }
    }

    if (!sandbox_mode() && geteuid() != 0) {
        /*
         * Installed but not setuid root: the verifier cannot be read, and
         * pretending otherwise would silently disable enforcement.
         */
        sd_audit("chkpwd", "error", source,
                 "the password checker is not installed setuid root");
        report("Sudaeon is not correctly installed: sudaeon-chkpwd must be setuid root.",
               quiet);
        return EXIT_ERROR;
    }

    if (reset) {
        if (geteuid() != 0 && !sandbox_mode()) {
            report("Only root may reset the lockout.", quiet);
            return EXIT_ERROR;
        }
        sd_lockout_clear();
        sd_audit("chkpwd", "change", source, "lockout counter cleared");
        return EXIT_OK;
    }

    if (status_only) {
        sd_lockout_status(&fails, &locked_for);
        if (locked_for > 0) {
            printf("locked %u\n", (unsigned)locked_for);
        } else {
            printf("ok\n");
        }
        return EXIT_OK;
    }

    if (sd_lockout_locked(&locked_for)) {
        sd_audit("chkpwd", "deny", source, "locked out");
        report("The master password is locked after too many incorrect attempts.", quiet);
        return EXIT_LOCKED;
    }

    if (!verifier_is_trustworthy(state_file(recovery ? "recovery.verifier"
                                                     : "master.verifier")) &&
        !sandbox_mode()) {
        sd_audit("chkpwd", "error", source,
                 "the verifier file is missing or has unsafe permissions");
        report("Sudaeon cannot verify the master password: the verifier file is "
               "missing or unsafe.", quiet);
        return EXIT_ERROR;
    }

    if (use_tty) {
        read_from = open("/dev/tty", O_RDWR | O_CLOEXEC);
        if (read_from < 0) {
            report("There is no terminal to ask on.", quiet);
            return EXIT_ERROR;
        }
        if (!quiet) {
            fprintf(stderr, "[Sudaeon]: Please Enter the Master Password: ");
            fflush(stderr);
        }
    }

    memset(secret, 0, sizeof(secret));
    if (sd_read_secret(use_tty ? read_from : 0, secret, sizeof(secret)) < 0) {
        if (read_from > 0) {
            close(read_from);
        }
        sd_audit("chkpwd", "error", source, "the password could not be read");
        report("The password could not be read.", quiet);
        return EXIT_ERROR;
    }
    if (read_from > 0) {
        close(read_from);
    }

    /*
     * Installed as a setuid helper we drop root while the key is derived, so a
     * bug in the KDF cannot be turned into a privilege escalation.  A plain
     * unprivileged run (tests, or a user calling the checker directly) has no
     * privileges to drop.
     */
    dropped_privileges = (geteuid() == 0 && getuid() != 0);
    if (dropped_privileges && seteuid(getuid()) != 0) {
        sd_audit("chkpwd", "error", source, "could not drop privileges");
        report("Sudaeon could not drop privileges.", quiet);
        return EXIT_ERROR;
    }

    if (recovery) {
        rc = sd_recovery_verify(secret, detail, sizeof(detail));
    } else {
        rc = sd_master_verify(secret, detail, sizeof(detail));
    }
    memset(secret, 0, sizeof(secret));

    if (dropped_privileges && seteuid(0) != 0) {
        /* Without root the counter and the audit log cannot be updated. */
        report("Sudaeon cannot record the result of the check.", quiet);
        return EXIT_ERROR;
    }

    if (rc == SD_OK) {
        sd_lockout_clear();
        sd_audit(recovery ? "recovery-check" : "master-check", "master-ok", source, NULL);
        if (!quiet) {
            printf("ok\n");
        }
        return EXIT_OK;
    }

    if (rc == 1) {
        int locked_now = 0;
        uint32_t seconds = 0;
        uint32_t limit = max_attempts > 0 ? (uint32_t)max_attempts
                                          : configured_max_attempts(3);
        int total = sd_lockout_fail(limit, &locked_now, &seconds);
        char extra[64];
        snprintf(extra, sizeof(extra), "%d", total);
        sd_audit_set_extra("attempt", extra);
        sd_audit(recovery ? "recovery-check" : "master-check", "master-fail", source,
                 locked_now ? "locked out after too many incorrect attempts"
                            : "incorrect password");
        sd_audit_set_extra("", "");
        report(MESSAGE_INCORRECT, quiet);
        if (locked_now) {
            char message[160];
            snprintf(message, sizeof(message), MESSAGE_TOO_MANY);
            report(message, quiet);
            sd_audit("chkpwd", "deny", source, "lockout started");
            return EXIT_LOCKED;
        }
        return EXIT_INCORRECT;
    }

    sd_audit("chkpwd", "error", source, detail[0] ? detail : "verification failed");
    report(detail[0] ? detail : "Sudaeon cannot verify the master password.", quiet);
    return EXIT_ERROR;
}
