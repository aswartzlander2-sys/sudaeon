/*
 * cutil.h - shared C helpers for Sudaeon.
 *
 * Used by the setuid password checker (sudaeon-chkpwd) and by the PAM module
 * (pam_sudaeon.so).  The Python side reads and writes the same files:
 *
 *   /var/lib/sudaeon/master.verifier    JSON, 0600 root, scrypt digest
 *   /var/lib/sudaeon/recovery.verifier  JSON, 0600 root, SHA-256 of the key
 *   /var/lib/sudaeon/enforcement.conf   flat policy rendering (see below)
 *   /var/lib/sudaeon/lockout.json       key=value rate limiting state
 *   /var/log/sudaeon/audit.log          JSON lines, one event per line
 *
 * enforcement.conf format (all values are flat, one per line; '# starts a
 * comment'; unknown keys are ignored so newer Python can feed older C):
 *
 *   schema=1                     file format version
 *   enabled=0|1                  master switch
 *   fail_closed=0|1              allow or refuse when the file is unreadable
 *   max_attempts=3               terminal prompt attempts before giving up
 *   prompt_text=Please Enter the Master Password:
 *   prompt_timeout=120           seconds a prompt may take
 *   default_role=regular|admin|exempt
 *   default_require=0|1          ask for the master password by default
 *   default_timeout=120          default prompt timeout
 *   [user:alice]
 *   role=admin
 *   exempt=0
 *   [user:*]                     fallback for accounts not listed
 *   role=regular
 *   exempt=0
 *   [action:sudo]                action names are stable identifiers
 *   blocked=1                    is the action restricted for non-exempt users
 *   require_master=1             may it be unlocked with the master password
 *   [schedule]
 *   mode=always|enforce-during|enforce-outside
 *   window=Mon,Tue,Wed,Thu,Fri,Sat,Sun,21:00,07:00
 */

#ifndef SUDAEON_CUTIL_H
#define SUDAEON_CUTIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define SD_OK 0
#define SD_ERR_USAGE 4
#define SD_ERR_IO 6
#define SD_ERR_MEMORY 7
#define SD_ERR_FORMAT 8
#define SD_ERR_CRYPTO 9

#define SD_PATH_MAX 256
#define SD_KEY_LEN 32
#define SD_SALT_MAX 64
#define SD_HASH_MAX 64
/*: scrypt cost limit: 2^20 keeps a hostile configuration from eating all RAM. */
#define SD_MAX_N (1u << 20)
#define SD_MAX_USERS 64
#define SD_MAX_ACTIONS 32
#define SD_MAX_WINDOWS 16
#define SD_WINDOW_DAYS 16

/* ------------------------------------------------------------------ */
/* hashing and key derivation                                          */
/* ------------------------------------------------------------------ */

void sd_sha256(const void *data, size_t len, uint8_t out[32]);
void sd_sha256_hex(const void *data, size_t len, char out[65]);
void sd_hmac_sha256(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[32]);
int  sd_pbkdf2_hmac_sha256(const uint8_t *pass, size_t passlen,
                           const uint8_t *salt, size_t saltlen,
                           uint32_t rounds, uint8_t *out, size_t outlen);
int  sd_scrypt(const uint8_t *pass, size_t passlen,
               const uint8_t *salt, size_t saltlen,
               uint32_t n, uint32_t r, uint32_t p,
               uint8_t *out, size_t outlen);
void sd_salsa20_8(uint8_t block[64]);
int  sd_constant_time_eq(const void *a, const void *b, size_t len);

/* The two inner stages of scrypt, exported so the test-suite can check them
 * against RFC 7914 sections 9 and 10.  `scratch` holds 2*r*64 bytes. */
void sd_blockmix(const uint32_t *b, uint32_t *y, uint32_t *scratch, uint32_t r);
int  sd_romix(uint32_t *block, uint32_t n, uint32_t r);

/* ------------------------------------------------------------------ */
/* master password verification                                        */
/* ------------------------------------------------------------------ */

/* Returns SD_OK when the password matches, 1 when it does not, 2 on error. */
int sd_master_verify(const char *password, char *detail, size_t detail_len);

/* Returns SD_OK when the recovery key matches, 1 when it does not, 2 on error. */
int sd_recovery_verify(const char *key, char *detail, size_t detail_len);

/* ------------------------------------------------------------------ */
/* audit log                                                           */
/* ------------------------------------------------------------------ */

void sd_audit(const char *action, const char *result, const char *source,
              const char *detail);

void sd_audit_set_extra(const char *key, const char *value);

/* ------------------------------------------------------------------ */
/* rate limiting                                                       */
/* ------------------------------------------------------------------ */

/* Fills *remaining with the number of seconds the lock lasts.
 * Returns 1 when a lock is in force, 0 otherwise. */
int  sd_lockout_locked(uint32_t *remaining);

/* Records a failed attempt.  Sets *locked_now to 1 when this failure started
 * a lock and stores the lock length in *seconds. */
int  sd_lockout_fail(uint32_t max_attempts, int *locked_now, uint32_t *seconds);

/* Clears the failure counter (a correct password, or an administrator reset). */
void sd_lockout_clear(void);

/* Prunes the state without changing the counters: used before reporting. */
int  sd_lockout_status(uint32_t *fails, uint32_t *remaining);

/* ------------------------------------------------------------------ */
/* policy rendering (enforcement.conf)                                 */
/* ------------------------------------------------------------------ */

#define SD_ROLE_REGULAR 0
#define SD_ROLE_ADMIN 1
#define SD_ROLE_EXEMPT 2

#define SD_SCHEDULE_ALWAYS 0
#define SD_SCHEDULE_DURING 1
#define SD_SCHEDULE_OUTSIDE 2

#define SD_ACTION_NAME_MAX 64
#define SD_USER_NAME_MAX 64

struct sd_window {
    char days[SD_WINDOW_DAYS];   /* 7 bytes, bit 0 = Monday ... bit 6 = Sunday */
    int start_minute;            /* minutes since midnight */
    int end_minute;
};

struct sd_user_entry {
    char name[SD_USER_NAME_MAX];
    int role;
    int exempt;
};

struct sd_action_entry {
    char name[SD_ACTION_NAME_MAX];
    int blocked;
    int require_master;
};

struct sd_config {
    int schema;
    int enabled;
    int fail_closed;
    uint32_t max_attempts;
    char prompt_text[128];
    uint32_t prompt_timeout;
    int default_role;
    int default_exempt;
    int default_require;
    char verifier_path[SD_PATH_MAX];
    char chkpwd_path[SD_PATH_MAX];
    char audit_path[SD_PATH_MAX];
    int audit_enabled;

    struct sd_user_entry users[SD_MAX_USERS];
    size_t user_count;
    struct sd_action_entry actions[SD_MAX_ACTIONS];
    size_t action_count;

    int schedule_mode;
    struct sd_window windows[SD_MAX_WINDOWS];
    size_t window_count;

    int loaded;                  /* 1 when the file was read successfully */
    int marker_present;          /* 1 when /var/lib/sudaeon/installed.json exists */
};

/* Reads /var/lib/sudaeon/enforcement.conf.  Returns SD_OK on success. */
int  sd_config_load(struct sd_config *cfg, char *err, size_t errlen);

/* Look up the action entry (never NULL: unknown actions get the defaults). */
const struct sd_action_entry *sd_config_action(const struct sd_config *cfg,
                                               const char *name);

/* Is this account exempt from the policy? */
int  sd_config_user_exempt(const struct sd_config *cfg, const char *user);

/* Role of the account, SD_ROLE_* */
int  sd_config_user_role(const struct sd_config *cfg, const char *user);

/* Is the policy in force at this moment?
 * `now_iso` is an ISO-8601 timestamp, `timezone` may be NULL ("local time"). */
int  sd_schedule_active(const struct sd_config *cfg, const char *now_iso,
                        const char *timezone);

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

/* Reads one line (without the newline) from fd.  Returns the length, or -1. */
int  sd_read_line(int fd, char *out, size_t outlen);

/* Reads a secret without echoing it (termios).  Returns the length, or -1.
 * When fd is not a terminal the line is read normally, so the checker can be
 * fed from a pipe as well. */
int  sd_read_secret(int fd, char *out, size_t outlen);

int  sd_file_exists(const char *path);
int  sd_write_file(const char *path, const char *text, mode_t mode);
int  sd_read_file(const char *path, char *out, size_t outlen);

/* Timestamp in ISO-8601 UTC, into buf (needs 32 bytes). */
void sd_now_iso(char *buf, size_t buflen);

const char *sd_username(void);
int  sd_is_root(void);

#endif /* SUDAEON_CUTIL_H */
