/*
 * Minimal stand-in for <security/pam_modules.h> so the Sudaeon PAM module can
 * be compiled and tested without libpam development headers.  The constants
 * and the function signatures match Linux-PAM.
 */
#ifndef SUDAEON_STUB_PAM_MODULES_H
#define SUDAEON_STUB_PAM_MODULES_H

#include "pam_appl.h"

#define PAM_SUCCESS 0
#define PAM_OPEN_ERR 1
#define PAM_SYMBOL_ERR 2
#define PAM_SERVICE_ERR 3
#define PAM_SYSTEM_ERR 4
#define PAM_BUF_ERR 5
#define PAM_PERM_DENIED 6
#define PAM_AUTH_ERR 7
#define PAM_CRED_INSUFFICIENT 8
#define PAM_AUTHINFO_UNAVAIL 9
#define PAM_USER_UNKNOWN 10
#define PAM_MAXTRIES 11
#define PAM_NEW_AUTHTOK_REQD 12
#define PAM_ACCT_EXPIRED 13
#define PAM_SESSION_ERR 14
#define PAM_CRED_UNAVAIL 15
#define PAM_CRED_EXPIRED 16
#define PAM_CRED_ERR 17
#define PAM_NO_MODULE_DATA 18
#define PAM_CONV_ERR 19
#define PAM_AUTHTOK_ERR 20
#define PAM_AUTHTOK_RECOVERY_ERR 21
#define PAM_AUTHTOK_LOCK_BUSY 22
#define PAM_AUTHTOK_DISABLE_AGING 23
#define PAM_TRY_AGAIN 24
#define PAM_IGNORE 25
#define PAM_ABORT 26
#define PAM_AUTHTOK_EXPIRED 27
#define PAM_MODULE_UNKNOWN 28
#define PAM_BAD_ITEM 29
#define PAM_CONV_AGAIN 30
#define PAM_INCOMPLETE 31

#define PAM_SILENT 0x8000
#define PAM_DISALLOW_NULL_AUTHTOK 0x0001
#define PAM_ESTABLISH_CRED 0x0002
#define PAM_DELETE_CRED 0x0004
#define PAM_REINITIALIZE_CRED 0x0008
#define PAM_REFRESH_CRED 0x0010

#define PAM_SERVICE 1
#define PAM_USER 2
#define PAM_TTY 3
#define PAM_RHOST 4
#define PAM_CONV 5
#define PAM_AUTHTOK 6
#define PAM_OLDAUTHTOK 7
#define PAM_RUSER 8
#define PAM_USER_PROMPT 9

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item);
int pam_set_item(pam_handle_t *pamh, int item_type, const void *item);
int pam_get_user(const pam_handle_t *pamh, const char **user, const char *prompt);

#endif /* SUDAEON_STUB_PAM_MODULES_H */
