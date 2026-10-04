/*
 * Minimal stand-in for <security/pam_appl.h>.  Linux-PAM and the Sudaeon test
 * harness both use this exact layout, so a module compiled against this header
 * also compiles against the real one.
 */
#ifndef SUDAEON_STUB_PAM_APPL_H
#define SUDAEON_STUB_PAM_APPL_H

#define PAM_PROMPT_ECHO_OFF 1
#define PAM_PROMPT_ECHO_ON 2
#define PAM_ERROR_MSG 3
#define PAM_TEXT_INFO 4

struct pam_message {
    int msg_style;
    const char *msg;
};

struct pam_response {
    char *resp;
    int resp_retcode;
};

struct pam_conv {
    int (*conv)(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr);
    void *appdata_ptr;
};

typedef struct pam_handle pam_handle_t;

#endif /* SUDAEON_STUB_PAM_APPL_H */
