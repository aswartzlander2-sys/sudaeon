/* Fake PAM implementation for the Sudaeon test-suite. */
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

pam_handle_t *stub_pam_new(const char *service, const char *user,
                           int (*conv)(int, const struct pam_message **,
                                       struct pam_response **, void *),
                           void *appdata)
{
    pam_handle_t *pamh = calloc(1, sizeof(*pamh));
    if (!pamh)
        return NULL;
    pamh->service = service ? strdup(service) : NULL;
    pamh->user = user ? strdup(user) : NULL;
    pamh->conv.conv = conv;
    pamh->conv.appdata_ptr = appdata;
    return pamh;
}

void stub_pam_free(pam_handle_t *pamh)
{
    if (!pamh)
        return;
    free(pamh->service);
    free(pamh->user);
    free(pamh);
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
    if (!pamh || !item)
        return PAM_SYSTEM_ERR;
    switch (item_type) {
    case PAM_SERVICE: *item = pamh->service; break;
    case PAM_USER: *item = pamh->user; break;
    case PAM_CONV: *item = &pamh->conv; break;
    case PAM_TTY: *item = "pts/0"; break;
    default: *item = NULL; break;
    }
    return PAM_SUCCESS;
}

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
    if (!pamh)
        return PAM_SYSTEM_ERR;
    if (item_type == PAM_USER) {
        free(pamh->user);
        pamh->user = item ? strdup((const char *)item) : NULL;
        return PAM_SUCCESS;
    }
    if (item_type == PAM_SERVICE) {
        free(pamh->service);
        pamh->service = item ? strdup((const char *)item) : NULL;
        return PAM_SUCCESS;
    }
    return PAM_SUCCESS;
}

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    (void)prompt;
    if (!pamh || !user)
        return PAM_SYSTEM_ERR;
    if (!pamh->user)
        return PAM_USER_UNKNOWN;
    *user = pamh->user;
    return PAM_SUCCESS;
}

const char *pam_strerror(pam_handle_t *pamh, int errnum)
{
    (void)pamh;
    return errnum == PAM_SUCCESS ? "Success" : "Error";
}

int pam_vprompt(pam_handle_t *pamh, int style, char **response, const char *fmt, va_list args)
{
    char text[1024];
    struct pam_message message;
    const struct pam_message *message_ptr = &message;
    struct pam_response *reply = NULL;
    int rc;

    if (!pamh || !pamh->conv.conv)
        return PAM_CONV_ERR;
    vsnprintf(text, sizeof(text), fmt, args);
    message.msg_style = style;
    message.msg = text;
    rc = pamh->conv.conv(1, &message_ptr, &reply, pamh->conv.appdata_ptr);
    if (rc != PAM_SUCCESS)
        return rc;
    if (style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON) {
        if (response) {
            *response = (reply && reply[0].resp) ? strdup(reply[0].resp) : NULL;
        }
    } else if (response) {
        *response = NULL;
    }
    if (reply) {
        if (reply[0].resp)
            free(reply[0].resp);
        free(reply);
    }
    return PAM_SUCCESS;
}

int pam_prompt(pam_handle_t *pamh, int style, char **response, const char *fmt, ...)
{
    va_list args;
    int rc;
    va_start(args, fmt);
    rc = pam_vprompt(pamh, style, response, fmt, args);
    va_end(args);
    return rc;
}

int pam_info(pam_handle_t *pamh, const char *fmt, ...)
{
    va_list args;
    int rc;
    va_start(args, fmt);
    rc = pam_vprompt(pamh, PAM_TEXT_INFO, NULL, fmt, args);
    va_end(args);
    return rc;
}

int pam_error(pam_handle_t *pamh, const char *fmt, ...)
{
    va_list args;
    int rc;
    va_start(args, fmt);
    rc = pam_vprompt(pamh, PAM_ERROR_MSG, NULL, fmt, args);
    va_end(args);
    return rc;
}

void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    va_list args;
    (void)pamh;
    (void)priority;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fputc('\n', stderr);
    va_end(args);
}
