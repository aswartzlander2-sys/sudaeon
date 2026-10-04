/* Minimal stand-in for <security/pam_ext.h>: the logging helper. */
#ifndef SUDAEON_STUB_PAM_EXT_H
#define SUDAEON_STUB_PAM_EXT_H

#include <stdarg.h>
#include <syslog.h>
#include "pam_appl.h"

void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...);

#endif /* SUDAEON_STUB_PAM_EXT_H */
