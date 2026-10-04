# sudaeon

Parental controls for **Ubuntu 24.04.5 LTS**: one master password, a policy that
covers power, session, terminal and application actions, and a master switch
that turns the whole thing on and off.

Sudaeon is deliberately built from stock Ubuntu/GNOME pieces - GTK 4,
libadwaita, PAM, polkit, logind, dconf and systemd - so it looks and behaves
like the rest of the system.

## What it does

* **Power and session actions** - rebooting, shutting down, halting, suspending
  and hibernating can be allowed, blocked, or blocked *unless* the master
  password is entered. The same applies to log out, screen lock, user switching
  and printing (through the GNOME lockdown keys).
* **Terminal sudo** - `pam_sudaeon.so` makes `sudo`, `su`, `pkexec`, `passwd`
  and friends ask for the master password inside the terminal:
  `[Sudaeon]: Please Enter the Master Password:`. Three wrong entries end the
  command; the wait then doubles (30 s, 60 s, 120 s ... capped at 30 minutes).
* **Permission dialogs** - when the desktop asks for authority (restart from
  the system menu, unlock a blocked application), a native GTK dialog titled
  *Sudaeon Permission Manager* asks for the master password and, when it is
  wrong, *Sudaeon Permission Manager - Access Denied* offers **Retry**.
* **Power button** - Disable / Require Master Password / Allow.
* **User manager** - every OS account is listed and can be an *Administrator*
  (dashboard access, system wide effect), *Exempt from Policy* (the policy does
  not apply) or a *Regular User* (policy applies, no dashboard).
* **Application control** - a picked application gets a desktop-entry override
  and a `PATH` shim, so launching it asks for the master password first. It is
  a speed bump, not a sandbox, and the dashboard says so.
* **Audit log** - every decision and every master password attempt is written as
  JSON lines to `/var/log/sudaeon/audit.log`.

## Layout

    src/sudaeon/            the Python program
      cutil.[ch]            C helpers: SHA-256, HMAC, PBKDF2, scrypt, the
                            policy parser, the rate limiter, the audit writer
      sudaeon-chkpwd.c      the setuid master password checker
      pam_sudaeon.c         the PAM module
      crypto.py             verifier records, the encrypted vault, recovery keys
      config.py             the policy schema and the renderer for
                            /var/lib/sudaeon/enforcement.conf
      engine.py             the single place that decides whether an action is
                            allowed
      sentinel/             the root daemon: logind inhibitors, the power
                            button, and the per-session permission dialogs
      gui/                  GTK 4 / libadwaita windows (dashboard, setup,
                            permission dialogs)
    tests/                  Python unit tests and the C test suites
    docs/                   design notes and the policy reference

## Building and testing

The C tests need nothing but a C compiler and glibc:

    make -C tests/c test-util     # SHA-256, HMAC, PBKDF2, scrypt, config, audit
    make -C tests/c test-chkpwd   # the setuid checker, end to end
    make -C tests/c test-pam      # the PAM module with a stub conversation
    make -C tests/c test          # all three

The Python tests need Python 3.11 (the GUI itself additionally needs
`python3-gi gir1.2-gtk-4.0 gir1.2-adw-1`):

    python3 -m unittest tests.test_crypto
    python3 -m unittest tests.test_config

`tests/fixtures/enforcement.conf` is the contract between the Python renderer
and the C parser: the Python test compares the rendered file byte for byte, and
the C test parses the same fixture.

## Security model

* The master password is never passed in `argv`; it travels on stdin.
* Verification always happens in the setuid helper (`sudaeon-chkpwd`), never in
  the GUI or the CLI process.
* `/var/lib/sudaeon/master.verifier` stores
  `sha256("SUDAEON-VERIFIER-V1" || scrypt(password, salt))`; the vault is
  ChaCha20-Poly1305 under the scrypt key. Both are documented in
  `docs/`.
* The PAM module contains no cryptography: it reads the pre-rendered policy and
  shells out to the checker, so a bug in PAM cannot leak the password.
* Root (uid 0) is always unrestricted, and `root_login` cannot be unlocked with
  the master password.
* Everyone who is not an Administrator, not exempt and inside the schedule is
  subject to the policy.

## Status

The enforcement engine, the C helpers, the PAM module, the checker, the
sentinel, the dashboard and both test suites are in place and green. Still to
come in this branch: the system assets (`data/`), the top-level `Makefile` and
`install.sh`, Debian packaging, the remaining Python unit tests and the
end-user documentation.
