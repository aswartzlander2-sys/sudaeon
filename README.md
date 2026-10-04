# sudaeon

Parental controls for **Ubuntu 24.04.5 LTS**: one master password, a policy that
covers power, session, terminal and application actions, and a master switch
that turns the whole thing on and off.

Sudaeon is deliberately built from stock Ubuntu/GNOME pieces - GTK 4,
libadwaita, PAM, polkit, logind, dconf and systemd - so it looks and behaves
like the rest of the system.

## Install from the ZIP download

Download the source as a ZIP (`Code` → `Download ZIP` on GitHub) and unpack it.
The tree is a full Debian source package: no git checkout, no extra tooling and
no debhelper are needed.

    sudo apt install build-essential dpkg-dev libpam0g-dev python3
    ./tools/build-deb.sh                     # writes dist/sudaeon_1.0.0_amd64.deb
    sudo apt install ./dist/sudaeon_*.deb    # or ./tools/build-deb.sh --install
    sudaeon setup                            # choose the master password

`apt install` unpacks the program and then runs `sudaeon configure` for you
(`debian/postinst`): it writes `/var/lib/sudaeon`, renders the policy, installs
the PAM lines, the polkit rule, the sudoers drop-in and the dconf lockdown, and
enables the sentinel service. **Nothing is enforced until a master password
exists** - the policy is written with the master switch off, and the account
that ran the installation becomes the first Administrator.

If the automatic step was skipped (unattended installs, `dpkg -i`), run it by
hand:

    sudo sudaeon configure

Either way, finish with:

    sudo sudaeon doctor     # optional: check PAM, polkit, logind, the services
    sudaeon setup           # first run: master password + confirmation

Removing it again:

    sudo apt remove sudaeon     # takes the enforcement hooks out, keeps the policy
    sudo apt purge sudaeon      # also removes /var/lib/sudaeon (password + vault)

Uninstalling from the dashboard (`sudaeon uninstall`) removes everything,
including the state, and is the recommended way if you are not sure.

## Building by hand

Everything the package does can also be done in place:

    make            # build sudaeon-chkpwd and pam_sudaeon.so into build/
    make test       # all C and Python suites
    sudo make install                    # /usr/local by default
    sudo PREFIX=/usr make install        # what the package uses
    sudo make uninstall

`make install` needs the PAM headers (`libpam0g-dev`). On a machine without
them the C sources can still be compiled and tested against the stub headers in
`tests/c/stubs`:

    make SUDAEON_STUB_PAM=1              # compiles against the stubs
    make -C tests/c test SUDAEON_STUB_PAM=1

A stub build must never be installed on a real computer: the PAM module has to
talk to the distribution's real PAM.

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

## What the package installs

    /usr/bin/sudaeon                                   the dashboard and the CLI
    /usr/lib/sudaeon/sudaeon/                          the Python program
    /usr/lib/sudaeon/sudaeon-chkpwd                    setuid master password checker (4755)
    /usr/lib/sudaeon/sudaeon-helper                    the root-only helper
    /usr/lib/<multiarch>/security/pam_sudaeon.so       the PAM module
    /usr/share/applications/com.sudaeon.Sudaeon.desktop
    /etc/xdg/autostart/com.sudaeon.Agent.desktop       the per-session agent
    /usr/lib/systemd/system/sudaeon-sentinel.service
    /usr/lib/tmpfiles.d/sudaeon.conf
    /etc/logrotate.d/sudaeon
    /usr/share/polkit-1/actions/com.sudaeon.policy
    /etc/polkit-1/rules.d/00-sudaeon.rules             written by 'sudaeon configure'
    /etc/sudoers.d/sudaeon                             written by 'sudaeon configure'
    /etc/sudaeon/README
    /var/lib/sudaeon/                                  policy, vault, verifiers
    /var/log/sudaeon/audit.log

`debian/control` declares `Rules-Requires-Root: no`: the package is built
without fakeroot (`dpkg-deb --root-owner-group` makes the archive entries root
owned), and its maintainer scripts are plain POSIX shell. `debian/rules` is a
small Makefile - there is no debhelper dependency, which is what makes the ZIP
download self-contained.

The icon is generated from `data/icons/sudaeon.svg` (or `.png`). Drop your own
logo there and rebuild to change it; `data/icons/sudaeon.svg` is the only file
the packaging reads.

## Layout

    Makefile                build, test, install, deb, uninstall
    debian/                 the Debian package (control, rules, maintainer scripts)
    tools/build-deb.sh      ZIP download -> .deb
    tools/gen-assets.py     renders the static system files into a package root
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
    data/icons/             the icon source
    docs/                   design notes and the policy reference

## Tests

The C tests need nothing but a C compiler and glibc:

    make -C tests/c test-util     # SHA-256, HMAC, PBKDF2, scrypt, config, audit
    make -C tests/c test-chkpwd   # the setuid checker, end to end
    make -C tests/c test-pam      # the PAM module with a stub conversation
    make -C tests/c test          # all three

The Python tests need Python 3.11:

    python3 -m unittest tests.test_crypto    # ChaCha20-Poly1305, scrypt vectors
    python3 -m unittest tests.test_config    # the policy schema and the renderer
    python3 -m unittest tests.test_package   # the Debian packaging and the CLI glue

`make test` runs all of them. `tests/fixtures/enforcement.conf` is the contract
between the Python renderer and the C parser: the Python test compares the
rendered file byte for byte, and the C test parses the same fixture.

## Security model

* The master password is never passed in `argv`; it travels on stdin.
* Verification always happens in the setuid helper (`sudaeon-chkpwd`), never in
  the GUI or the CLI process.
* `/var/lib/sudaeon/master.verifier` stores
  `sha256("SUDAEON-VERIFIER-V1" || scrypt(password, salt))`; the vault is
  ChaCha20-Poly1305 under the scrypt key. Both are documented in `docs/`.
* The PAM module contains no cryptography: it reads the pre-rendered policy and
  shells out to the checker, so a bug in PAM cannot leak the password.
* Root (uid 0) is always unrestricted, and `root_login` cannot be unlocked with
  the master password.
* Everyone who is not an Administrator, not exempt and inside the schedule is
  subject to the policy.

## Status

The enforcement engine, the C helpers, the PAM module, the checker, the
sentinel, the dashboard, the Debian packaging and the test suites are in place
and green. Still to come: the application icon (`data/icons/`), the end-user
documentation and screenshots in `docs/`, and a `recovery_key_display` helper in
the CLI.
