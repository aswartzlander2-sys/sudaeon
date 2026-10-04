# Sudaeon - parental controls for Ubuntu 24.04 LTS
#
# The usual entry points:
#
#   make                 build the C helpers into build/
#   make test            run every test suite (C and Python)
#   make install         install on this computer (needs root)
#   make deb             build a Debian package (sudaeon_<version>_<arch>.deb)
#   make uninstall       remove an installation made by 'make install'
#   make icons           re-render the icon set from assets/sudaeon.svg
#   make clean           remove build/ and the packaging leftovers
#
# 'make install' understands DESTDIR and PREFIX, so it is also what
# debian/rules uses to fill the package:
#
#   make install DESTDIR=/tmp/root PREFIX=/usr

NAME      = sudaeon
VERSION  := $(shell python3 -c "import sys; sys.path.insert(0, 'src'); \
    from sudaeon.version import APP_VERSION; print(APP_VERSION)" 2>/dev/null || echo 1.0.0)

SRC       = src/sudaeon
BUILD     = build
TESTS     = tests/c

PREFIX   ?= /usr
DESTDIR  ?=
LIBDIR   ?= $(PREFIX)/lib
BINDIR   ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share
SYSCONFDIR ?= /etc
LOCALSTATEDIR ?= /var

# Where PAM looks for modules.  Debian and Ubuntu use the multiarch directory;
# the fallbacks keep this working on other layouts.
PAM_DIR  ?= $(or $(wildcard $(PREFIX)/lib/*-linux-gnu/security),\
                 $(wildcard $(PREFIX)/lib/security),\
                 /lib/security)

CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -Wno-unused-parameter
PYTHON   ?= /usr/bin/python3

# The PAM module needs the PAM development headers (libpam0g-dev).  The checker
# does not, so 'make' still produces something useful without them; the module
# is only built against the test stubs when SUDAEON_STUB_PAM=1 is set, which is
# what the CI and the sandbox use to exercise the packaging.
PAM_HEADERS := $(wildcard /usr/include/security/pam_appl.h)
ifeq ($(SUDAEON_STUB_PAM),1)
PAM_INC := -Itests/c/stubs
else
PAM_INC :=
endif

INSTALL_DIR  = $(DESTDIR)$(LIBDIR)/sudaeon
DEST_PYTHON  = $(INSTALL_DIR)/sudaeon
DEST_BIN     = $(DESTDIR)$(BINDIR)/$(NAME)
DEST_CHKPWD  = $(INSTALL_DIR)/sudaeon-chkpwd
DEST_MODULE  = $(INSTALL_DIR)/pam_sudaeon.so
DEST_PAM     = $(DESTDIR)$(PAM_DIR)/pam_sudaeon.so
DEST_DOC     = $(DESTDIR)$(SHAREDIR)/doc/$(NAME)

PY_PACKAGE = $(shell find $(SRC) -name '*.py' -not -path '*/__pycache__/*')

.PHONY: all test test-c test-python install install-program install-config \
        uninstall deb icons clean distclean help

all: $(BUILD)/sudaeon-chkpwd $(BUILD)/pam_sudaeon.so

# ---------------------------------------------------------------------------
# the compiled parts
# ---------------------------------------------------------------------------

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/sudaeon-chkpwd: $(SRC)/sudaeon-chkpwd.c $(SRC)/cutil.c $(SRC)/cutil.h | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRC) -o $@ $(SRC)/sudaeon-chkpwd.c $(SRC)/cutil.c

$(BUILD)/pam_sudaeon.so: $(SRC)/pam_sudaeon.c $(SRC)/cutil.c $(SRC)/cutil.h | $(BUILD)
ifeq ($(PAM_HEADERS)$(SUDAEON_STUB_PAM),)
	@echo "error: the PAM development headers are missing." >&2
	@echo "       install them with: sudo apt install libpam0g-dev" >&2
	@echo "       (or run 'make SUDAEON_STUB_PAM=1 ...' for a test build that" >&2
	@echo "        must never be installed on a real computer)" >&2
	@exit 1
endif
	$(CC) $(CFLAGS) -fPIC -shared $(PAM_INC) -o $@ $(SRC)/pam_sudaeon.c $(SRC)/cutil.c

# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

test: test-c test-python

test-c: all
	$(MAKE) -C $(TESTS) test

test-python:
	$(PYTHON) -m unittest discover -s tests -t . -v

# ---------------------------------------------------------------------------
# installation
# ---------------------------------------------------------------------------

install: all
	@test "$$(id -u)" = "0" -o -n "$(DESTDIR)" || \
		{ echo "make install needs root (or DESTDIR for a staged install)" >&2; exit 1; }
	$(MAKE) install-program
	$(MAKE) install-config
	@echo "Sudaeon $(VERSION) installed."
	@echo "Next: run 'sudaeon setup' (or open the Sudaeon entry in the menu) to"
	@echo "choose the master password; nothing is enforced until you do."

install-program:
	install -d -m 755 $(INSTALL_DIR)
	install -d -m 755 $(DEST_PYTHON)
	# the python package (the C sources stay in the source tree)
	for file in $(PY_PACKAGE); do \
		target=$(DEST_PYTHON)/$${file#$(SRC)/}; \
		install -d -m 755 "$$(dirname $$target)"; \
		install -m 644 "$$file" "$$target"; \
	done
	@# No byte-code is shipped: the interpreter compiles .pyc for the Python
	@# that is actually installed on the target machine.  Build-host .pyc files
	@# are stale there, and leaving them in the package is a lintian warning.
	-find $(DEST_PYTHON) -name '__pycache__' -type d -prune -exec rm -rf {} +

	# the launcher (/usr/bin/sudaeon) is written by gen-assets.py, together
	# with the privileged entry points that share its code
	install -d -m 755 $(DESTDIR)$(BINDIR)
	ln -sf $(BINDIR)/$(NAME) $(INSTALL_DIR)/sudaeon-helper
	ln -sf $(BINDIR)/$(NAME) $(INSTALL_DIR)/sudaeon-sentinel
	ln -sf $(BINDIR)/$(NAME) $(INSTALL_DIR)/sudaeon-polkit-guard

	# the setuid checker and the PAM module
	install -m 4755 $(BUILD)/sudaeon-chkpwd $(DEST_CHKPWD)
	install -m 644 $(BUILD)/pam_sudaeon.so $(DEST_MODULE)
	install -d -m 755 $(dir $(DEST_PAM))
	install -m 644 $(BUILD)/pam_sudaeon.so $(DEST_PAM)

install-config:
	$(PYTHON) tools/gen-assets.py --root $(DESTDIR) --quiet
	install -d -m 755 $(DEST_DOC)

# ---------------------------------------------------------------------------
# icons
# ---------------------------------------------------------------------------

# Developer helper: render the icon set into the system (or DESTDIR) location.
# Drop your own logo in assets/sudaeon.svg first; nothing else needs to change.
icons:
	$(PYTHON) -c "import os, sys; sys.path.insert(0, 'src'); \
from pathlib import Path; \
from sudaeon import brand; \
root = Path('$(DESTDIR)') if '$(DESTDIR)' else None; \
report = brand.build_icons(root); \
print(f\"rendered {len(report['rendered'])} icons from {report['source']}\" \
      if report['source'] else 'no logo found in assets/')"

# ---------------------------------------------------------------------------
# Debian package
# ---------------------------------------------------------------------------

deb: all
	tools/build-deb.sh

# ---------------------------------------------------------------------------
# removal / cleanup
# ---------------------------------------------------------------------------

uninstall:
	@test "$$(id -u)" = "0" -o -n "$(DESTDIR)" || \
		{ echo "make uninstall needs root" >&2; exit 1; }
	-rm -f $(DEST_CHKPWD) $(DEST_MODULE) $(INSTALL_DIR)/sudaeon-helper \
		$(INSTALL_DIR)/sudaeon-sentinel $(INSTALL_DIR)/sudaeon-polkit-guard
	-rm -rf $(DEST_PYTHON)
	-rmdir $(INSTALL_DIR) 2>/dev/null || true
	-rm -f $(DEST_BIN)
	-rm -f $(DESTDIR)$(SHAREDIR)/applications/com.sudaeon.Sudaeon.desktop
	-rm -f $(DESTDIR)$(PREFIX)/lib/tmpfiles.d/sudaeon.conf
	-rm -f $(DESTDIR)$(SYSCONFDIR)/xdg/autostart/com.sudaeon.Agent.desktop
	-rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/sudaeon-sentinel.service
	-rm -f $(DESTDIR)$(SYSCONFDIR)/logrotate.d/sudaeon
	@echo "State in $(LOCALSTATEDIR)/lib/sudaeon and the audit log were kept;"
	@echo "use 'sudo sudaeon uninstall --purge' to remove them as well."

clean:
	rm -rf $(BUILD) debian/sudaeon debian/.debhelper debian/files \
		debian/*.substvars debian/*.debhelper dist
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

distclean: clean
	$(MAKE) -C $(TESTS) clean

check-deps:
	@command -v $(CC) >/dev/null || { echo "missing: a C compiler (apt install build-essential)"; exit 1; }
	@test -n "$(PAM_HEADERS)" || test "$(SUDAEON_STUB_PAM)" = "1" || \
		{ echo "missing: the PAM development headers (apt install libpam0g-dev)"; exit 1; }
	@command -v $(PYTHON) >/dev/null || { echo "missing: python3"; exit 1; }
	@echo "build dependencies look complete"

help:
	@sed -n 's/^# \{0,1\}//p' Makefile | sed -n '1,16p'
