# Sudaeon C layer: build and run the tests for cutil, sudaeon-chkpwd and
# pam_sudaeon.so.  Nothing here needs libpam development headers: the stubs in
# tests/c/stubs provide the small part of the PAM API the module uses.
#
#   make -C tests/c            # build everything
#   make -C tests/c test-util  # RFC 7914 / RFC 8439 vectors, policy parsing
#   make -C tests/c test-chkpwd
#   make -C tests/c test-pam
#   make -C tests/c test       # all three suites
#   make -C tests/c clean

CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
SRC = ../../src/sudaeon
BUILD = build

.PHONY: all clean test test-util test-chkpwd test-pam

all: test-util test-chkpwd test-pam

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/sudaeon-chkpwd: $(SRC)/sudaeon-chkpwd.c $(SRC)/cutil.c $(SRC)/cutil.h | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRC) -o $@ $(SRC)/sudaeon-chkpwd.c $(SRC)/cutil.c

$(BUILD)/pam_sudaeon.so: $(SRC)/pam_sudaeon.c $(SRC)/cutil.c $(SRC)/cutil.h | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -shared -Istubs -I$(SRC) -o $@ $(SRC)/pam_sudaeon.c $(SRC)/cutil.c

$(BUILD)/test_util: test_util.c $(SRC)/cutil.c | $(BUILD)
	$(CC) $(CFLAGS) -Wno-format-truncation -I$(SRC) -o $@ test_util.c $(SRC)/cutil.c

$(BUILD)/test_chkpwd: test_chkpwd.c $(SRC)/cutil.c | $(BUILD)
	$(CC) $(CFLAGS) -Wno-format-truncation -I$(SRC) -o $@ test_chkpwd.c $(SRC)/cutil.c

$(BUILD)/test_pam: test_pam.c $(SRC)/pam_sudaeon.c $(SRC)/cutil.c | $(BUILD)
	$(CC) $(CFLAGS) -Istubs -I$(SRC) -o $@ test_pam.c $(SRC)/pam_sudaeon.c $(SRC)/cutil.c

test: test-util test-chkpwd test-pam

test-util: $(BUILD)/test_util
	$(BUILD)/test_util

test-chkpwd: $(BUILD)/sudaeon-chkpwd $(BUILD)/test_chkpwd
	$(BUILD)/test_chkpwd $(BUILD)/sudaeon-chkpwd

test-pam: $(BUILD)/pam_sudaeon.so $(BUILD)/test_pam
	$(BUILD)/test_pam

clean:
	rm -rf $(BUILD)
