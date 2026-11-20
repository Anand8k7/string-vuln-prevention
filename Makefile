# =============================================================================
#  CYE551 - Secure Coding Using C/C++  |  MSRIT, Dept. of CSE (Cyber Security)
#  Mini Project: Implementing Prevention Methods for String Vulnerabilities
#
#  Targets
#    make / make all   -> build vulnerable + secure programs
#    make vulnerable   -> build deliberately unsafe demos   (bin/vulnerable/)
#    make secure       -> build fixed programs + safe lib   (bin/secure/)
#    make asan         -> build BOTH with AddressSanitizer  (bin/asan/)
#    make test         -> build and run the test suite (PASS/FAIL table)
#    make analyze      -> cppcheck + ASan + Valgrind, logs in analysis/logs/
#    make clean        -> remove all build output
#
#  Sources are discovered automatically: every  src/vulnerable/X.c  becomes
#  bin/vulnerable/X,  every  src/secure/X.c  becomes  bin/secure/X  (linked
#  against the safe-string library in src/lib/).
# =============================================================================

# Use gcc unless the user overrides it (e.g. `make CC=clang`).
# (`CC ?= gcc` does not work because make predefines CC=cc.)
ifeq ($(origin CC),default)
CC := gcc
endif
BIN     := bin
LIB_DIR := src/lib

# -----------------------------------------------------------------------------
# Compiler flags
# -----------------------------------------------------------------------------
# Secure build: every warning that matters for strings is turned into an
# error, plus the usual hardening (stack protector, FORTIFY_SOURCE, PIE).
SECURE_CFLAGS := -std=c11 -Wall -Wextra -Werror -Wpedantic \
                 -Wformat=2 -Wformat-security -Wformat-overflow=2 \
                 -Wformat-truncation=2 -Wstringop-overflow=4 \
                 -Wshadow -Wconversion -Wsign-conversion \
                 -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
                 -fPIE -I$(LIB_DIR)
SECURE_LDFLAGS := -pie -Wl,-z,relro,-z,now

# Vulnerable build: protections are switched OFF on purpose so the bugs are
# observable during the demo. Warnings are still shown (not errors) so you
# can see that the compiler already complains about the unsafe code.
VULN_CFLAGS := -std=c11 -Wall -Wextra -O0 -g \
               -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
               -Wno-error
VULN_LDFLAGS :=

# ASan/UBSan build (used for both versions in the analysis phase).
ASAN_CFLAGS := -std=c11 -Wall -Wextra -O1 -g -fno-omit-frame-pointer \
               -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
               -fsanitize=address,undefined -I$(LIB_DIR)
ASAN_LDFLAGS := -fsanitize=address,undefined

# -----------------------------------------------------------------------------
# Source discovery
# -----------------------------------------------------------------------------
LIB_SRC    := $(wildcard $(LIB_DIR)/*.c)
LIB_HDR    := $(wildcard $(LIB_DIR)/*.h)
LIB_OBJ    := $(patsubst $(LIB_DIR)/%.c,$(BIN)/lib/%.o,$(LIB_SRC))
VULN_SRC   := $(wildcard src/vulnerable/*.c)
SECURE_SRC := $(wildcard src/secure/*.c)
TEST_SRC   := $(wildcard tests/*.c)

VULN_BIN   := $(patsubst src/vulnerable/%.c,$(BIN)/vulnerable/%,$(VULN_SRC))
SECURE_BIN := $(patsubst src/secure/%.c,$(BIN)/secure/%,$(SECURE_SRC))
ASAN_VULN  := $(patsubst src/vulnerable/%.c,$(BIN)/asan/vulnerable_%,$(VULN_SRC))
ASAN_SEC   := $(patsubst src/secure/%.c,$(BIN)/asan/secure_%,$(SECURE_SRC))
TEST_BIN   := $(patsubst tests/%.c,$(BIN)/tests/%,$(TEST_SRC))

.PHONY: all lib vulnerable secure asan test analyze clean help

all: vulnerable secure

help:
	@sed -n '5,13p' Makefile

# -----------------------------------------------------------------------------
# Build rules
# -----------------------------------------------------------------------------
vulnerable: $(VULN_BIN)
	@echo "[vulnerable] built: $(if $(VULN_BIN),$(VULN_BIN),<none yet>)"

# Safe-string library, compiled with the strict secure flags (-Werror).
lib: $(LIB_OBJ)

$(BIN)/lib/%.o: $(LIB_DIR)/%.c $(LIB_HDR) Makefile | $(BIN)/lib
	$(CC) $(SECURE_CFLAGS) -c $< -o $@

secure: lib $(SECURE_BIN)
	@echo "[secure] built: $(if $(SECURE_BIN),$(SECURE_BIN),<none yet>)"

asan: $(ASAN_VULN) $(ASAN_SEC)
	@echo "[asan] built: $(if $(ASAN_VULN)$(ASAN_SEC),$(ASAN_VULN) $(ASAN_SEC),<none yet>)"

$(BIN)/vulnerable/%: src/vulnerable/%.c Makefile | $(BIN)/vulnerable
	$(CC) $(VULN_CFLAGS) $< -o $@ $(VULN_LDFLAGS)

$(BIN)/secure/%: src/secure/%.c $(LIB_OBJ) $(LIB_HDR) Makefile | $(BIN)/secure
	$(CC) $(SECURE_CFLAGS) $< $(LIB_OBJ) -o $@ $(SECURE_LDFLAGS)

$(BIN)/asan/vulnerable_%: src/vulnerable/%.c Makefile | $(BIN)/asan
	$(CC) $(ASAN_CFLAGS) $< -o $@ $(ASAN_LDFLAGS)

$(BIN)/asan/secure_%: src/secure/%.c $(LIB_SRC) $(LIB_HDR) Makefile | $(BIN)/asan
	$(CC) $(ASAN_CFLAGS) $< $(LIB_SRC) -o $@ $(ASAN_LDFLAGS)

# Test programs are built with ASan + UBSan (and -Werror) so any memory error
# or undefined behaviour inside the library makes the test run fail.
TEST_CFLAGS := $(ASAN_CFLAGS) -Werror

$(BIN)/tests/%: tests/%.c $(LIB_SRC) $(LIB_HDR) Makefile | $(BIN)/tests
	$(CC) $(TEST_CFLAGS) $< $(LIB_SRC) -o $@ $(ASAN_LDFLAGS)

$(BIN)/lib $(BIN)/vulnerable $(BIN)/secure $(BIN)/asan $(BIN)/tests:
	@mkdir -p $@

# -----------------------------------------------------------------------------
# Test / analysis
# -----------------------------------------------------------------------------
test: all asan $(TEST_BIN)
	@if [ -x tests/run_tests.sh ]; then \
		tests/run_tests.sh; \
	elif [ -n "$(TEST_BIN)" ]; then \
		rc=0; for t in $(TEST_BIN); do ./$$t || rc=1; done; exit $$rc; \
	else \
		echo "[test] no tests yet (added in Phase 2)"; \
	fi

analyze: all asan
	@if [ -x analysis/run_analysis.sh ]; then \
		analysis/run_analysis.sh; \
	else \
		echo "[analyze] analysis/run_analysis.sh not present yet (added in Phase 5)"; \
	fi

clean:
	rm -rf $(BIN)
	rm -f analysis/logs/*.log
