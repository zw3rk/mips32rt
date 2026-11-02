# Self-documenting Makefile for mips32rt — MIPS32r2 (mipsel/mips O32) -> AArch64 user-mode translator
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help all build build-darwin test check check-line-limits check-abi-invariants clean

BUILD_DIR := _build

# CC defaults to the shell's cc; inside the cross shell
#   nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c ...
# that is the aarch64-unknown-linux-musl cross CC.  An explicit
# CC from the environment or command line always wins.
ifeq ($(origin CC),default)
  CC := cc
endif
# src/main.c calls setenv(3), which musl hides under strict -std=c11 unless a
# POSIX feature-test macro is visible; expose exactly that (keeps -pedantic
# and every prescribed warning intact).
CFLAGS  ?= -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror=vla -Werror -pedantic -Os -fPIE -Iinclude -Isrc -Isrc/rt32
LDFLAGS ?= -static-pie -Wl,-z,max-page-size=4096

# src/main.c plus every vendored rt32 core file (Lane L0a).  Later phases
# append src/interp, src/dbt, and src/os (beyond src/os/syscall_nr.h).
# Wave U3: exactly one host backend joins the build (both define the same
# rt_host_* symbols). Selected from the compiler target triple so
# cross-builds get backend_linux even when the build host is Darwin.
U3_PROBE_CC := $(or $(CC),cc)
ifeq ($(findstring darwin,$(shell $(U3_PROBE_CC) -dumpmachine 2>/dev/null)),darwin)
U3_BACKEND_SRC := src/os/backend_darwin.c
else
U3_BACKEND_SRC := src/os/backend_linux.c
endif
U3_OS_SRCS := $(filter-out src/os/backend_linux.c src/os/backend_darwin.c,$(wildcard src/os/*.c)) $(U3_BACKEND_SRC)
SRCS := src/main.c $(wildcard src/rt32/*.c) $(wildcard src/interp/*.c) $(U3_OS_SRCS) $(wildcard src/dbt/*.c) $(wildcard src/vm/*.c) $(wildcard src/dbt/aot/*.c) src/rt32/safe_syscall_a64.S src/dbt/trampoline_a64.S
HDRS := src/mips32rt.h include/a32host.h $(wildcard src/rt32/*.h) $(wildcard src/interp/*.h) $(wildcard src/os/*.h) $(wildcard src/dbt/*.h) $(wildcard src/vm/*.h) $(wildcard src/dbt/aot/*.h)

OBJ_DIR    := $(BUILD_DIR)/obj
OBJS       := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(filter %.c,$(SRCS))) $(OBJ_DIR)/rt32/safe_syscall_a64.o $(OBJ_DIR)/dbt/trampoline_a64.o
MIPS32RT_BIN := $(BUILD_DIR)/mips32rt
MIPS32RT_DARWIN_BIN := $(BUILD_DIR)/mips32rt-darwin
DARWIN_CC     ?= cc
DARWIN_CFLAGS ?= -std=c11 -D_DARWIN_C_SOURCE -Wall -Wextra -Werror=vla -Werror -pedantic -Os -fPIE -Iinclude -Isrc -Isrc/rt32

help: ## Show available build and verification targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

all: build ## Build everything (currently just the mips32rt binary)

build: $(MIPS32RT_BIN) ## Build static-PIE aarch64-linux mips32rt binary

build-darwin: ## Build native macOS arm64 mips32rt-darwin binary
	@$(MAKE) --no-print-directory $(MIPS32RT_DARWIN_BIN) CC="$(DARWIN_CC)" CFLAGS="$(DARWIN_CFLAGS)" LDFLAGS="" OBJ_DIR="$(BUILD_DIR)/darwin-obj"

$(MIPS32RT_BIN): $(OBJS)
	@printf "\033[32m▸ Linking\033[0m $@\n"
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@
	@ln -sf mips32rt $(BUILD_DIR)/mips32rt-binfmt-p

$(MIPS32RT_DARWIN_BIN): $(OBJS)
	@printf "\033[32m▸ Linking\033[0m $@\n"
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/rt32/safe_syscall_a64.o: src/rt32/safe_syscall_a64.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/dbt/trampoline_a64.o: src/dbt/trampoline_a64.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

test: ## Run the host-native test suites (ABI invariants + decoder self-test)
	@mkdir -p $(BUILD_DIR)
	@if [ -f tests/check_abi_invariants.c ]; then \
		cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc tests/check_abi_invariants.c -o $(BUILD_DIR)/check_abi_invariants && ./$(BUILD_DIR)/check_abi_invariants; \
	fi
	@if [ -f tests/test_decode.c ]; then \
		cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc tests/test_decode.c src/interp/decode.c -o $(BUILD_DIR)/test_decode && ./$(BUILD_DIR)/test_decode; \
	fi

check: test check-line-limits check-abi-invariants ## Run all Phase 0 checks

check-line-limits: ## Fail if any .c/.h/.S source file exceeds 900 lines
	@fail=0; \
	for f in $$(find src include tests -name '*.c' -o -name '*.h' -o -name '*.S'); do \
		n=$$(wc -l < "$$f"); \
		if [ "$$n" -gt 900 ]; then echo "LIMIT FAIL: $$f has $$n lines (>900)"; fail=1; fi; \
	done; \
	if [ "$$fail" -ne 0 ]; then exit 1; fi; \
	echo "line limits ok (every .c/.h/.S <= 900 lines)"

check-abi-invariants: ## Compile+run tests/check_abi_invariants.c (lane L0b; skips gracefully until it lands)
	@if [ -f tests/check_abi_invariants.c ]; then \
		mkdir -p $(BUILD_DIR) && \
		cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc tests/check_abi_invariants.c -o $(BUILD_DIR)/check_abi_invariants && ./$(BUILD_DIR)/check_abi_invariants; \
	else \
		echo "check-abi-invariants: tests/check_abi_invariants.c not present (lane L0b) — skipping"; \
	fi

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
