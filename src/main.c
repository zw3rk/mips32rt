/*
 * src/main.c — Entry point and option handling for mips32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0: option/env plumbing and the invocation forms only.  No engine
 * is wired yet (Phases 1 and 2); running a guest exits 2 with a clear
 * message.  --version and --help work without any guest binary.
 */

/* POSIX 2008: setenv/environ under strict -std=c11 with musl. */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mips32rt.h"
#include "rt32/rt32.h"

extern char **environ;

#define MIPS32RT_VERSION "0.0-phase0"

/* Phase 1: the reference interpreter drives the guest to exit(2) or to a
 * synchronous fault (which raises SIGSEGV, see mips_fault).  interp_run
 * returns only if an engine-level stop reason was recorded. */
int interp_main(mips32_ctx_t *ctx)
{
    int rc = interp_run(ctx);

    if (rc != 0) {
        (void)fprintf(stderr, "mips32rt: interp stopped (reason %u, info 0x%x)\n",
                      ctx->exit_reason, ctx->exit_info);
        return 1;
    }
    return 0;
}

int dbt_main(mips32_ctx_t *ctx)
{
    (void)ctx;
    (void)fprintf(stderr, "mips32rt: DBT not yet implemented (Phase 2)\n");
    return 2;
}

static void usage(FILE *out)
{
    static const char *msg =
        "mips32rt — MIPS32r2 (mipsel/mips O32) Linux user-mode translator\n"
        "\n"
        "Usage:\n"
        "  mips32rt [--window HEX] [--sysroot DIR] [--cache DIR]\n"
        "           [--interp | --dbt] [--difftest] [--trace] -- PATH [ARGV0...]\n"
        "  mips32rt --help\n"
        "  mips32rt --version\n"
        "\n"
        "Environment: MIPS32RT_WINDOW, MIPS32RT_SYSROOT, MIPS32RT_CACHE,\n"
        "             MIPS32RT_ENGINE, MIPS32RT_TRACE, MIPS32RT_DIFFTEST,\n"
        "             MIPS32RT_HOST\n";
    fputs(msg, out);
}

static int parse_engine(const char *s, int *out)
{
    if (strcmp(s, "interp") == 0) {
        *out = MIPS32_ENGINE_INTERP;
        return 0;
    }
    if (strcmp(s, "dbt") == 0) {
        *out = MIPS32_ENGINE_DBT;
        return 0;
    }
    return -1;
}

/* Returns the index of the guest PATH in argv[], or -1 on error. */
static int parse_args(mips32_ctx_t *ctx, int argc, char **argv)
{
    int i = 1;

    while (i < argc && strcmp(argv[i], "--") != 0) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            exit(0);
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("mips32rt %s\n", MIPS32RT_VERSION);
            exit(0);
        }
        if (strcmp(argv[i], "--interp") == 0) {
            ctx->engine = MIPS32_ENGINE_INTERP;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--dbt") == 0) {
            ctx->engine = MIPS32_ENGINE_DBT;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--difftest") == 0) {
            ctx->difftest_enabled = true;
            i++;
            continue;
        }
        if (strcmp(argv[i], "--trace") == 0) {
            ctx->trace_enabled = true;
            i++;
            continue;
        }
        if (i + 1 >= argc) {
            return -1;
        }
        if (strcmp(argv[i], "--window") == 0) {
            char *end = NULL;
            (void)strtoull(argv[i + 1], &end, 0);
            if (end == argv[i + 1] || *end != '\0') {
                return -1;
            }
            /* Consumed by rt32_vm_init via MIPS32RT_WINDOW (see below). */
            setenv("MIPS32RT_WINDOW", argv[i + 1], 1);
        } else if (strcmp(argv[i], "--sysroot") == 0) {
            ctx->sysroot = argv[i + 1];
        } else if (strcmp(argv[i], "--cache") == 0) {
            ctx->cache_dir = argv[i + 1];
        } else if (strcmp(argv[i], "--engine") == 0) {
            if (parse_engine(argv[i + 1], &ctx->engine) != 0) {
                return -1;
            }
        } else {
            return -1;
        }
        i += 2;
    }

    if (i >= argc) {
        return -1; /* missing "-- PATH" */
    }
    return i + 1; /* first token after "--" */
}

static void apply_env(mips32_ctx_t *ctx)
{
    const char *s;

    if (ctx->engine != MIPS32_ENGINE_DBT && ctx->engine != MIPS32_ENGINE_INTERP) {
        /* Not set explicitly by --interp/--dbt: honor the environment. */
        if ((s = getenv("MIPS32RT_ENGINE")) != NULL) {
            if (parse_engine(s, &ctx->engine) != 0) {
                fprintf(stderr, "mips32rt: bad MIPS32RT_ENGINE=%s\n", s);
                exit(2);
            }
        }
    }
    if (ctx->sysroot == NULL && (s = getenv("MIPS32RT_SYSROOT")) != NULL) {
        ctx->sysroot = s;
    }
    if (ctx->cache_dir == NULL && (s = getenv("MIPS32RT_CACHE")) != NULL) {
        ctx->cache_dir = s;
    }
    if (!ctx->trace_enabled && (s = getenv("MIPS32RT_TRACE")) != NULL && s[0] != '\0' &&
        strcmp(s, "0") != 0) {
        ctx->trace_enabled = true;
    }
    if (!ctx->difftest_enabled && (s = getenv("MIPS32RT_DIFFTEST")) != NULL && s[0] != '\0' &&
        strcmp(s, "0") != 0) {
        ctx->difftest_enabled = true;
    }
    /* MIPS32RT_HOST=none opts out of the /dev/a32host handshake. */
    if ((s = getenv("MIPS32RT_HOST")) != NULL && strcmp(s, "none") == 0) {
        ctx->has_host_info = false;
    }
}

static uint64_t env_window(void)
{
    const char *s = getenv("MIPS32RT_WINDOW");
    char *end = NULL;
    unsigned long long v;

    if (s == NULL) {
        /* Unset means "no explicit choice": rt32_vm_init then applies
         * its own resolution order (env re-read, a32host hint, scan).
         * A literal MIPS32RT_WINDOW=0 still selects no-offset mode. */
        return UINT64_MAX;
    }
    v = strtoull(s, &end, 0);
    if (end == s || *end != '\0') {
        return UINT64_MAX; /* rt32_vm_init re-parses and reports it */
    }
    return (uint64_t)v;
}

/* Phase 0 guest launch: reserve the window and admit the ELF only; the
 * engines that would run it arrive in Phases 1 (interp) and 2 (dbt). */
static int run_guest(mips32_ctx_t *ctx)
{
    rt32_elf_info_t info;
    uint32_t sp = 0;
    int fd;
    int r;

    rt32_host_probe(ctx);
    if (rt32_vm_init(ctx, env_window()) != 0) {
        (void)fprintf(stderr, "mips32rt: guest window init failed\n");
        return -1;
    }

    fd = rt32_open_guest_ro(ctx, ctx->exec_path);
    if (fd < 0) {
        (void)fprintf(stderr, "mips32rt: cannot open '%s'\n", ctx->exec_path);
        return -1;
    }
    if (rt32_elf_load(ctx, fd, ctx->exec_path, &info) != 0) {
        (void)fprintf(stderr, "mips32rt: ELF load failed: %s\n", ctx->exec_path);
        return -1;
    }

    if (rt32_stack_setup(ctx, &info, ctx->guest_argc, ctx->guest_argv,
                         ctx->host_envp, &sp) != 0) {
        (void)fprintf(stderr, "mips32rt: guest stack setup failed\n");
        return -1;
    }

    /* ELF + stack recorded regions in the VMA table; mirror them into
     * ctx->regions for the guest accessors (mem.c walks the mirror). */
    rt32_vm_sync_ctx(ctx);

    /* Flat O32 Linux initial state (engines consume it from Phase 1 on). */
    ctx->gpr[MIPS32_REG_SP] = sp;
    ctx->pc = ctx->elf_entry;
    ctx->next_pc = ctx->pc + 4U;
    /* Endianness + NaN mode from the ELF admission probe (SPEC 1.1, E03). */
    ctx->cp0_config1 = info.is_be ? 1U : 0U;
    ctx->nan2008 = info.nan2008 ? 1U : 0U;
    ctx->fr_mode = 0U;

    if (ctx->engine < 0) {
        ctx->engine = MIPS32_ENGINE_INTERP; /* default oracle (Phase 1) */
    }
    if (ctx->difftest_enabled && ctx->engine != MIPS32_ENGINE_DBT) {
        (void)fprintf(stderr, "mips32rt: --difftest needs the DBT engine (Phase 2)\n");
        return 2;
    }
    if (ctx->engine == MIPS32_ENGINE_DBT) {
        r = dbt_main(ctx);
    } else {
        r = interp_main(ctx);
    }
    /* RC2 difftest hook: deterministic exit-state dump (stderr keeps it
     * separate from guest stdout).  Set MIPS32RT_DUMPSTATE=1. */
    if (getenv("MIPS32RT_DUMPSTATE") != NULL) {
        mips_dump_regs(ctx, stderr);
    }
    return r;
}

/* Shared exit-state dump for the RC2 difftest harness (both engines). */
void mips_dump_regs(const mips32_ctx_t *ctx, FILE *out)
{
    unsigned i;

    if (ctx == NULL || out == NULL) {
        return;
    }
    (void)fprintf(out, "REGS pc=%08x next=%08x hi=%08x lo=%08x ulr=%08x fcsr=%08x\n",
                  ctx->pc, ctx->next_pc, ctx->hi, ctx->lo, ctx->ulr, ctx->fcsr);
    for (i = 0u; i < 32u; i += 4u) {
        (void)fprintf(out, "GPR r%02u=%08x r%02u=%08x r%02u=%08x r%02u=%08x\n", i,
                      ctx->gpr[i], i + 1u, ctx->gpr[i + 1u], i + 2u,
                      ctx->gpr[i + 2u], i + 3u, ctx->gpr[i + 3u]);
    }
    (void)fprintf(out, "EXIT reason=%u info=%08x\n", ctx->exit_reason, ctx->exit_info);
}

int main(int argc, char **argv)
{
    mips32_ctx_t ctx;
    int path_idx;
    int st;

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = -1; /* unset: --interp/--dbt or MIPS32RT_ENGINE; INTERP default */

    path_idx = parse_args(&ctx, argc, argv);
    if (path_idx < 0) {
        usage(stderr);
        return 2;
    }
    apply_env(&ctx);
    ctx.exec_path = argv[path_idx];
    ctx.guest_argc = argc - path_idx;
    ctx.guest_argv = &argv[path_idx];
    ctx.host_envp = environ;

    st = run_guest(&ctx);

    if (st < 0) {
        return 1;
    }
    return st;
}
