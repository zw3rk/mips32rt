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

/* _GNU_SOURCE: setenv/environ and getauxval(AT_EXECFD) under strict
 * -std=c11 with musl (implies the POSIX 2008 feature set as well). */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <sys/auxv.h>
#endif

#include "mips32rt.h"
#include "rt32/rt32.h"

/* Linux generic auxv key (see asm-generic <linux/auxvec.h>); musl's
 * <sys/auxv.h> normally provides it, this is only a fallback. */
#ifndef AT_EXECFD
#define AT_EXECFD 2
#endif

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

/* dbt_main is provided by src/dbt/dbt.c (lane L2b). */

static void usage(FILE *out)
{
    static const char *msg =
        "mips32rt — MIPS32r2 (mipsel/mips O32) Linux user-mode translator\n"
        "\n"
        "Usage:\n"
        "  mips32rt [--window HEX] [--sysroot DIR] [--cache DIR]\n"
        "           [--interp | --dbt] [--difftest] [--trace]\n"
        "           [--execfn PATH] [--image-fd FD] -- PATH [ARGV0...]\n"
        "  mips32rt --help\n"
        "  mips32rt --version\n"
        "\n"
        "  --execfn PATH loads PATH as the guest image and records it in\n"
        "    AT_EXECFN, while every token after -- stays guest argv verbatim\n"
        "    (custom argv[0] preserved).  Without --execfn, PATH is both the\n"
        "    image path and guest argv[0].\n"
        "  --image-fd FD loads the image from the open descriptor (preferred\n"
        "    over AT_EXECFD from auxv; closed after mapping).  PATH is still\n"
        "    required and feeds AT_EXECFN.\n"
        "\n"
        "Environment: MIPS32RT_WINDOW, MIPS32RT_SYSROOT, MIPS32RT_CACHE,\n"
        "             MIPS32RT_ENGINE, MIPS32RT_TRACE, MIPS32RT_DIFFTEST,\n"
        "             MIPS32RT_HOST, MIPS32RT_EXECFN\n";
    fputs(msg, out);
}

/* AT_EXECFD presence (HOST-CONTRACT 3.1): descriptor 0 is a valid open
 * file when stdin was closed before execve, so presence is decided by
 * errno after getauxval, never by comparing the value against 0. */
static int auxv_exec_fd(void)
{
#ifdef __linux__
    unsigned long v;

    errno = 0;
    v = getauxval((unsigned long)AT_EXECFD);
    if (errno != 0) {
        return -1;
    }
    if (v > (unsigned long)INT_MAX) {
        return -1;
    }
    return (int)v;
#else
    return -1;
#endif
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

/* Returns the index of the guest PATH in argv[], or -1 on error.
 * --execfn (when given) is stored in *out_execfn; --image-fd (when given)
 * in *out_image_fd (caller initializes both). */
static int parse_args(mips32_ctx_t *ctx, int argc, char **argv,
                      const char **out_execfn, int *out_image_fd)
{
    int i = 1;

    while (i < argc && strcmp(argv[i], "--") != 0) {
        if (argv[i][0] != '-') {
            return i;
        }
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
            unsigned long long v = strtoull(argv[i + 1], &end, 0);
            if (end == argv[i + 1] || *end != '\0' || v == UINT64_MAX) {
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
        } else if (strcmp(argv[i], "--execfn") == 0) {
            if (argv[i + 1][0] == '\0') {
                return -1;
            }
            *out_execfn = argv[i + 1];
        } else if (strcmp(argv[i], "--image-fd") == 0) {
            char *end = NULL;
            long v;
            errno = 0;
            v = strtol(argv[i + 1], &end, 10);
            /* Any nonnegative int is accepted (fd 0 is valid when stdin
             * was closed before execve); only the descriptor itself is
             * ever closed after mapping, never 0/1/2 or caller fds. */
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                v < 0 || v > INT_MAX) {
                return -1;
            }
            *out_image_fd = (int)v;
        } else {
            return -1;
        }
        i += 2;
    }

    if (i >= argc || i + 1 >= argc) {
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
 * engines that would run it arrive in Phases 1 (interp) and 2 (dbt).
 * exec_fd >= 0 (--image-fd, else AT_EXECFD from auxv) supplies the image
 * bytes; rt32_elf_load consumes exactly that descriptor and closes it
 * after mapping, leaving 0/1/2 and all other caller fds untouched. */
static int run_guest(mips32_ctx_t *ctx, int exec_fd)
{
    rt32_elf_info_t info;
    uint32_t sp = 0;
    int fd = exec_fd;
    int r;

    rt32_host_probe(ctx);
    if (rt32_vm_init(ctx, env_window()) != 0) {
        (void)fprintf(stderr, "mips32rt: guest window init failed\n");
        return -1;
    }

    if (fd < 0) {
        fd = rt32_open_guest_ro(ctx, ctx->exec_path);
        if (fd < 0) {
            (void)fprintf(stderr, "mips32rt: cannot open '%s'\n", ctx->exec_path);
            return -1;
        }
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
    ctx->fr_mode = info.fr_mode != 0U ? 1U : 0U;

    if (ctx->engine < 0) {
        ctx->engine = MIPS32_ENGINE_DBT;
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
    const char *execfn = NULL;
    const char *exec_path;
    const char *env_execfn;
    int path_idx;
    int image_fd = -1;
    int exec_fd;
    int st;

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = -1; /* unset: --interp/--dbt or MIPS32RT_ENGINE; INTERP default */
    ctx.fixade_enabled = 1u; /* Wave U3: Linux MIPS TIF_FIXADE default-on */

    path_idx = parse_args(&ctx, argc, argv, &execfn, &image_fd);
    if (path_idx < 0) {
        usage(stderr);
        return 2;
    }
    apply_env(&ctx);
    /* Wave 1 descriptor order (HOST-CONTRACT 3.1): an explicit --image-fd
     * wins; otherwise the AT_EXECFD auxv entry (when present) supplies the
     * image; otherwise the path is opened.  A value of 0 with errno == 0
     * is a valid descriptor, so auxv_exec_fd decides by errno, not value. */
    exec_fd = image_fd;
    if (exec_fd < 0) {
        exec_fd = auxv_exec_fd();
    }
    /* --execfn decouples the image path (AT_EXECFN) from guest argv[0]:
     * every token after -- stays guest argv verbatim.  MIPS32RT_EXECFN is
     * the env fallback; an explicit --execfn always wins. */
    exec_path = argv[path_idx];
    if (execfn != NULL) {
        exec_path = execfn;
    } else if ((env_execfn = getenv("MIPS32RT_EXECFN")) != NULL &&
               env_execfn[0] != '\0') {
        exec_path = env_execfn;
    }
    ctx.exec_path = exec_path;
    ctx.guest_argc = argc - path_idx;
    ctx.guest_argv = &argv[path_idx];
    ctx.host_envp = environ;

    st = run_guest(&ctx, exec_fd);

    if (st < 0) {
        return 1;
    }
    return st;
}
