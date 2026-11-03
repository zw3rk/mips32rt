/*
 * src/os/proc.c — Process lifecycle: fork, vfork, execve, wait4/waitpid (lane L4c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 4 process lifecycle per SPEC 2.3 (O32 conventions) and the Phase 4
 * lane card.  Dispatch arrives from src/os/syscall_min.c (which stays the
 * only caller); this file owns every helper it needs so the L2a private
 * header and all frozen headers stay untouched.
 *
 * Syscall numbers (offsets from __NR_Linux = 4000) verified one by one
 * against /usr/mipsel-linux-gnu/include/asm/unistd_o32.h from
 * libc6-dev-mipsel-cross 2.36-8cross2 (debian:bookworm-slim,
 * linux/arm64, 2026-10-24):
 *   __NR_fork    +2   (fork)
 *   __NR_waitpid +7   (waitpid: distinct from wait4, same status encoding)
 *   __NR_execve  +11  (execve)
 *   __NR_wait4   +114 (wait4)
 *   __NR_clone   +120 (clone, owned by lane L4b)
 * MIPS O32 defines NO __NR_vfork (the 425-define header has no vfork
 * entry): glibc vfork(2) lowers to clone(2), so vfork arrives through
 * the L4b clone path; mips_proc_vfork below is the same fork body for
 * any direct caller, documented as vfork-as-fork.
 *
 * Return convention (SPEC 2.3): success records $a3 = 0, $v0 = value;
 * error records $a3 = 1, $v0 = positive MIPS errno.  Only ENOSYS differs
 * from the host (MIPS 89 vs host 38); every other errno passes through.
 */

#define _GNU_SOURCE /* wait4(2), WCONTINUED under strict -std=c11 */

#include "mips32rt.h"

#include "os/syscall_nr.h"
#include "os/syscalls_priv.h"
#include "rt32/rt32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Local caps (mirror the L2a sizes). */
#define PROC_PATH_MAX   4096U
#define PROC_PTR_CAP    512U
#define PROC_RUSAGE_SIZE 72U /* MIPS32 struct rusage: 2x timeval(8B) + 14x u32 */
#define PROC_FD_HARD_CAP 65536U

/*
 * Cross-lane hooks (established weak-reference pattern from src/rt32/vm.c:
 * declare locally, NULL-check before calling, no header changes).
 *
 * mips32_dbt_invalidate_range is provided by the Phase 2 DBT; without it
 * (interp-only link) execve still works because no code cache exists.
 * mips32_signals_reset_for_exec is provided by lane L4a's guest-owned
 * signal table; rt32_vm_copy_from/to are weak so standalone host unit
 * harnesses that compile proc.c without vm.c still link.
 */
__attribute__((weak)) void mips32_dbt_invalidate_range(mips32_ctx_t *ctx,
                                                      uint32_t start,
                                                      uint32_t end);
__attribute__((weak)) void mips32_signals_reset_for_exec(mips32_ctx_t *ctx);
__attribute__((weak)) int rt32_vm_copy_from(const mips32_ctx_t *ctx, void *dst,
                                            uint32_t va, uint32_t len);
__attribute__((weak)) int rt32_vm_copy_to(mips32_ctx_t *ctx, uint32_t va,
                                          const void *src, uint32_t len);

/* ---- local guest-memory + return helpers (self-contained, lane-owned) ---- */

static uint32_t proc_swap32(uint32_t v)
{
    return ((v & 0x000000FFU) << 24) | ((v & 0x0000FF00U) << 8) |
           ((v & 0x00FF0000U) >> 8) | ((v & 0xFF000000U) >> 24);
}

static int32_t proc_ret(mips32_ctx_t *ctx, int32_t raw)
{
    int32_t err;

    if (raw < 0) {
        err = mips_errno_from_host((int)(-raw));
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)err;
        ctx->gpr[MIPS32_REG_A3] = 1U;
    } else {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)raw;
        ctx->gpr[MIPS32_REG_A3] = 0U;
    }
    return raw;
}

static int proc_copy_from(const mips32_ctx_t *ctx, void *dst, uint32_t va,
                          uint32_t len)
{
    int (*fn)(const mips32_ctx_t *, void *, uint32_t, uint32_t) =
        rt32_vm_copy_from;

    if (fn != NULL) {
        return fn(ctx, dst, va, len);
    }
    if (len == 0U) {
        return 0;
    }
    if (ctx == NULL || dst == NULL ||
        !mips32_range_ok(ctx, va, len, (uint32_t)PROT_READ)) {
        return -EFAULT;
    }
    memcpy(dst, mips32_guest_ptr(ctx, va), (size_t)len);
    return 0;
}

static int proc_copy_to(mips32_ctx_t *ctx, uint32_t va, const void *src,
                        uint32_t len)
{
    int (*fn)(mips32_ctx_t *, uint32_t, const void *, uint32_t) =
        rt32_vm_copy_to;

    if (fn != NULL) {
        return fn(ctx, va, src, len);
    }
    if (len == 0U) {
        return 0;
    }
    if (ctx == NULL || src == NULL ||
        !mips32_range_ok(ctx, va, len, (uint32_t)PROT_WRITE)) {
        return -EFAULT;
    }
    memcpy(mips32_guest_ptr(ctx, va), src, (size_t)len);
    return 0;
}

/*
 * Fetch O32 argument i (0-based): $a0..$a3 for i<4, guest stack slot at
 * sp+16+4*(i-4) otherwise.  Failure yields ok=0 for an -EFAULT return.
 */
static uint32_t proc_arg(mips32_ctx_t *ctx, uint32_t sp, unsigned i, int *ok)
{
    uint32_t va;
    uint32_t val = 0U;

    if (i < 4U) {
        *ok = 1;
        return ctx->gpr[MIPS32_REG_A0 + i];
    }
    va = sp + 16U + 4U * (i - 4U);
    if ((va & 3U) != 0U || proc_copy_from(ctx, &val, va, 4U) != 0) {
        *ok = 0;
        return 0U;
    }
    *ok = 1;
    return mips_is_be(ctx) ? proc_swap32(val) : val;
}

/* Guest-endian u32 load/store (host window bytes are always LE). */
static int proc_ld32(const mips32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    uint32_t v = 0U;

    if (proc_copy_from(ctx, &v, va, 4U) != 0) {
        return -EFAULT;
    }
    *out = mips_is_be(ctx) ? proc_swap32(v) : v;
    return 0;
}

static int proc_st32(mips32_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint32_t w = mips_is_be(ctx) ? proc_swap32(v) : v;

    if (proc_copy_to(ctx, va, &w, 4U) != 0) {
        return -EFAULT;
    }
    return 0;
}

/* Copy a NUL-terminated guest string into host_buf (PATH_MAX cap). */
static int proc_read_cstr(const mips32_ctx_t *ctx, uint32_t va,
                          char *host_buf)
{
    uint32_t i;

    for (i = 0; i < PROC_PATH_MAX; i++) {
        char b = 0;

        if (proc_copy_from(ctx, &b, va + i, 1U) != 0) {
            return -EFAULT;
        }
        host_buf[i] = b;
        if (b == '\0') {
            return 0;
        }
    }
    return -ENAMETOOLONG;
}

/* Free a host strvec built by copy_guest_strvec. */
static void proc_free_strvec(char **vec, int count)
{
    int i;

    if (vec == NULL) {
        return;
    }
    for (i = 0; i < count; i++) {
        free(vec[i]);
    }
    free(vec);
}

/*
 * Snapshot a guest argv/envp pointer vector into host heap memory (must
 * run BEFORE rt32_vm_reset_for_exec unmaps the old image).  Each entry is
 * a guest-endian u32 VA; each string is capped at PROC_PATH_MAX.  Returns
 * 0 with *out_vec holding count NUL-terminated host strings (*out_count),
 * or a negative errno (nothing leaked on failure).
 */
static int copy_guest_strvec(mips32_ctx_t *ctx, uint32_t vec_va,
                             char ***out_vec, int *out_count)
{
    char  **vec = NULL;
    int     count = 0;
    int     i;

    *out_vec = NULL;
    *out_count = 0;
    if (vec_va == 0U) {
        return 0;
    }
    vec = (char **)calloc(PROC_PTR_CAP + 1U, sizeof(char *));
    if (vec == NULL) {
        return -ENOMEM;
    }
    for (i = 0; i < (int)PROC_PTR_CAP; i++) {
        uint32_t str_va = 0U;
        char    *host_s = NULL;

        if (proc_ld32(ctx, vec_va + (uint32_t)i * 4U, &str_va) != 0) {
            proc_free_strvec(vec, count);
            return -EFAULT;
        }
        if (str_va == 0U) {
            break; /* NUL terminator of the vector */
        }
        host_s = (char *)malloc(PROC_PATH_MAX);
        if (host_s == NULL) {
            proc_free_strvec(vec, count);
            return -ENOMEM;
        }
        if (proc_read_cstr(ctx, str_va, host_s) != 0) {
            free(host_s);
            proc_free_strvec(vec, count);
            return -EFAULT;
        }
        vec[count++] = host_s;
    }
    if (i == (int)PROC_PTR_CAP) {
        /* Uncapped vector: refuse rather than walk off the mapping. */
        proc_free_strvec(vec, count);
        return -E2BIG;
    }
    *out_vec = vec;
    *out_count = count;
    return 0;
}

/* Close every fd flagged O_CLOEXEC (POSIX exec semantics), except keep_fd. */
static void close_cloexec_fds(int keep_fd)
{
    long lim = sysconf(_SC_OPEN_MAX);
    long n;
    long fd;

    if (lim <= 0L) {
        lim = 1024L;
    }
    if (lim > (long)PROC_FD_HARD_CAP) {
        lim = (long)PROC_FD_HARD_CAP;
    }
    for (fd = 0L, n = lim; fd < n; fd++) {
        int flags;

        if ((int)fd == keep_fd) {
            continue;
        }
        flags = fcntl((int)fd, F_GETFD);
        if (flags >= 0 && (flags & FD_CLOEXEC) != 0) {
            (void)close((int)fd);
        }
    }
}

/* fork/vfork live in src/os/fork.c (coordinated fork protocol). */

/* ---- execve ---- */

int32_t mips_proc_execve(mips32_ctx_t *ctx, uint32_t sp)
{
    uint32_t       path_va;
    uint32_t       argv_va;
    uint32_t       envp_va;
    int            ok = 1;
    char           path[PROC_PATH_MAX];
    char         **argv_copy = NULL;
    char         **envp_copy = NULL;
    int            argc_copy = 0;
    int            envc_copy = 0;
    int            rc;
    int            fd;
    rt32_elf_info_t info;
    uint32_t       new_sp = 0U;
    unsigned       i;
    char          *exec_dup = NULL;
    size_t         path_len;

    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
    path_va = proc_arg(ctx, sp, 0, &ok);
    argv_va = proc_arg(ctx, sp, 1, &ok);
    envp_va = proc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return proc_ret(ctx, -EFAULT);
    }
    rc = proc_read_cstr(ctx, path_va, path);
    if (rc != 0) {
        return proc_ret(ctx, rc);
    }
    if (path[0] == '\0') {
        return proc_ret(ctx, -ENOENT);
    }
    /* Snapshot argv/envp BEFORE the reset unmaps the old image. */
    rc = copy_guest_strvec(ctx, argv_va, &argv_copy, &argc_copy);
    if (rc != 0) {
        return proc_ret(ctx, rc);
    }
    rc = copy_guest_strvec(ctx, envp_va, &envp_copy, &envc_copy);
    if (rc != 0) {
        proc_free_strvec(argv_copy, argc_copy);
        return proc_ret(ctx, rc);
    }
    if (argc_copy < 1) {
        proc_free_strvec(argv_copy, argc_copy);
        proc_free_strvec(envp_copy, envc_copy);
        return proc_ret(ctx, -EINVAL);
    }
    /* Pre-open and validate first: a missing or non-ELF file fails here
     * with the old image intact. */
    fd = rt32_open_guest_ro(ctx, path);
    if (fd < 0) {
        proc_free_strvec(argv_copy, argc_copy);
        proc_free_strvec(envp_copy, envc_copy);
        return proc_ret(ctx, -ENOENT);
    }
    if (rt32_elf_validate(ctx, fd) != 0) {
        (void)close(fd);
        proc_free_strvec(argv_copy, argc_copy);
        proc_free_strvec(envp_copy, envc_copy);
        return proc_ret(ctx, -ENOEXEC);
    }

    /* Tear down the old image: unmaps every guest page (stack included),
     * clears brk/mmap cursors and the region table (rt32/vm.c).
     * Close O_CLOEXEC descriptors BEFORE rt32_elf_load creates new
     * FD_CLOEXEC file-backing duplicates in g_vm_backing[]. */
    rt32_vm_reset_for_exec(ctx);
    close_cloexec_fds(fd);
    if (mips32_dbt_invalidate_range != NULL) {
        /* Drop stale translations: the new image reuses the same VAs. */
        mips32_dbt_invalidate_range(ctx, MIPS32_LOW_GUARD_SIZE,
                                    MIPS32_TASK_SIZE_TOP);
    }
    /* rt32_elf_load takes ownership of fd (closes it either way). */
    rc = rt32_elf_load(ctx, fd, path, &info);
    if (rc != 0) {
        proc_free_strvec(argv_copy, argc_copy);
        proc_free_strvec(envp_copy, envc_copy);
        _Exit(127);
    }
    rc = rt32_stack_setup(ctx, &info, argc_copy, argv_copy,
                          (envc_copy > 0) ? envp_copy : NULL, &new_sp);
    proc_free_strvec(argv_copy, argc_copy);
    proc_free_strvec(envp_copy, envc_copy);
    if (rc != 0) {
        _Exit(127);
    }

    /* Mirror the fresh regions into the ctx copy (as run_guest does). */
    rt32_vm_sync_ctx(ctx);

    /* Flat O32 initial state (mirrors run_guest in src/main.c). */
    for (i = 0U; i < 32U; i++) {
        ctx->gpr[i] = 0U;
    }
    ctx->gpr[MIPS32_REG_SP] = new_sp;
    ctx->pc = ctx->elf_entry;
    ctx->next_pc = ctx->pc + 4U;
    ctx->hi = 0U;
    ctx->lo = 0U;
    ctx->ulr = 0U; /* TLS dies with the old image; set_thread_area reruns */
    ctx->fcsr = 0U;
    ctx->in_delay_slot = 0U;
    ctx->llbit = 0U;
    ctx->lladdr = 0U;
    ctx->llval = 0U;
    ctx->cp0_config1 = info.is_be ? 1U : 0U;
    ctx->nan2008 = info.nan2008 ? 1U : 0U;
    ctx->fr_mode = info.fr_mode != 0U ? 1U : 0U;
    ctx->exit_reason = 0U;
    ctx->exit_info = 0U;

    /* Process state: same thread, new program. */
    ctx->clear_child_tid = 0U;
    ctx->robust_list_head = 0U;
    ctx->robust_list_len = 0U;
    ctx->is_thread_clone = false;
    if (mips32_signals_reset_for_exec != NULL) {
        /* L4a hook: guest handler table back to SIG_DFL. */
        mips32_signals_reset_for_exec(ctx);
    }

    /* AT_EXECFN/stack builder reads ctx->exec_path: hand it the new path. */
    path_len = strlen(path) + 1U;
    exec_dup = (char *)malloc(path_len);
    if (exec_dup != NULL) {
        memcpy(exec_dup, path, path_len);
        ctx->exec_path = exec_dup;
    }
    return proc_ret(ctx, 0);
}

/* ---- wait4 / waitpid ---- */

/* Shared wait body.  waitpid(pid, status, options) == wait4(pid, status,
 * options, NULL): pass guest_rusage_va = 0 for the waitpid form.
 *
 * The host wait always runs through POSIX waitpid (a wait4 with a NULL
 * rusage is exactly waitpid); the guest rusage is a zero-filled 72-byte
 * MIPS32 struct rusage on request (lane card), so no host rusage is
 * needed and this file stays portable to every host libc.
 *
 * MIPS wait options/status encoding matches the host asm-generic values
 * (WNOHANG 1, WUNTRACED 2, WCONTINUED 8; exit << 8, sig low 7 bits,
 * 0x7f stopped), so both pass through untranslated.
 */
static int32_t proc_wait_common(mips32_ctx_t *ctx, uint32_t sp,
                                int with_rusage)
{
    uint32_t guest_pid;
    uint32_t status_va;
    uint32_t options;
    uint32_t rusage_va = 0U;
    int      ok = 1;
    int      status = 0;
    pid_t    got;

    guest_pid = proc_arg(ctx, sp, 0, &ok);
    status_va = proc_arg(ctx, sp, 1, &ok);
    options   = proc_arg(ctx, sp, 2, &ok);
    if (with_rusage) {
        rusage_va = proc_arg(ctx, sp, 3, &ok);
    }
    if (!ok) {
        return proc_ret(ctx, -EFAULT);
    }
    rt32_vm_sync_ctx(ctx);
    if (status_va != 0U &&
        !mips32_range_ok(ctx, status_va, 4U, (uint32_t)PROT_WRITE)) {
        return proc_ret(ctx, -EFAULT);
    }
    if (rusage_va != 0U &&
        !mips32_range_ok(ctx, rusage_va, PROC_RUSAGE_SIZE,
                         (uint32_t)PROT_WRITE)) {
        return proc_ret(ctx, -EFAULT);
    }
    errno = 0;
    got = waitpid((pid_t)(int32_t)guest_pid, &status, (int)options);
    if (got < 0) {
        return proc_ret(ctx, -(int32_t)errno);
    }
    if (status_va != 0U) {
        if (proc_st32(ctx, status_va, (uint32_t)status) != 0) {
            return proc_ret(ctx, -EFAULT);
        }
    }
    if (rusage_va != 0U) {
        uint8_t zero_rusage[PROC_RUSAGE_SIZE];

        memset(zero_rusage, 0, sizeof(zero_rusage));
        if (proc_copy_to(ctx, rusage_va, zero_rusage, sizeof(zero_rusage)) != 0) {
            return proc_ret(ctx, -EFAULT);
        }
    }
    return proc_ret(ctx, (int32_t)got);
}

int32_t mips_proc_wait4(mips32_ctx_t *ctx, uint32_t sp)
{
    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
    return proc_wait_common(ctx, sp, 1);
}

int32_t mips_proc_waitpid(mips32_ctx_t *ctx, uint32_t sp)
{
    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
    return proc_wait_common(ctx, sp, 0);
}

/* ---- Phase 5 (lane L5a): /proc/self/{exe,maps,cmdline,stat,auxv} ----
 *
 * Guest-view synthesis for the five /proc/self nodes the lane card names:
 * exe reads back the guest path, maps renders the recorded window VMAs,
 * cmdline joins the guest argv, stat synthesizes the 52-field kernel
 * layout, auxv replays the stack auxv (BE-swapped for mips guests).
 *
 * Only exact absolute /proc/self/<node> and /proc/<pid>/<node> (own pid)
 * names intercept; every other path falls through to the host untouched.
 * Unit-tested by tests/run_p5.sh (host-native probe, no guest needed).
 */

static int proc_node_kind(const char *node)
{
    if (strcmp(node, "exe") == 0) {
        return MIPS_PROC_EXE;
    }
    if (strcmp(node, "maps") == 0) {
        return MIPS_PROC_MAPS;
    }
    if (strcmp(node, "cmdline") == 0) {
        return MIPS_PROC_CMDLINE;
    }
    if (strcmp(node, "stat") == 0) {
        return MIPS_PROC_STAT;
    }
    if (strcmp(node, "auxv") == 0) {
        return MIPS_PROC_AUXV;
    }
    return MIPS_PROC_NONE;
}

int mips_proc_classify(const char *path)
{
    static const char self_prefix[] = "/proc/self/";
    const char *node;
    size_t i;
    unsigned long pid;

    if (path == NULL) {
        return MIPS_PROC_NONE;
    }
    if (strncmp(path, self_prefix, sizeof(self_prefix) - 1U) == 0) {
        node = path + sizeof(self_prefix) - 1U;
        if (*node == '\0' || strchr(node, '/') != NULL) {
            return MIPS_PROC_NONE;
        }
        return proc_node_kind(node);
    }
    if (strncmp(path, "/proc/", 6U) != 0) {
        return MIPS_PROC_NONE;
    }
    pid = 0UL;
    i = 6U;
    while (path[i] >= '0' && path[i] <= '9') {
        pid = pid * 10UL + (unsigned long)(path[i] - '0');
        i++;
    }
    if (i == 6U || path[i] != '/' || pid != (unsigned long)getpid()) {
        return MIPS_PROC_NONE;
    }
    node = path + i + 1U;
    if (*node == '\0' || strchr(node, '/') != NULL) {
        return MIPS_PROC_NONE;
    }
    return proc_node_kind(node);
}

/* Render the window VMA table in kernel maps(5) form.  Returns the byte
 * count (excluding NUL) or a negative errno. */
int mips_proc_maps_text(mips32_ctx_t *ctx, char *buf, unsigned long cap)
{
    unsigned long pos = 0UL;
    size_t i;

    if (ctx == NULL || buf == NULL || cap == 0UL) {
        return -EFAULT;
    }
    rt32_vm_sync_ctx(ctx);
    for (i = 0; i < ctx->region_count; i++) {
        const mips32_region_t *r = &ctx->regions[i];
        char line[160];
        int n = snprintf(line, sizeof(line), "%08x-%08x %c%c%c%c %08x 00:00 0%s%s\n",
                         r->start, r->end,
                         (r->prot & (uint32_t)PROT_READ) != 0U ? 'r' : '-',
                         (r->prot & (uint32_t)PROT_WRITE) != 0U ? 'w' : '-',
                         (r->prot & (uint32_t)PROT_EXEC) != 0U ? 'x' : '-',
                         'p', 0U,
                         r->name[0] != '\0' ? " " : "", r->name);
        if (n < 0 || (unsigned long)n >= (unsigned long)sizeof(line)) {
            return -EIO;
        }
        if (pos + (unsigned long)n + 1UL > cap) {
            return -ENOMEM;
        }
        memcpy(buf + pos, line, (size_t)n);
        pos += (unsigned long)n;
    }
    buf[pos] = '\0';
    return (int)pos;
}

/* Basename without libgen (stays in string.h). */
static const char *proc_comm_name(const char *path)
{
    const char *base;
    const char *slash;

    if (path == NULL || *path == '\0') {
        return "mips32rt";
    }
    base = path;
    for (slash = path; *slash != '\0'; slash++) {
        if (*slash == '/') {
            base = slash + 1;
        }
    }
    return (*base == '\0') ? "mips32rt" : base;
}

/* Synthesize the 52-field /proc/self/stat layout (proc(5) order): the
 * identity fields (pid, comm, state, ppid, pgrp, session) are truthful,
 * counters and clocks read zero in this user-mode view. */
static int proc_stat_text(mips32_ctx_t *ctx, char *buf, unsigned long cap)
{
    int pid = (int)getpid();
    int ppid = (int)getppid();
    int pgrp = (int)getpgrp();
    int session = getsid(0);
    int n;

    (void)ctx;
    if (buf == NULL || cap == 0UL) {
        return -EFAULT;
    }
    if (session < 0) {
        session = pid;
    }
    n = snprintf(buf, cap,
                 "%d (%s) R %d %d %d 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                 pid, proc_comm_name(ctx != NULL ? ctx->exec_path : NULL),
                 ppid, pgrp, session);
    if (n < 0 || (unsigned long)n >= cap) {
        return -ENOMEM;
    }
    return n;
}

/* NUL-joined guest argv in kernel cmdline form (trailing NUL, no newline).
 * Returns the byte count or a negative errno. */
static int proc_cmdline_bytes(mips32_ctx_t *ctx, char *buf, unsigned long cap)
{
    unsigned long pos = 0UL;
    int i;

    if (ctx == NULL || buf == NULL || cap == 0UL) {
        return -EFAULT;
    }
    for (i = 0; i < ctx->guest_argc; i++) {
        const char *arg = (ctx->guest_argv != NULL && ctx->guest_argv[i] != NULL)
            ? ctx->guest_argv[i] : "";
        size_t len = strlen(arg) + 1U;
        if (pos + (unsigned long)len > cap) {
            return -ENOMEM;
        }
        memcpy(buf + pos, arg, len);
        pos += (unsigned long)len;
    }
    return (int)pos;
}

static int proc_auxv_bytes(mips32_ctx_t *ctx, char *buf, unsigned long cap)
{
    size_t i;
    unsigned long pos = 0UL;

    if (ctx == NULL || buf == NULL || cap == 0UL) {
        return -EFAULT;
    }
    if (ctx->auxv_bytes > cap || (ctx->auxv_bytes % 4U) != 0U) {
        return -ENOMEM;
    }
    for (i = 0; i < ctx->auxv_bytes; i += 4U) {
        uint32_t w;
        memcpy(&w, (const char *)ctx->auxv_data + i, 4U);
        if (mips_is_be(ctx)) {
            w = proc_swap32(w);
        }
        memcpy(buf + pos, &w, 4U);
        pos += 4UL;
    }
    return (int)pos;
}

/* Write the whole buffer (EINTR-safe); 0 on success, -errno otherwise. */
static int proc_write_all(int fd, const void *data, unsigned long len)
{
    const char *p = (const char *)data;
    while (len > 0UL) {
        ssize_t n = write(fd, p, (size_t)len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (n == 0) {
            return -EIO;
        }
        p += n;
        len -= (unsigned long)n;
    }
    return 0;
}

/* Materialize content as a seekable read-only host fd.  Write-mode opens
 * fail with EACCES exactly like the kernel nodes. */
static int proc_synth_fd(const char *tag, const void *data, unsigned long len,
                         int flags)
{
    int fd;
    int rc;

    if (((flags & O_ACCMODE) != O_RDONLY) || ((flags & O_TRUNC) != 0)) {
        return -EACCES;
    }
#ifdef __linux__
    fd = memfd_create(tag, (flags & O_CLOEXEC) != 0 ? MFD_CLOEXEC : 0);
#else
    (void)tag;
    char tmpl[] = "/tmp/mips32rt-proc-XXXXXX";
    fd = mkstemp(tmpl);
    if (fd >= 0) {
        (void)unlink(tmpl);
        if ((flags & O_CLOEXEC) != 0) {
            (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
    }
#endif
    if (fd < 0) {
        return -errno;
    }
    rc = proc_write_all(fd, data, len);
    if (rc != 0) {
        close(fd);
        return rc;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        close(fd);
        return -errno;
    }
    return fd;
}

/* Open a readable handle for a classified node: host fd or -errno.
 * exe prefers a real read-only handle on the guest executable (kernel
 * read semantics serve ELF bytes) and falls back to the path string. */
int mips_proc_open(mips32_ctx_t *ctx, int kind, int flags)
{
    char text[8192];
    int n;

    if (ctx == NULL) {
        return -EFAULT;
    }
    switch (kind) {
    case MIPS_PROC_EXE: {
        const char *exe = (ctx->exec_path != NULL) ? ctx->exec_path : "";
        if (((flags & O_ACCMODE) != O_RDONLY) || ((flags & O_TRUNC) != 0)) {
            return -EACCES;
        }
        if (exe[0] != '\0') {
            int fd = rt32_open_guest_ro(ctx, exe);
            if (fd >= 0) {
                return fd;
            }
        }
        return proc_synth_fd("exe", exe, (unsigned long)strlen(exe), flags);
    }
    case MIPS_PROC_MAPS:
        n = mips_proc_maps_text(ctx, text, sizeof(text));
        if (n < 0) {
            return n;
        }
        return proc_synth_fd("maps", text, (unsigned long)n, flags);
    case MIPS_PROC_CMDLINE:
        n = proc_cmdline_bytes(ctx, text, sizeof(text));
        if (n < 0) {
            return n;
        }
        return proc_synth_fd("cmdline", text, (unsigned long)n, flags);
    case MIPS_PROC_STAT:
        n = proc_stat_text(ctx, text, sizeof(text));
        if (n < 0) {
            return n;
        }
        return proc_synth_fd("stat", text, (unsigned long)n, flags);
    case MIPS_PROC_AUXV:
        n = proc_auxv_bytes(ctx, text, sizeof(text));
        if (n < 0) {
            return n;
        }
        return proc_synth_fd("auxv", text, (unsigned long)n, flags);
    default:
        break;
    }
    return -ENOENT;
}

/* readlink on the classified node: only exe is a symlink (the guest path);
 * the file nodes fail with EINVAL exactly like the kernel ones.  Returns
 * the byte count or a negative errno. */
long mips_proc_readlink(mips32_ctx_t *ctx, int kind, char *buf,
                        unsigned long bufsz)
{
    const char *exe;
    unsigned long n;

    if (ctx == NULL || buf == NULL) {
        return -EFAULT;
    }
    if (kind != MIPS_PROC_EXE) {
        return (kind == MIPS_PROC_NONE) ? -ENOENT : -EINVAL;
    }
    exe = (ctx->exec_path != NULL) ? ctx->exec_path : "";
    n = (unsigned long)strlen(exe);
    if (n > bufsz) {
        n = bufsz;
    }
    if (n > 0UL) {
        memcpy(buf, exe, (size_t)n);
    }
    return (long)n;
}
