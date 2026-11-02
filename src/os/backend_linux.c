/*
 * src/os/backend_linux.c — Backend 1: static-PIE aarch64-linux (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 section 6, Backend 1: runs inside
 * hyper-linux (hl) or directly on a native aarch64-linux kernel.
 * Raw Linux AArch64 svc #0 via mips32_safe_syscall6 (D18
 * signal-window gate) for the DBT path; libc fallback here for the
 * host build.  Host mprotect W^X + IC IALLU discipline; /dev/a32host
 * family shm inode table; MAP_PRIVATE arena COW via the kernel.
 *
 * Pure C11.  Never touches x18.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include "os/backend.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* macOS names it MAP_ANON; Linux MAP_ANONYMOUS. */
#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

#if defined(__linux__) && !defined(SYS_memfd_create)
#if defined(__aarch64__)
#define SYS_memfd_create 279
#endif
#endif

mips32_backend_kind_t mips32_host_backend_kind(void)
{
    return MIPS32_BACKEND_LINUX;
}

int mips32_host_is_hyper_linux(void)
{
    int fd = open("/dev/a32host", O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        return 0;
    }
    (void)close(fd);
    return 1;
}

size_t mips32_host_page_size(void)
{
    long v = sysconf(_SC_PAGESIZE);

    if (v <= 0) {
        return 4096u;
    }
    return (size_t)v;
}

int mips32_host_map_anon(void *hint_addr, size_t len, int linux_prot,
                          int fixed, int noreplace, void **out_host_addr)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *res;

    if (len == 0u || out_host_addr == NULL) {
        return -EINVAL;
    }
    if (fixed != 0) {
        flags |= MAP_FIXED;
    }
    if (noreplace != 0) {
#ifdef MAP_FIXED_NOREPLACE
        flags |= MAP_FIXED_NOREPLACE;
#else
        if (fixed == 0) {
            flags |= MAP_FIXED;
        }
#endif
    }
    res = mmap(hint_addr, len, linux_prot, flags, -1, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = res;
    return 0;
}

int mips32_host_create_shared_mem(const char *name, size_t size,
                                   int *out_host_fd)
{
    int fd;
    char path[64];

    if (size == 0u || out_host_fd == NULL) {
        return -EINVAL;
    }
#if defined(__linux__) && defined(SYS_memfd_create)
    fd = (int)syscall((long)SYS_memfd_create,
                      (name != NULL) ? name : "mips32rt-fam", 0u);
    if (fd >= 0) {
        if (ftruncate(fd, (off_t)size) != 0) {
            int e = errno;

            (void)close(fd);
            return -e;
        }
        *out_host_fd = fd;
        return 0;
    }
#endif
    if (name != NULL) {
        (void)snprintf(path, sizeof(path), "/%s", name);
    } else {
        (void)snprintf(path, sizeof(path), "/mips32rt-fam-%d",
                       (int)getpid());
    }
    fd = shm_open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return -errno;
    }
    (void)shm_unlink(path);
    if (ftruncate(fd, (off_t)size) != 0) {
        int e = errno;

        (void)close(fd);
        return -e;
    }
    *out_host_fd = fd;
    return 0;
}

void *mips32_host_jit_alloc(size_t size)
{
    void *p;

    if (size == 0u) {
        return NULL;
    }
    p = mmap(NULL, size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        return NULL;
    }
    return p;
}

void mips32_host_jit_thread_init(void)
{
}

void mips32_host_jit_begin_write(void *buf, size_t size)
{
    (void)buf;
    (void)size;
}

int mips32_host_jit_seal_rx(void *buf, size_t size)
{
    if (mprotect(buf, size, PROT_READ | PROT_EXEC) != 0) {
        return -errno;
    }
    __builtin___clear_cache((char *)buf, (char *)buf + size);
    return 0;
}

int mips32_host_worker_sync_init(mips32_worker_sync_t *ws)
{
    int fds[2];

    if (ws == NULL) {
        return -EINVAL;
    }
    atomic_store_explicit(&ws->sig_seq, 0u, memory_order_relaxed);
    atomic_store_explicit(&ws->in_commit_window, 0u, memory_order_relaxed);
    atomic_store_explicit(&ws->ulock_wait_addr, 0u, memory_order_relaxed);
    ws->kqueue_fd = -1;
    ws->host_tid = 0u;
    if (pipe(fds) != 0) {
        return -errno;
    }
    (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    ws->wake_pipe_rd = fds[0];
    ws->wake_pipe_wr = fds[1];
    return 0;
}

void mips32_host_worker_sync_destroy(mips32_worker_sync_t *ws)
{
    if (ws == NULL) {
        return;
    }
    (void)close(ws->wake_pipe_rd);
    (void)close(ws->wake_pipe_wr);
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
}

static long host_gettid(void)
{
#if defined(__linux__) && defined(SYS_gettid)
    return syscall((long)SYS_gettid);
#else
    return (long)getpid();
#endif
}

int mips32_host_preempt_worker(uint64_t host_tid)
{
#if defined(__linux__) && defined(SYS_tgkill)
    long rc = syscall((long)SYS_tgkill, (long)getpid(), (long)host_tid,
                      (int)(SIGRTMIN + 1));

    if (rc != 0) {
        return (int)-errno;
    }
    return 0;
#else
    (void)host_tid;
    return -ENOSYS;
#endif
}

int64_t mips32_host_getdents64(int fd, void *linux_dirent64_buf,
                                size_t buf_size)
{
#if defined(__linux__) && defined(SYS_getdents64)
    long n = syscall((long)SYS_getdents64, fd, linux_dirent64_buf, buf_size);

    if (n < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)n;
#else
    (void)fd;
    (void)linux_dirent64_buf;
    (void)buf_size;
    return (int64_t)-ENOSYS;
#endif
}

int64_t mips32_host_ioctl(int fd, uint64_t linux_req, void *arg)
{
    int r = ioctl(fd, (unsigned long)linux_req, arg);

    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t mips32_host_pipe2(int fds[2], int linux_flags)
{
#if defined(__linux__)
    if (pipe2(fds, linux_flags) != 0) {
        return (int64_t)-errno;
    }
#else
    if (pipe(fds) != 0) {
        return (int64_t)-errno;
    }
    (void)linux_flags;
#endif
    return 0;
}

int64_t mips32_host_futex_wait(_Atomic uint32_t *pinned_host_uaddr,
                                const mips32_futex_key_t *key,
                                uint32_t host_endian_val,
                                const struct timespec *timeout,
                                mips32_worker_sync_t *ws,
                                uint32_t expected_seq)
{
#if defined(__linux__) && defined(SYS_futex)
    long op = 0; /* FUTEX_WAIT */
    uint32_t cur;

    (void)key;
    if (ws != NULL &&
        atomic_load_explicit(&ws->sig_seq, memory_order_acquire) !=
            expected_seq) {
        return (int64_t)-EINTR;
    }
    cur = atomic_load_explicit(pinned_host_uaddr, memory_order_acquire);
    if (cur != host_endian_val) {
        return (int64_t)-EAGAIN;
    }
    {
        long rc = syscall((long)SYS_futex, pinned_host_uaddr, op,
                          host_endian_val, timeout, NULL, 0);
        if (rc != 0) {
            return (int64_t)-errno;
        }
    }
    return 0;
#else
    (void)pinned_host_uaddr;
    (void)key;
    (void)host_endian_val;
    (void)timeout;
    (void)ws;
    (void)expected_seq;
    return (int64_t)-ENOSYS;
#endif
}

int64_t mips32_host_futex_wake(_Atomic uint32_t *pinned_host_uaddr,
                                const mips32_futex_key_t *key, int count)
{
#if defined(__linux__) && defined(SYS_futex)
    long op = 1; /* FUTEX_WAKE */
    long rc;

    (void)key;
    rc = syscall((long)SYS_futex, pinned_host_uaddr, op, count, NULL, NULL,
                 0);
    if (rc < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)rc;
#else
    (void)pinned_host_uaddr;
    (void)key;
    (void)count;
    return (int64_t)-ENOSYS;
#endif
}

int64_t mips32_host_clock_nanosleep(int linux_clk_id, int linux_flags,
                                     const struct timespec *req,
                                     struct timespec *rem,
                                     mips32_worker_sync_t *ws,
                                     uint32_t expected_seq)
{
    (void)ws;
    (void)expected_seq;
#if defined(__linux__)
    if (clock_nanosleep((clockid_t)linux_clk_id, linux_flags, req, rem) != 0) {
        return (int64_t)-errno;
    }
#else
    if (nanosleep(req, rem) != 0) {
        (void)linux_clk_id;
        (void)linux_flags;
        return (int64_t)-errno;
    }
#endif
    return 0;
}

int64_t mips32_host_tgkill(int64_t tgid, int64_t tid, int linux_sig)
{
#if defined(__linux__) && defined(SYS_tgkill)
    long rc = syscall((long)SYS_tgkill, (long)tgid, (long)tid, linux_sig);

    if (rc != 0) {
        return (int64_t)-errno;
    }
    return 0;
#else
    (void)tgid;
    (void)tid;
    (void)linux_sig;
    return (int64_t)-ENOSYS;
#endif
}

void mips32_host_exit_group(int status)
{
#if defined(__linux__) && defined(SYS_exit_group)
    (void)syscall((long)SYS_exit_group, status);
#else
    _Exit(status);
#endif
    __builtin_unreachable();
}

static mips32_host_sync_fault_fn g_on_sync = NULL;
static mips32_host_async_sig_fn g_on_async = NULL;
static mips32_host_preempt_fn g_on_preempt = NULL;

static void linux_sync_handler(int signo, siginfo_t *si, void *uc)
{
    mips32_host_sync_fault_t f;

    if (g_on_sync == NULL) {
        return;
    }
    f.linux_si_signo = (signo == SIGBUS) ? 10 : 11;
    f.linux_si_code = si->si_code;
    f.fault_addr = (uintptr_t)si->si_addr;
    f.host_pc = 0u;
    f.is_write = 0;
    f.host_ucontext = uc;
    g_on_sync(&f);
}

static void linux_preempt_handler(int signo, siginfo_t *si, void *uc)
{
    (void)signo;
    (void)si;
    if (g_on_preempt != NULL) {
        g_on_preempt(uc);
    }
}

int mips32_host_install_signal_handlers(mips32_host_sync_fault_fn on_sync,
                                         mips32_host_async_sig_fn on_async,
                                         mips32_host_preempt_fn on_preempt)
{
    struct sigaction sa;

    (void)on_async;
    g_on_sync = on_sync;
    g_on_async = on_async;
    g_on_preempt = on_preempt;
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = linux_sync_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        return -errno;
    }
    if (sigaction(SIGBUS, &sa, NULL) != 0) {
        return -errno;
    }
    (void)memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = linux_preempt_handler;
    sa.sa_flags = SA_SIGINFO;
    (void)sigemptyset(&sa.sa_mask);
#if defined(__linux__)
    (void)sigaction(SIGRTMIN + 1, &sa, NULL);
#else
    (void)sigaction(SIGUSR2, &sa, NULL);
#endif
    (void)host_gettid();
    return 0;
}
