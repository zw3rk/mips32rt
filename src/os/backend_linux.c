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

int mips32_host_map_file(void *hint_addr, size_t len, int linux_prot,
                          int shared, int fixed, int host_fd,
                          uint64_t aligned_file_offset,
                          void **out_host_addr)
{
    int flags = 0;
    void *res;

    if (len == 0u || out_host_addr == NULL || host_fd < 0) {
        return -EINVAL;
    }
    flags |= (shared != 0) ? MAP_SHARED : MAP_PRIVATE;
    if (fixed != 0) {
        flags |= MAP_FIXED;
    }
    res = mmap(hint_addr, len, linux_prot, flags, host_fd,
               (off_t)aligned_file_offset);
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

int mips32_host_protect(void *host_addr, size_t len, int linux_prot)
{
    if (mprotect(host_addr, len, linux_prot) != 0) {
        return -errno;
    }
    return 0;
}

int mips32_host_unmap(void *host_addr, size_t len)
{
    if (munmap(host_addr, len) != 0) {
        return -errno;
    }
    return 0;
}

int mips32_host_msync(void *host_addr, size_t len, int linux_flags)
{
    int flags = 0;

    if ((linux_flags & 0x4) != 0) {
        flags |= MS_SYNC;
    }
    if ((linux_flags & 0x1) != 0) {
        flags |= MS_ASYNC;
    }
    if (flags == 0) {
        flags = MS_SYNC;
    }
    if (msync(host_addr, len, flags) != 0) {
        return -errno;
    }
    return 0;
}

int mips32_host_madvise(void *host_addr, size_t len, int linux_advice)
{
    if (madvise(host_addr, len, linux_advice) != 0) {
        return -errno;
    }
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

void mips32_host_jit_free(void *buf, size_t size)
{
    if (buf != NULL && size != 0u) {
        (void)munmap(buf, size);
    }
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

void mips32_host_worker_notify_signal(mips32_worker_sync_t *ws)
{
    uint8_t one = 1u;

    if (ws == NULL) {
        return;
    }
    (void)atomic_fetch_add_explicit(&ws->sig_seq, 1u,
                                    memory_order_acq_rel);
    (void)write(ws->wake_pipe_wr, &one, 1u);
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

/* ---- Filesystem / descriptors: libc baseline (DBT fast path uses the
 * D18 safe_syscall_a64.S gate where linked). ---- */

int64_t mips32_host_openat(int dirfd, const char *path, int linux_flags,
                            uint32_t mode, mips32_worker_sync_t *ws,
                            uint32_t expected_seq)
{
    int fd;

    (void)ws;
    (void)expected_seq;
    fd = openat(dirfd, path, linux_flags, (mode_t)mode);
    if (fd < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)fd;
}

int64_t mips32_host_close(int fd)
{
    if (close(fd) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t mips32_host_read(int fd, void *buf, size_t count,
                          mips32_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t n;

    (void)ws;
    (void)expected_seq;
    n = read(fd, buf, count);
    if (n < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)n;
}

int64_t mips32_host_write(int fd, const void *buf, size_t count,
                           mips32_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t n;

    (void)ws;
    (void)expected_seq;
    n = write(fd, buf, count);
    if (n < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)n;
}

int64_t mips32_host_pread64(int fd, void *buf, size_t count, int64_t offset)
{
    ssize_t n = pread(fd, buf, count, (off_t)offset);

    if (n < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)n;
}

int64_t mips32_host_pwrite64(int fd, const void *buf, size_t count,
                              int64_t offset)
{
    ssize_t n = pwrite(fd, buf, count, (off_t)offset);

    if (n < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)n;
}

int64_t mips32_host_lseek(int fd, int64_t offset, int linux_whence)
{
    off_t r = lseek(fd, (off_t)offset, linux_whence);

    if (r == (off_t)-1) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t mips32_host_ftruncate(int fd, int64_t length)
{
    if (ftruncate(fd, (off_t)length) != 0) {
        return (int64_t)-errno;
    }
    return 0;
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

int64_t mips32_host_fcntl(int fd, int linux_cmd, uint64_t arg)
{
    int r = fcntl(fd, linux_cmd, (long)arg);

    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
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

int64_t mips32_host_readlinkat(int dirfd, const char *path, char *buf,
                                size_t bufsiz)
{
    ssize_t n = readlinkat(dirfd, path, buf, bufsiz);

    if (n < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)n;
}

int64_t mips32_host_unlinkat(int dirfd, const char *path, int linux_flags)
{
    if (unlinkat(dirfd, path, linux_flags) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t mips32_host_getcwd(char *buf, size_t size)
{
    if (getcwd(buf, size) == NULL) {
        return (int64_t)-errno;
    }
    return 0;
}

/* ---- Networking (subset wired in U3; the rest arrives with full
 * syscall coverage). ---- */

int64_t mips32_host_socket(int linux_domain, int linux_type, int protocol)
{
    int fd = socket(linux_domain, linux_type, protocol);

    if (fd < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)fd;
}

int64_t mips32_host_connect(int fd, const void *linux_addr, uint32_t addrlen,
                             mips32_worker_sync_t *ws, uint32_t expected_seq)
{
    (void)ws;
    (void)expected_seq;
    if (connect(fd, (const struct sockaddr *)linux_addr,
                (socklen_t)addrlen) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t mips32_host_sendto(int fd, const void *buf, size_t len,
                            int linux_flags, const void *linux_dest_addr,
                            uint32_t addrlen, mips32_worker_sync_t *ws,
                            uint32_t expected_seq)
{
    ssize_t n;

    (void)ws;
    (void)expected_seq;
    n = sendto(fd, buf, len, linux_flags,
               (const struct sockaddr *)linux_dest_addr, (socklen_t)addrlen);
    if (n < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)n;
}

int64_t mips32_host_recvfrom(int fd, void *buf, size_t len, int linux_flags,
                              void *linux_src_addr_out,
                              uint32_t *addrlen_inout,
                              mips32_worker_sync_t *ws,
                              uint32_t expected_seq)
{
    ssize_t n;

    (void)ws;
    (void)expected_seq;
    n = recvfrom(fd, buf, len, linux_flags,
                 (struct sockaddr *)linux_src_addr_out,
                 (socklen_t *)addrlen_inout);
    if (n < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)n;
}

int64_t mips32_host_ppoll(void *linux_pollfds, size_t nfds,
                           const struct timespec *rel_timeout,
                           const uint64_t *linux_sigmask,
                           mips32_worker_sync_t *ws, uint32_t expected_seq)
{
    (void)linux_pollfds;
    (void)nfds;
    (void)rel_timeout;
    (void)linux_sigmask;
    (void)ws;
    (void)expected_seq;
    return (int64_t)-ENOSYS;
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

int64_t mips32_host_clock_gettime(int linux_clk_id, struct timespec *tp)
{
    if (clock_gettime((clockid_t)linux_clk_id, tp) != 0) {
        return (int64_t)-errno;
    }
    return 0;
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

/* ---- Process / signals. ---- */

int mips32_host_worker_altstack_init(void **out_stack_mem,
                                      size_t *out_stack_size)
{
    void *p;

    if (out_stack_mem == NULL || out_stack_size == NULL) {
        return -EINVAL;
    }
    p = malloc(64u * 1024u);
    if (p == NULL) {
        return -ENOMEM;
    }
    *out_stack_mem = p;
    *out_stack_size = 64u * 1024u;
    return 0;
}

void mips32_host_worker_altstack_destroy(void *stack_mem, size_t stack_size)
{
    (void)stack_size;
    free(stack_mem);
}

int64_t mips32_host_fork(void)
{
    pid_t p = fork();

    if (p < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)p;
}

int64_t mips32_host_wait4(int64_t pid, int *linux_status_out,
                           int linux_options,
                           mips32_worker_sync_t *ws, uint32_t expected_seq)
{
    pid_t r;

    (void)ws;
    (void)expected_seq;
    r = waitpid((pid_t)pid, linux_status_out, linux_options);
    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
}

int64_t mips32_host_kill(int64_t pid, int linux_sig)
{
    if (kill((pid_t)pid, linux_sig) != 0) {
        return (int64_t)-errno;
    }
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
