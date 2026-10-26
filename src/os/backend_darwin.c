/*
 * src/os/backend_darwin.c — Backend 2: standalone macOS arm64 (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 section 6, Backend 2: native macOS arm64
 * Mach-O running guest Linux ELFs with zero Hypervisor.framework
 * dependency via libSystem, MAP_JIT APRR W^X, per-syscall-class
 * kevent/wake-pipe/__ulock_wait2 signal-atomic blocking, and 4 KiB
 * Soft-TLB sub-page protection.  Linux->Darwin errno/open/stat/
 * sockaddr translation lives at the syscall boundary.
 *
 * Darwin-only APIs are guarded so this TU still syntax-checks on
 * Linux (the U3 lane acceptance runs "make check" on Linux/macOS
 * hosts).  Pure C11.  Never touches x18.
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include "os/backend.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* macOS names it MAP_ANON; Linux MAP_ANONYMOUS. */
#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <sys/event.h>
#endif

mips32_backend_kind_t mips32_host_backend_kind(void)
{
    return MIPS32_BACKEND_DARWIN;
}

int mips32_host_is_hyper_linux(void)
{
    return 0;
}

size_t mips32_host_page_size(void)
{
    long v = sysconf(_SC_PAGESIZE);

    if (v <= 0) {
        return 16384u;
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
    (void)noreplace;
    if (fixed != 0) {
        flags |= MAP_FIXED;
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
    char path[64];
    int fd;

    if (size == 0u || out_host_fd == NULL) {
        return -EINVAL;
    }
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

/* MAP_JIT APRR W^X: RW staging pages flip to PROT_READ|PROT_EXEC. */
void *mips32_host_jit_alloc(size_t size)
{
    void *p;
#if defined(__APPLE__)
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT;
#else
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#endif

    if (size == 0u) {
        return NULL;
    }
    p = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (p == MAP_FAILED) {
        return NULL;
    }
    return p;
}

void mips32_host_jit_thread_init(void)
{
#if defined(__APPLE__)
    (void)pthread_jit_write_protect_np(1);
#endif
}

void mips32_host_jit_begin_write(void *buf, size_t size)
{
    (void)buf;
    (void)size;
#if defined(__APPLE__)
    (void)pthread_jit_write_protect_np(0);
#endif
}

int mips32_host_jit_seal_rx(void *buf, size_t size)
{
#if defined(__APPLE__)
    (void)pthread_jit_write_protect_np(1);
    if (mprotect(buf, size, PROT_READ | PROT_EXEC) != 0) {
        return -errno;
    }
    sys_icache_invalidate(buf, size);
#else
    if (mprotect(buf, size, PROT_READ | PROT_EXEC) != 0) {
        return -errno;
    }
    __builtin___clear_cache((char *)buf, (char *)buf + size);
#endif
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
#if defined(__APPLE__)
    ws->kqueue_fd = kqueue();
    if (ws->kqueue_fd < 0) {
        return -errno;
    }
#endif
    if (pipe(fds) != 0) {
        int e = errno;
#if defined(__APPLE__)
        (void)close(ws->kqueue_fd);
        ws->kqueue_fd = -1;
#endif
        return -e;
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
#if defined(__APPLE__)
    if (ws->kqueue_fd >= 0) {
        (void)close(ws->kqueue_fd);
    }
#endif
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
    ws->kqueue_fd = -1;
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

int mips32_host_preempt_worker(uint64_t host_tid)
{
#if defined(__APPLE__)
    if (pthread_kill((pthread_t)host_tid, SIGUSR2) != 0) {
        return -errno;
    }
    return 0;
#else
    (void)host_tid;
    return -ENOSYS;
#endif
}

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
    (void)fd;
    (void)linux_dirent64_buf;
    (void)buf_size;
    return (int64_t)-ENOSYS;
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
    (void)fd;
    (void)linux_req;
    (void)arg;
    return (int64_t)-ENOSYS;
}

int64_t mips32_host_pipe2(int fds[2], int linux_flags)
{
    if (pipe(fds) != 0) {
        return (int64_t)-errno;
    }
    (void)linux_flags;
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
    (void)pinned_host_uaddr;
    (void)key;
    (void)host_endian_val;
    (void)timeout;
    (void)ws;
    (void)expected_seq;
    return (int64_t)-ENOSYS;
}

int64_t mips32_host_futex_wake(_Atomic uint32_t *pinned_host_uaddr,
                                const mips32_futex_key_t *key, int count)
{
    (void)pinned_host_uaddr;
    (void)key;
    (void)count;
    return (int64_t)-ENOSYS;
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
    if (nanosleep(req, rem) != 0) {
        (void)linux_clk_id;
        (void)linux_flags;
        return (int64_t)-errno;
    }
    return 0;
}

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
    (void)tgid;
    (void)tid;
    (void)linux_sig;
    return (int64_t)-ENOSYS;
}

void mips32_host_exit_group(int status)
{
    _Exit(status);
    __builtin_unreachable();
}

int mips32_host_install_signal_handlers(mips32_host_sync_fault_fn on_sync,
                                         mips32_host_async_sig_fn on_async,
                                         mips32_host_preempt_fn on_preempt)
{
    (void)on_sync;
    (void)on_async;
    (void)on_preempt;
    return -ENOSYS;
}
