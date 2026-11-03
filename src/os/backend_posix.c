/*
 * src/os/backend_posix.c — Shared POSIX host wrappers for Linux & Darwin backends
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include "os/backend.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

void mips32_host_jit_free(void *buf, size_t size)
{
    if (buf != NULL && size != 0u) {
        (void)munmap(buf, size);
    }
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

int64_t mips32_host_fcntl(int fd, int linux_cmd, uint64_t arg)
{
    int r = fcntl(fd, linux_cmd, (long)arg);

    if (r < 0) {
        return (int64_t)-errno;
    }
    return (int64_t)r;
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

int64_t mips32_host_clock_gettime(int linux_clk_id, struct timespec *tp)
{
    if (clock_gettime((clockid_t)linux_clk_id, tp) != 0) {
        return (int64_t)-errno;
    }
    return 0;
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
