/*
 * src/os/backend.h — Complete Host OS Backend Interface (Wave U3, Rev 4)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 section 6 (frozen for Waves U1-U3):
 * every <arch>rt builds two zero-dependency artifacts from this
 * interface — Backend 1 (_build/<arch>rt-linux-aarch64 via
 * backend_linux.c: static-PIE aarch64-linux musl ELF) and Backend 2
 * (_build/<arch>rt-darwin-arm64 via backend_darwin.c: native macOS
 * arm64 Mach-O with zero Hypervisor.framework dependency).
 *
 * Groups: (1) identity + dynamic host page size, (2) host memory
 * primitives for src/vm/vm32.c, (3) JIT W^X code cache, (4)
 * per-syscall-class race-free blocking + worker preemption
 * (astra#xhigh #13, fable C3/M10), (5) filesystem/descriptors,
 * (6) networking/multiplexing, (7) futex keying/pinning/admission
 * (astra#xhigh #11), (8) process/thread/signal delivery.
 */

#ifndef MIPS32RT_OS_BACKEND_H
#define MIPS32RT_OS_BACKEND_H

#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

typedef enum {
    MIPS32_BACKEND_LINUX = 1, /* static-PIE aarch64-linux (native or hl) */
    MIPS32_BACKEND_DARWIN = 2 /* standalone macOS arm64 Mach-O (libSystem) */
} mips32_backend_kind_t;

/* 1. Backend identity & dynamic host page size (never hardcoded). */
mips32_backend_kind_t mips32_host_backend_kind(void);
int mips32_host_is_hyper_linux(void);
/* 4096, 16384, or 65536 via sysconf(_SC_PAGESIZE) on both hosts. */
size_t mips32_host_page_size(void);

/* 2. Low-level host memory primitives consumed by src/vm/vm32.c. */
int mips32_host_map_anon(void *hint_addr, size_t len, int linux_prot,
                          int fixed, int noreplace, void **out_host_addr);
int mips32_host_map_file(void *hint_addr, size_t len, int linux_prot,
                          int shared, int fixed, int host_fd,
                          uint64_t aligned_file_offset,
                          void **out_host_addr);
int mips32_host_create_shared_mem(const char *name, size_t size,
                                   int *out_host_fd);
int mips32_host_protect(void *host_addr, size_t len, int linux_prot);
int mips32_host_unmap(void *host_addr, size_t len);
int mips32_host_msync(void *host_addr, size_t len, int linux_flags);
int mips32_host_madvise(void *host_addr, size_t len, int linux_advice);

/* 3. JIT W^X code-cache allocation & thread-local APRR publication. */
void *mips32_host_jit_alloc(size_t size);
void mips32_host_jit_thread_init(void);
void mips32_host_jit_begin_write(void *buf, size_t size);
int mips32_host_jit_seal_rx(void *buf, size_t size);
void mips32_host_jit_free(void *buf, size_t size);

/*
 * 4. Per-syscall-class race-free signal-atomic blocking & preemption:
 * Linux routes blocking syscalls through safe_syscall_a64.S; Darwin
 * multiplexes readiness via kevent/poll on {target_fd, wake_pipe_rd}
 * before non-blocking I/O, checks sig_seq under the futex bucket lock
 * and sleeps via __ulock_wait2, and waits on kqueue for wait/sleep.
 */
typedef struct {
    _Atomic uint32_t sig_seq;
    _Atomic uint32_t in_commit_window;
    _Atomic uintptr_t ulock_wait_addr;
    int kqueue_fd;
    int wake_pipe_rd;
    int wake_pipe_wr;
    uint64_t host_tid;
} mips32_worker_sync_t;

int mips32_host_worker_sync_init(mips32_worker_sync_t *ws);
void mips32_host_worker_sync_destroy(mips32_worker_sync_t *ws);
void mips32_host_worker_notify_signal(mips32_worker_sync_t *ws);
/* Reserved preemption signal: SIGRTMIN+1 via tgkill (Linux),
 * SIGUSR2 via pthread_kill (Darwin). */
int mips32_host_preempt_worker(uint64_t host_tid);

/* 5. Filesystem & descriptor operations (blocking calls take ws). */
int64_t mips32_host_openat(int dirfd, const char *path, int linux_flags,
                            uint32_t mode, mips32_worker_sync_t *ws,
                            uint32_t expected_seq);
int64_t mips32_host_close(int fd);
int64_t mips32_host_read(int fd, void *buf, size_t count,
                          mips32_worker_sync_t *ws, uint32_t expected_seq);
int64_t mips32_host_write(int fd, const void *buf, size_t count,
                           mips32_worker_sync_t *ws, uint32_t expected_seq);
int64_t mips32_host_pread64(int fd, void *buf, size_t count, int64_t offset);
int64_t mips32_host_pwrite64(int fd, const void *buf, size_t count,
                              int64_t offset);
int64_t mips32_host_lseek(int fd, int64_t offset, int linux_whence);
int64_t mips32_host_ftruncate(int fd, int64_t length);
int64_t mips32_host_getdents64(int fd, void *linux_dirent64_buf,
                                size_t buf_size);
int64_t mips32_host_fcntl(int fd, int linux_cmd, uint64_t arg);
int64_t mips32_host_ioctl(int fd, uint64_t linux_req, void *arg);
int64_t mips32_host_pipe2(int fds[2], int linux_flags);
int64_t mips32_host_readlinkat(int dirfd, const char *path, char *buf,
                                size_t bufsiz);
int64_t mips32_host_unlinkat(int dirfd, const char *path, int linux_flags);
int64_t mips32_host_getcwd(char *buf, size_t size);

/* 6. Networking & I/O multiplexing. */
int64_t mips32_host_socket(int linux_domain, int linux_type, int protocol);
int64_t mips32_host_connect(int fd, const void *linux_addr, uint32_t addrlen,
                             mips32_worker_sync_t *ws, uint32_t expected_seq);
int64_t mips32_host_sendto(int fd, const void *buf, size_t len,
                            int linux_flags, const void *linux_dest_addr,
                            uint32_t addrlen, mips32_worker_sync_t *ws,
                            uint32_t expected_seq);
int64_t mips32_host_recvfrom(int fd, void *buf, size_t len, int linux_flags,
                              void *linux_src_addr_out,
                              uint32_t *addrlen_inout,
                              mips32_worker_sync_t *ws,
                              uint32_t expected_seq);
int64_t mips32_host_ppoll(void *linux_pollfds, size_t nfds,
                           const struct timespec *rel_timeout,
                           const uint64_t *linux_sigmask,
                           mips32_worker_sync_t *ws, uint32_t expected_seq);

/* 7. Canonical futex key, backing pinning & lock-order-safe admission:
 * pin (promote COW_CLEAN->DIRTY, bump futex_pin_count, compute
 * mips32_futex_key_t, convert to host endianness) under a short VM
 * lease BEFORE the bucket lock (Rank 1 mmap -> Rank 7 bucket safe). */
typedef enum {
    MIPS32_FUTEX_PRIVATE = 1,
    MIPS32_FUTEX_SHARED_ANON = 2,
    MIPS32_FUTEX_SHARED_FILE = 3
} mips32_futex_key_kind_t;

typedef struct {
    uint32_t kind;
    uint32_t reserved;
    uint64_t owner_id;
    uint64_t mount_id;
    uint64_t offset;
} mips32_futex_key_t;

int64_t mips32_host_futex_wait(_Atomic uint32_t *pinned_host_uaddr,
                                const mips32_futex_key_t *key,
                                uint32_t host_endian_val,
                                const struct timespec *timeout,
                                mips32_worker_sync_t *ws,
                                uint32_t expected_seq);
int64_t mips32_host_futex_wake(_Atomic uint32_t *pinned_host_uaddr,
                                const mips32_futex_key_t *key, int count);
int64_t mips32_host_clock_gettime(int linux_clk_id, struct timespec *tp);
int64_t mips32_host_clock_nanosleep(int linux_clk_id, int linux_flags,
                                     const struct timespec *req,
                                     struct timespec *rem,
                                     mips32_worker_sync_t *ws,
                                     uint32_t expected_seq);

/* 8. Process, thread, and sync/async signal delivery. */
int64_t mips32_host_fork(void);
int64_t mips32_host_wait4(int64_t pid, int *linux_status_out,
                           int linux_options,
                           mips32_worker_sync_t *ws, uint32_t expected_seq);
int64_t mips32_host_kill(int64_t pid, int linux_sig);
int64_t mips32_host_tgkill(int64_t tgid, int64_t tid, int linux_sig);
void mips32_host_exit_group(int status) __attribute__((noreturn));

typedef struct {
    int linux_si_signo;
    int linux_si_code;
    uintptr_t fault_addr;
    uintptr_t host_pc;
    int is_write;
    void *host_ucontext;
} mips32_host_sync_fault_t;

typedef struct {
    int linux_si_signo;
    int linux_si_code;
    int32_t sender_pid;
    uint32_t sender_uid;
} mips32_host_async_siginfo_t;

typedef void (*mips32_host_sync_fault_fn)(const mips32_host_sync_fault_t *f);
typedef void (*mips32_host_async_sig_fn)(const mips32_host_async_siginfo_t *s);
typedef void (*mips32_host_preempt_fn)(void *host_ucontext);

int mips32_host_install_signal_handlers(mips32_host_sync_fault_fn on_sync,
                                         mips32_host_async_sig_fn on_async,
                                         mips32_host_preempt_fn on_preempt);

#endif /* MIPS32RT_OS_BACKEND_H */
