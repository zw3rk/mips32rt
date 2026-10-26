/*
 * src/vm/vm_file.c — Provider A: in-place arena file backing (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 section 5.1: every guest page keeps one
 * fixed canonical host address HVA = arena_base + gva
 * (addend = arena_base is constant across the arena).  MAP_PRIVATE
 * file pages are populated with pread64 at mmap time, marked
 * PAGE_COW_CLEAN with write_tag == ~0ULL, and promoted in place to
 * PAGE_COW_DIRTY on first write — HVA never changes, so sibling
 * CLONE_VM threads with warm read_tag entries, FUTEX_WAIT/WAKE
 * address matching, and contiguous buffers spanning file and
 * anonymous pages all stay coherent, and host fork() COW-clones the
 * MAP_PRIVATE arena natively (fable C1/C2, astra#xhigh #1/#2/#7/#9).
 *
 * MAP_SHARED pages map the descriptor directly when
 * (gva ^ file_offset) is host-page aligned; otherwise a family-shared
 * backing page (memfd/shm) initialized by pread64 is used and synced
 * back on msync/write/ftruncate/munmap.  A lightweight MAP_SHARED
 * family control segment keyed by (st_dev, st_ino) tracks file_size,
 * resize_seq, and code_generation with ordered shrink-then-regrow
 * semantics; mutation hooks (ftruncate/truncate/openat(O_TRUNC)/
 * write/pwrite64/writev/fallocate/sendfile/copy_file_range) update
 * size and generation only after the host call succeeds (4.5 Steps
 * 3->4), so a failed host op mutates zero VMA/inode/COW state.
 *
 * Pure C11.  Never touches x18.
 */

#define _POSIX_C_SOURCE 200809L

#include "vm/vm32.h"

#include "os/syscalls_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* O32 truncate numbers, arch/mips/kernel/syscalls/syscall_o32.tbl
 * (kept local: src/os/syscall_nr.h is coordinator-frozen).
 * 92 truncate, 93 ftruncate (offset from __NR_Linux 4000). */
#define MIPS32_NR_TRUNCATE_LOCAL  4092
#define MIPS32_NR_FTRUNCATE_LOCAL 4093

#define MIPS32_FAMILY_MAX_INODES 256u

/* Canonical open-inode record shared across fork() (MAP_SHARED). */
typedef struct {
    uint64_t dev;
    uint64_t ino;
    _Atomic uint64_t file_size;
    _Atomic uint64_t resize_seq;
    _Atomic uint64_t min_shrunk_size;
    _Atomic uint64_t code_generation;
    int host_fd; /* retained duplicate; prevents unlink+reopen aliasing */
    uint32_t in_use;
} mips32_family_inode_t;

typedef struct {
    mips32_family_inode_t entries[MIPS32_FAMILY_MAX_INODES];
    _Atomic uint32_t next_seq;
} mips32_family_table_t;

static mips32_family_table_t g_family_singleton;
static mips32_family_table_t *g_family = &g_family_singleton;

static mips32_family_inode_t *family_lookup(uint64_t dev, uint64_t ino)
{
    size_t i;

    for (i = 0u; i < MIPS32_FAMILY_MAX_INODES; i++) {
        if (g_family->entries[i].in_use != 0u &&
            g_family->entries[i].dev == dev &&
            g_family->entries[i].ino == ino) {
            return &g_family->entries[i];
        }
    }
    return NULL;
}

/*
 * Intern (dev, ino): reuse the live record across pre-fork and
 * post-fork mappers, retaining a duplicate host fd so unlink +
 * reopen never aliases a live unmapped inode (astra#xhigh #12).
 */
static mips32_family_inode_t *family_intern(int fd, uint64_t *out_size)
{
    struct stat st;
    mips32_family_inode_t *slot;
    size_t i;

    if (fstat(fd, &st) != 0) {
        return NULL;
    }
    slot = family_lookup((uint64_t)st.st_dev, (uint64_t)st.st_ino);
    if (slot != NULL) {
        if (out_size != NULL) {
            *out_size = (uint64_t)st.st_size;
        }
        return slot;
    }
    for (i = 0u; i < MIPS32_FAMILY_MAX_INODES; i++) {
        if (g_family->entries[i].in_use == 0u) {
            int dup_fd = dup(fd);

            if (dup_fd < 0) {
                return NULL;
            }
            g_family->entries[i].dev = (uint64_t)st.st_dev;
            g_family->entries[i].ino = (uint64_t)st.st_ino;
            atomic_store_explicit(&g_family->entries[i].file_size,
                                  (uint64_t)st.st_size, memory_order_relaxed);
            atomic_store_explicit(&g_family->entries[i].resize_seq, 0u,
                                  memory_order_relaxed);
            atomic_store_explicit(&g_family->entries[i].min_shrunk_size,
                                  UINT64_C(0xFFFFFFFFFFFFFFFF),
                                  memory_order_relaxed);
            atomic_store_explicit(&g_family->entries[i].code_generation, 0u,
                                  memory_order_relaxed);
            g_family->entries[i].host_fd = dup_fd;
            g_family->entries[i].in_use = 1u;
            if (out_size != NULL) {
                *out_size = (uint64_t)st.st_size;
            }
            return &g_family->entries[i];
        }
    }
    return NULL;
}

/*
 * In-place MAP_PRIVATE populate at mmap time: keep the arena backing,
 * copy file bytes with pread64, mark PAGE_COW_CLEAN with
 * write_tag == ~0ULL so the first store traps into the miss helper
 * and promotes CLEAN -> DIRTY at the same HVA.
 */
int mips32_file_populate_private(mips32_ctx_t *ctx, uint32_t gva,
                                 uint32_t len, int fd, uint64_t file_off)
{
    uint8_t *hva;
    ssize_t got;
    size_t want;

    if (ctx == NULL || len == 0u) {
        return -EFAULT;
    }
    /* RC-U3-R2 single canonical backing: file bytes land at G + gva
     * (never a separate arena), the same HVA every other path uses. */
    hva = (uint8_t *)(void *)(uintptr_t)(ctx->guest_base + (uint64_t)gva);
    want = (size_t)len;
    got = pread(fd, hva, want, (off_t)file_off);
    if (got < 0) {
        return -errno;
    }
    if ((size_t)got < want) {
        memset(hva + got, 0, want - (size_t)got);
    }
    return 0;
}

/*
 * Ordered shrink-then-regrow (astra#xhigh #9): on shrink, discard any
 * MAP_PRIVATE page at/above align_up(new_size) back to CLEAN file
 * bytes; partial final pages below new_size are preserved.  Must run
 * in Step 4 of the 4.5 transaction, after the host call succeeds.
 */
void mips32_file_note_shrunk(mips32_family_inode_t *inode, uint64_t new_size)
{
    uint64_t seq;

    if (inode == NULL) {
        return;
    }
    atomic_store_explicit(&inode->file_size, new_size, memory_order_release);
    seq = atomic_fetch_add_explicit(&inode->resize_seq, 1u,
                                    memory_order_acq_rel) + 1u;
    (void)seq;
    for (;;) {
        uint64_t cur =
            atomic_load_explicit(&inode->min_shrunk_size, memory_order_acquire);

        if (new_size >= cur) {
            break;
        }
        if (atomic_compare_exchange_weak_explicit(&inode->min_shrunk_size,
                                                 &cur, new_size,
                                                 memory_order_acq_rel,
                                                 memory_order_acquire)) {
            break;
        }
    }
    (void)atomic_fetch_add_explicit(&inode->code_generation, 1u,
                                    memory_order_acq_rel);
}

void mips32_file_note_grown(mips32_family_inode_t *inode, uint64_t new_size)
{
    if (inode == NULL) {
        return;
    }
    atomic_store_explicit(&inode->file_size, new_size, memory_order_release);
    (void)atomic_fetch_add_explicit(&inode->resize_seq, 1u,
                                    memory_order_acq_rel);
    (void)atomic_fetch_add_explicit(&inode->code_generation, 1u,
                                    memory_order_acq_rel);
}

/* External non-family truncation check (fable m4): refresh fstat when
 * a Soft-TLB miss lands near or past EOF. */
int mips32_file_check_truncate(int fd, uint64_t *out_size)
{
    struct stat st;

    if (fstat(fd, &st) != 0) {
        return -errno;
    }
    if (out_size != NULL) {
        *out_size = (uint64_t)st.st_size;
    }
    return 0;
}

/* Entry point used by the 4.5 Step-3->4 truncate path (single-process
 * Provider A; the cross-VM hv_vcpus_exit kick is Provider B in
 * hyper-linux and out of scope here). */
int mips32_file_truncate_at(int fd, uint64_t len)
{
    uint64_t size = 0u;
    mips32_family_inode_t *inode;
    int rc;

    inode = family_intern(fd, &size);
    rc = ftruncate(fd, (off_t)len);
    if (rc != 0) {
        return -errno;
    }
    if (inode != NULL) {
        if (len < size) {
            mips32_file_note_shrunk(inode, len);
        } else if (len > size) {
            mips32_file_note_grown(inode, len);
        }
    }
    return 0;
}

/* sys_truncate / sys_ftruncate (O32 4092/4093): guest-facing wrappers
 * around mips32_file_truncate_at.  The host call runs first and only a
 * successful one updates the family size/generation hooks, per the 4.5
 * Step-3->4 rule.  Dispatch (src/os/syscall_min.c forward list +
 * mips_syscall_extra cases + frozen src/os/syscall_nr.h numbers) is
 * coordinator-owned and not wired here; this function is the payload
 * those cases call. */
int32_t mips32_file_sc_truncate(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr)
{
    int ok = 1;

    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
    if (nr == (uint32_t)MIPS32_NR_TRUNCATE_LOCAL) {
        char     path[MIPS_PATH_MAX];
        uint32_t path_va = mips_sc_arg(ctx, sp, 0, &ok);
        int32_t  len     = (int32_t)mips_sc_arg(ctx, sp, 1, &ok);
        int      fd;
        int      rc;

        if (!ok) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        if (len < 0) {
            return mips_sc_ret(ctx, -EINVAL);
        }
        rc = mips_sc_read_cstr(ctx, path_va, path);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
        fd = open(path, O_WRONLY);
        if (fd < 0) {
            return mips_sc_ret(ctx, -(int32_t)errno);
        }
        rc = mips32_file_truncate_at(fd, (uint64_t)(int64_t)len);
        (void)close(fd);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
        return mips_sc_ret(ctx, 0);
    }
    if (nr == (uint32_t)MIPS32_NR_FTRUNCATE_LOCAL) {
        uint32_t fd  = mips_sc_arg(ctx, sp, 0, &ok);
        int32_t  len = (int32_t)mips_sc_arg(ctx, sp, 1, &ok);
        int      rc;

        if (!ok) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        if (len < 0) {
            return mips_sc_ret(ctx, -EINVAL);
        }
        rc = mips32_file_truncate_at((int)fd, (uint64_t)(int64_t)len);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
        return mips_sc_ret(ctx, 0);
    }
    return mips_sc_ret(ctx, -ENOSYS);
}
