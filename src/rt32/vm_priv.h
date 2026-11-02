/*
 * src/rt32/vm_priv.h — Private sharing between vm.c and vm_mmap.c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Not part of the rt32 public interface (rt32.h); declares the VMA-table
 * internals owned by vm.c that vm_mmap.c needs.  Every guest mapping
 * mutation still funnels through the D19 CLONE_VM lock (vm_lock_*).
 */

#ifndef RT32_VM_PRIV_H
#define RT32_VM_PRIV_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"

#define RT32_WINDOW_SIZE         0x100000000ULL
#define RT32_MMAP_BASE_32        0x40000000U
#define RT32_MMAP_TOP_32         0x70000000U
#define RT32_MAP_FIXED           0x10U
#define RT32_MAP_ANONYMOUS       0x20U
#define RT32_MAP_FIXED_NOREPLACE 0x100000U
#define RT32_MREMAP_MAYMOVE      1U
#define RT32_MREMAP_FIXED        2U

/* D19 CLONE_VM page-table lock (defined in vm.c). */
extern _Atomic uint32_t g_vm_lock;
/* VMA generation + brk state (defined in vm.c; mutated under the lock). */
extern _Atomic uint64_t g_vm_gen;
extern uint32_t g_vm_brk_base;
extern uint32_t g_vm_brk_curr;
/* Bottom-up mmap cursor (defined in vm.c; mutated under the lock). */
extern uint32_t g_vm_mmap_cursor;
void vm_lock_acquire(void);
void vm_lock_release(void);

uint64_t vm_page_align_up(uint64_t v);
int      vm_reserve_prot_none(mips32_ctx_t *ctx, uint32_t start, uint32_t len);
void     vm_invalidate_jit(mips32_ctx_t *ctx, uint32_t start, uint32_t end);

/* ctx <-> authoritative-table mirrors (defined in vm.c). */
void vm_sync_from_ctx(mips32_ctx_t *ctx);
void vm_sync_brk_to_ctx(mips32_ctx_t *ctx);
void vm_copy_state_to_ctx(mips32_ctx_t *dst);
void vm_sync_to_ctx(mips32_ctx_t *ctx);
/* Host-page protection union + restore (defined in vm.c). */
int  vm_union_host_prot_locked(uint32_t start, uint32_t end);
void vm_host_restore_locked(uint32_t start, uint32_t end);
/* Coordinated fork stages (defined in vm.c). */
void vm_fork_prepare(void);
void vm_fork_release(void);
/* LL/SC-aware bulk guest store (defined in src/os/mem.c): data write
 * plus epoch/reservation update under one LL critical section.  Call
 * with g_vm_lock held (VM outer, LL inner); src must be non-NULL. */
void mips_guest_store_commit(mips32_ctx_t *ctx, uint32_t va,
                             const void *src, uint32_t len);

/* Per-region file-backing metadata (M32-3, M32-4, M32-R2-2). */
typedef struct {
    int      fd;        /* retained dup'd fd for file mappings, or -1 */
    uint64_t file_off;  /* byte offset in fd at region->start */
    uint64_t dev;       /* st_dev when fd >= 0 */
    uint64_t ino;       /* st_ino when fd >= 0 */
    uint8_t  darw_sync; /* 1 when Darwin sub-16KiB MAP_SHARED needs writeback */
} vm_backing_t;

extern mips32_ctx_t   *g_vm_root_ctx;
extern mips32_region_t g_vm_regions[MIPS32_MAX_REGIONS];
extern vm_backing_t    g_vm_backing[MIPS32_MAX_REGIONS];
extern size_t          g_vm_region_count;

/* Locked VMA-table primitives (defined in vm.c; caller holds the lock). */
void vm_remove_region_at(size_t idx);
int  vm_insert_region_raw(uint32_t start, uint32_t end, uint32_t prot,
                          uint32_t flags, const char *name);
int  vm_insert_region_backed(uint32_t start, uint32_t end, uint32_t prot,
                             uint32_t flags, const char *name,
                             vm_backing_t back);
void vm_coalesce_regions_locked(void);
int  vm_can_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end,
                                 size_t extra_insert);
int  vm_flush_darw_range_locked(uint32_t start, uint32_t end);
void vm_flush_darw_inode_locked(uint64_t dev, uint64_t ino);
/* Temporary host-prot elevation (defined in vm_darw.c). */
void vm_host_temp_prot(uint32_t start, uint32_t end, int prot);
void vm_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end);
int  vm_record_region_locked(uint32_t start, uint32_t end, uint32_t prot,
                             uint32_t flags, const char *name);
int  vm_record_region_backed_locked(uint32_t start, uint32_t end, uint32_t prot,
                                    uint32_t flags, const char *name,
                                    vm_backing_t back);
int  vm_can_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot);
void vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot);
bool vm_range_overlaps_locked(uint32_t start, uint32_t end);
bool vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                  uint32_t *out_prot, uint32_t *out_flags,
                                  char *out_name, size_t name_sz,
                                  vm_backing_t *out_back);
int  vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va);

#endif /* RT32_VM_PRIV_H */
