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
void vm_sync_to_ctx(mips32_ctx_t *ctx);

/* Locked VMA-table primitives (defined in vm.c; caller holds the lock). */
void vm_remove_region_at(size_t idx);
int  vm_insert_region_raw(uint32_t start, uint32_t end, uint32_t prot,
                          uint32_t flags, const char *name);
void vm_coalesce_regions_locked(void);
void vm_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end);
int  vm_record_region_locked(uint32_t start, uint32_t end, uint32_t prot,
                             uint32_t flags, const char *name);
void vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot);
bool vm_range_overlaps_locked(uint32_t start, uint32_t end);
bool vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                  uint32_t *out_prot, uint32_t *out_flags,
                                  char *out_name, size_t name_sz);
int  vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va);

#endif /* RT32_VM_PRIV_H */
