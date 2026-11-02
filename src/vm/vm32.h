/*
 * src/vm/vm32.h — Two-regime Class-A 32-bit VM + Soft-TLB + recovery records
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wave U3 (UNIFICATION-PLAN.md Rev 4, sections 4.3-4.6, 5.1, 6, 7):
 * Regime A1 (H == 4096: 1-instruction [x20, wAddr, uxtw] over a
 * MAP_PRIVATE 4 GiB window [G, G+4GiB)) vs Regime A2 (H > 4096:
 * 7-instruction Soft-TLB with x20 = &ctx->tlb[0] over a MAP_PRIVATE
 * arena with union host protections).  Pure C11; never touches x18.
 *
 * The 32-byte Soft-TLB entry, the 24-byte relative dbt_mem_site_t, and
 * the rt_npc_mode_t (including RT_NPC_DYNAMIC_CTX for MIPS JR/JALR)
 * match UNIFICATION-PLAN.md section 4.3 exactly so AOT payloads
 * (src/dbt/aot/) serialize them verbatim.
 */

#ifndef MIPS32RT_VM32_H
#define MIPS32RT_VM32_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"

/* ---- Soft-TLB geometry (UNIFICATION-PLAN.md 4.3) ---- */

#define MIPS32_TLB_BITS 12u
#define MIPS32_TLB_SIZE (1u << MIPS32_TLB_BITS) /* 4096 entries */
#define MIPS32_TLB_INVALID_TAG (~UINT64_C(0))   /* low 12 bits 0xFFF: no match */

typedef struct {
    uint64_t read_tag;       /* (gva & ~0xFFF) when readable & < EOF, else ~0 */
    uintptr_t addend;        /* host_page_base - (gva & ~0xFFF) */
    uint64_t write_tag;      /* (gva & ~0xFFF) when writable & promoted & */
                             /* !has_code & !has_reservation, else ~0 */
    uint64_t flags_reserved; /* zero; keeps 32-byte cache alignment */
} mips32_tlb_entry_t;

_Static_assert(sizeof(mips32_tlb_entry_t) == 32,
               "Soft-TLB entry must be 32 bytes");

/* ---- Guest PC recovery modes (UNIFICATION-PLAN.md 4.3) ---- */

typedef enum {
    MIPS32_NPC_SEQUENTIAL = 0, /* guest_npc = guest_pc + insn_len */
    MIPS32_NPC_STATIC_TARGET = 1, /* guest_npc = block_base + site->npc_delta */
    MIPS32_NPC_DYNAMIC_CTX = 2 /* guest_npc = ctx->delay_target (JR/JALR) */
} mips32_npc_mode_t;

/*
 * Purely relative 24-byte site record: serialized verbatim into AOT
 * block payloads, so no absolute host or guest addresses may appear.
 */
typedef struct {
    uint16_t seq_start_offset;  /* .L_tlb_seq_start_k (ubfx) byte offset */
    uint16_t host_insn_offset;  /* .L_tlb_mem_insn_k (ldr/str) byte offset */
    uint16_t cont_insn_offset;  /* .L_tlb_cont_k byte offset */
    uint16_t guest_pc_delta;    /* faulting guest PC minus block guest base */
    int32_t npc_delta;          /* static target delta (NPC_STATIC_TARGET) */
    uint32_t insn_word;         /* raw guest instruction word */
    int16_t sp_rollback_delta;  /* pre-store base-reg adjustment to undo */
    uint8_t npc_mode;           /* mips32_npc_mode_t */
    uint8_t width;              /* 1, 2, 4, 8, or 16 */
    uint8_t flags;              /* STORE | SIGNED | BE | IN_DELAY_SLOT */
    uint8_t val_or_dst_reg;     /* arch/host reg index for store val / load dst */
    uint8_t addr_base_reg;      /* arch base reg index when rollback != 0 */
    uint8_t reserved;
} mips32_mem_site_t;

_Static_assert(sizeof(mips32_mem_site_t) == 24,
               "dbt_mem_site_t must be 24 bytes");

/* Site flag bits. */
#define MIPS32_SITE_STORE         0x01u
#define MIPS32_SITE_SIGNED        0x02u
#define MIPS32_SITE_BE            0x04u
#define MIPS32_SITE_IN_DELAY_SLOT 0x08u
#define MIPS32_SITE_PRE_COMMIT_SP 0x10u

/* ---- VM regimes (UNIFICATION-PLAN.md 4.6) ---- */

#define MIPS32_VM_REGIME_UNSET 0u
#define MIPS32_VM_REGIME_A1    1u /* H == 4096: direct [x20, wAddr, uxtw] */
#define MIPS32_VM_REGIME_A2    2u /* H > 4096: Soft-TLB over MAP_PRIVATE arena */

/* Linux MIPS sysmips(2) command for address-error fixing control. */
#define MIPS32_SYSMIPS_FIXADE 7 /* MIPS_FIXADE (Linux sys/sysmips.h) */

/* ---- VM lifecycle (src/vm/vm32.c) ---- */

/* Pick A1 vs A2 from the host page size H (4096 -> A1, else A2). */
uint32_t mips32_vm_regime_for_host(size_t host_page_size);

/* Select the regime, reserve the arena/window, allocate the A2 TLB. */
int mips32_vm32_init(mips32_ctx_t *ctx);

/* Release the A2 TLB allocation (window reservation lives with rt32). */
void mips32_vm32_fini(mips32_ctx_t *ctx);

/* Slow-path miss helper shared by DBT per-site stubs and the interp. */
int mips32_vm_tlb_miss(mips32_ctx_t *ctx, uint32_t gva, int is_write,
                       uint32_t width);

/* Invalidate TLB entries and DBT blocks overlapping [start, end). */
void mips32_vm_invalidate_range(mips32_ctx_t *ctx, uint32_t start,
                                uint32_t end);

/* ---- TIF_FIXADE unaligned-access control (src/vm/vm32.c) ---- */

/* Default-on (Linux MIPS TIF_FIXADE): call once per fresh context. */
void mips32_fixade_init(mips32_ctx_t *ctx);
/* sysmips(MIPS_FIXADE, arg): arg==0 disables, nonzero enables. */
int32_t mips32_fixade_sysmips(mips32_ctx_t *ctx, uint32_t arg);

#endif /* MIPS32RT_VM32_H */
