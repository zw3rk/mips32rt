/*
 * src/mips32rt.h — Core context, constants, and module interfaces for mips32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0 freeze (SPEC 2.1): the layout of the first 448 bytes of
 * mips32_ctx_t is ABI-locked for the future DBT trampoline (Phase 2) and
 * the a64 emitter.  Fields after the fpr array are C-only and may be
 * extended at the tail between phases; never inside the locked prefix.
 */

#ifndef MIPS32RT_H
#define MIPS32RT_H

#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "a32host.h" /* vendored, byte-identical to i686rt/a32rt (D14) */

/* MIPS32 GPR indices in architectural numbering. */
#define MIPS32_REG_ZERO 0U
#define MIPS32_REG_AT   1U
#define MIPS32_REG_V0   2U
#define MIPS32_REG_V1   3U
#define MIPS32_REG_A0   4U
#define MIPS32_REG_A1   5U
#define MIPS32_REG_A2   6U
#define MIPS32_REG_A3   7U
#define MIPS32_REG_T0   8U
#define MIPS32_REG_T1   9U
#define MIPS32_REG_T2   10U
#define MIPS32_REG_T3   11U
#define MIPS32_REG_T4   12U
#define MIPS32_REG_T5   13U
#define MIPS32_REG_T6   14U
#define MIPS32_REG_T7   15U
#define MIPS32_REG_S0   16U
#define MIPS32_REG_S1   17U
#define MIPS32_REG_S2   18U
#define MIPS32_REG_S3   19U
#define MIPS32_REG_S4   20U
#define MIPS32_REG_S5   21U
#define MIPS32_REG_S6   22U
#define MIPS32_REG_S7   23U
#define MIPS32_REG_T8   24U
#define MIPS32_REG_T9   25U
#define MIPS32_REG_K0   26U
#define MIPS32_REG_K1   27U
#define MIPS32_REG_GP   28U
#define MIPS32_REG_SP   29U
#define MIPS32_REG_FP   30U
#define MIPS32_REG_RA   31U

/* CP0 UserLocal register number read by RDHWR (SPEC 2.2). */
#define MIPS32_RDHWR_ULR 29U

/* Engine exit reasons (engines return to the dispatcher via exit_reason). */
#define MIPS32_EXIT_NONE        0U
#define MIPS32_EXIT_BRANCH     1U
#define MIPS32_EXIT_SYSCALL    2U
#define MIPS32_EXIT_UNDEF      3U
#define MIPS32_EXIT_FAULT      4U
#define MIPS32_EXIT_TRAP       5U
#define MIPS32_EXIT_SINGLE_STEP 6U

/* Architectural limits, page/window constants (SPEC 1.1, 1.2). */
#define MIPS32_MAX_REGIONS   512U
#define MIPS32_RAS_SIZE      64U
#define MIPS32_IBTC_SIZE     1024U
#define MIPS32_PAGE_SIZE     4096U
#define MIPS32_TASK_SIZE_TOP 0x7FFF8000U /* O32 useg compat limit (SPEC 1.1) */
#define MIPS32_STACK_TOP     0x7FFF0000U /* initial stack top (SPEC 1.1) */
#define MIPS32_SIGTRAMP      0x7FFF7000U /* synthetic sigtramp page (SPEC 1.1) */
#define MIPS32_LOW_GUARD_SIZE 0x00010000U

typedef struct mips32_region {
    uint32_t start;
    uint32_t end;
    uint32_t prot;
    uint32_t flags;
    char     name[64];
} mips32_region_t;

/* Engine selection (MIPS32RT_ENGINE, --interp/--dbt). */
enum {
    MIPS32_ENGINE_INTERP = 0, /* portable C interpreter: oracle (Phase 1) */
    MIPS32_ENGINE_DBT    = 1  /* MIPS32r2 -> A64 translator (Phase 2) */
};

/*
 * Architectural + runtime state for a MIPS32r2 O32 guest thread.
 *
 * ABI-locked prefix (offsets 0..447, SPEC 2.1):
 *   0x000 gpr[32]        $0..$31 ($0 hardwired 0 by engines on writeback)
 *   0x080 pc, 0x084 next_pc, 0x088 hi, 0x08c lo
 *   0x090 ulr (CP0 UserLocal), 0x094 fcsr (FCR31)
 *   0x098 in_delay_slot, 0x099 fr_mode, 0x09a llbit, 0x09b nan2008
 *   0x09c lladdr, 0x0a0 llval, 0x0a4 cp0_config1 (bit 0 = is_be)
 *   0x0a8 guest_base (host base G of [G, G+4GiB)), 0x0b0 ibtc_ptr
 *   0x0b8 exit_reason, 0x0bc exit_info
 *   0x0c0 fpr[32]        256 B of u64 slots, 16-byte aligned
 */
typedef struct mips32_ctx {
    uint32_t gpr[32];         /* 0x000 */
    uint32_t pc;              /* 0x080 */
    uint32_t next_pc;         /* 0x084 */
    uint32_t hi;              /* 0x088 */
    uint32_t lo;              /* 0x08c */
    uint32_t ulr;             /* 0x090 */
    uint32_t fcsr;            /* 0x094 */
    uint8_t  in_delay_slot;   /* 0x098 */
    uint8_t  fr_mode;         /* 0x099 */
    uint8_t  llbit;           /* 0x09a */
    uint8_t  nan2008;         /* 0x09b */
    uint32_t lladdr;          /* 0x09c */
    uint32_t llval;           /* 0x0a0 */
    uint32_t cp0_config1;     /* 0x0a4 */
    uint64_t guest_base;      /* 0x0a8 */
    uint64_t ibtc_ptr;        /* 0x0b0 */
    uint32_t exit_reason;     /* 0x0b8 */
    uint32_t exit_info;       /* 0x0bc */
    uint64_t fpr[32];         /* 0x0c0 */

    /* ---- C-only tail (no asm offset dependencies; extend at end only) ---- */

    /* Guest memory layout & allocator inside [G, G + 4GiB) */
    uint32_t brk_base;
    uint32_t brk_curr;
    uint32_t mmap_cursor;       /* bottom-up cursor for guest mmap (Phase 1) */
    uint32_t interp_base;
    uint32_t elf_base;
    uint32_t elf_entry;
    uint32_t stack_top;
    uint32_t stack_base;

    /* Host handshake (vendored a32host, unchanged ABI 1.0/1.1) */
    a32h_info_t host_info;
    bool        has_host_info;

    /* Tracked guest regions (sorted by start) for /proc/self/maps + gaps */
    mips32_region_t regions[MIPS32_MAX_REGIONS];
    size_t          region_count;

    /* Thread, futex, and signal state (wired in Phase 4) */
    uint32_t clear_child_tid;
    uint32_t robust_list_head;
    uint32_t robust_list_len;
    int      host_tid;
    bool     is_thread_clone;

    /* Guest startup metadata for /proc/self/{cmdline,auxv,exe} (Phase 5) */
    int      guest_argc;
    char   **guest_argv;
    char   **host_envp;
    uint32_t auxv_data[64];
    size_t   auxv_bytes;

    /* Configuration & engine selection */
    const char *sysroot;
    const char *exec_path;
    const char *cache_dir;
    int         engine;         /* MIPS32_ENGINE_* */
    bool        trace_enabled;
    bool        difftest_enabled;

    /* Instrumentation counters */
    uint64_t blocks_executed;
    uint64_t syscalls_executed;
    uint64_t blocks_compiled;
    uint64_t icache_flushes;
    uint64_t wx_transitions;
} mips32_ctx_t;

/* ABI-locked offsets (SPEC 2.1, verified by tests/check_abi_invariants). */
#define MIPS32_CTX_GPR_OFFSET           0x000U
#define MIPS32_CTX_PC_OFFSET            0x080U
#define MIPS32_CTX_NEXT_PC_OFFSET       0x084U
#define MIPS32_CTX_HI_OFFSET            0x088U
#define MIPS32_CTX_LO_OFFSET            0x08cU
#define MIPS32_CTX_ULR_OFFSET           0x090U
#define MIPS32_CTX_FCSR_OFFSET          0x094U
#define MIPS32_CTX_IN_DELAY_SLOT_OFFSET 0x098U
#define MIPS32_CTX_FR_MODE_OFFSET       0x099U
#define MIPS32_CTX_LLBIT_OFFSET          0x09aU
#define MIPS32_CTX_NAN2008_OFFSET       0x09bU
#define MIPS32_CTX_LLADDR_OFFSET        0x09cU
#define MIPS32_CTX_LLVAL_OFFSET         0x0a0U
#define MIPS32_CTX_CP0_CONFIG1_OFFSET   0x0a4U
#define MIPS32_CTX_GUEST_BASE_OFFSET    0x0a8U
#define MIPS32_CTX_IBTC_PTR_OFFSET      0x0b0U
#define MIPS32_CTX_EXIT_REASON_OFFSET   0x0b8U
#define MIPS32_CTX_EXIT_INFO_OFFSET     0x0bcU
#define MIPS32_CTX_FPR_OFFSET           0x0c0U

_Static_assert(offsetof(mips32_ctx_t, gpr) == 0, "gpr must be at offset 0");
_Static_assert(offsetof(mips32_ctx_t, pc) == 0x080, "pc must be at offset 0x080");
_Static_assert(offsetof(mips32_ctx_t, next_pc) == 0x084, "next_pc at 0x084");
_Static_assert(offsetof(mips32_ctx_t, hi) == 0x088, "hi must be at offset 0x088");
_Static_assert(offsetof(mips32_ctx_t, lo) == 0x08c, "lo must be at offset 0x08c");
_Static_assert(offsetof(mips32_ctx_t, ulr) == 0x090, "ulr must be at offset 0x090");
_Static_assert(offsetof(mips32_ctx_t, fcsr) == 0x094, "fcsr must be at offset 0x094");
_Static_assert(offsetof(mips32_ctx_t, in_delay_slot) == 0x098, "in_delay_slot at 0x098");
_Static_assert(offsetof(mips32_ctx_t, fr_mode) == 0x099, "fr_mode at 0x099");
_Static_assert(offsetof(mips32_ctx_t, llbit) == 0x09a, "llbit at 0x09a");
_Static_assert(offsetof(mips32_ctx_t, nan2008) == 0x09b, "nan2008 at 0x09b");
_Static_assert(offsetof(mips32_ctx_t, lladdr) == 0x09c, "lladdr at 0x09c");
_Static_assert(offsetof(mips32_ctx_t, llval) == 0x0a0, "llval at 0x0a0");
_Static_assert(offsetof(mips32_ctx_t, cp0_config1) == 0x0a4, "cp0_config1 at 0x0a4");
_Static_assert(offsetof(mips32_ctx_t, guest_base) == 0x0a8, "guest_base at 0x0a8");
_Static_assert(offsetof(mips32_ctx_t, ibtc_ptr) == 0x0b0, "ibtc_ptr at 0x0b0");
_Static_assert(offsetof(mips32_ctx_t, exit_reason) == 0x0b8, "exit_reason at 0x0b8");
_Static_assert(offsetof(mips32_ctx_t, exit_info) == 0x0bc, "exit_info at 0x0bc");
_Static_assert(offsetof(mips32_ctx_t, fpr) == 0x0c0, "fpr must be at offset 0x0c0");
_Static_assert(sizeof(((mips32_ctx_t *)0)->fpr) == 256, "fpr must span 256 bytes");
_Static_assert(sizeof(mips32_ctx_t) >= 0x1c0, "locked prefix must span 0x1c0 bytes");

static inline void mips32_spin_lock(_Atomic uint32_t *lock)
{
    while (atomic_exchange_explicit(lock, 1U, memory_order_acquire) != 0U) {
        sched_yield();
    }
}

static inline void mips32_spin_unlock(_Atomic uint32_t *lock)
{
    atomic_store_explicit(lock, 0U, memory_order_release);
}

/* Guest VA -> host pointer.  va is u32: never sign-extend or truncate. */
static inline void *mips32_guest_ptr(const mips32_ctx_t *ctx, uint32_t guest_va)
{
    return (void *)(uintptr_t)(ctx->guest_base + (uint64_t)guest_va);
}

static inline uint32_t mips32_page_down(uint32_t x)
{
    return x & ~(MIPS32_PAGE_SIZE - 1U);
}

static inline uint32_t mips32_page_up(uint32_t x)
{
    return (x + (MIPS32_PAGE_SIZE - 1U)) & ~(MIPS32_PAGE_SIZE - 1U);
}

/*
 * Guest prot -> host prot for window mappings.  Guest PROT_EXEC is never
 * host-exec (the window holds data; translated code lives outside it),
 * which also dissolves any W^X conflict; SMC write-protection is layered
 * on top by the JIT (Phase 2), not here.
 */
static inline int mips32_host_prot(const mips32_ctx_t *ctx, uint32_t guest_prot)
{
    (void)ctx;
    uint32_t p = guest_prot & 0x7U;
    if ((p & 0x4U) != 0U) {
        p |= 0x1U; /* PROT_EXEC implies PROT_READ on host */
        p &= ~0x4U;
    }
    return (int)p;
}

/* Engine entry points (defined by src/interp/ and src/dbt/ in later phases). */
int interp_main(mips32_ctx_t *ctx);
int dbt_main(mips32_ctx_t *ctx);

/*
 * ---- Phase 1 frozen contracts (decoder / interp / guest memory / syscalls)
 *
 * Endianness: ctx->cp0_config1 bit 0 selects BE (mips) vs LE (mipsel).
 * Faults: memory helpers return 0 on success, MIPS_FAULT (-1) when the
 * access is unmapped, unaligned (for aligned-only accesses), or faulting.
 */
#define MIPS_FAULT (-1)

static inline int mips_is_be(const mips32_ctx_t *ctx)
{
    return (ctx->cp0_config1 & 1U) != 0;
}

/* Decoded MIPS32r2 instruction (word already in host byte order). */
typedef struct mips_dec {
    uint32_t word;              /* raw 32-bit instruction word */
    uint8_t  op;                /* major opcode (bits 31..26) */
    uint8_t  rs;                /* bits 25..21 */
    uint8_t  rt;                /* bits 20..16 */
    uint8_t  rd;                /* bits 15..11 */
    uint8_t  sa;                /* bits 10..6 */
    uint8_t  funct;             /* bits 5..0 (SPECIAL) */
    uint16_t imm;               /* bits 15..0 */
    uint32_t target;            /* bits 25..0 (J/JAL) */
    int32_t  simm;              /* sign-extended imm */
    uint32_t uimm;              /* zero-extended imm */
} mips_dec_t;

/* Pure decoder (src/interp/decode.c, lane L1a). */
void mips_decode(uint32_t word, mips_dec_t *d);
/* Endianness-aware fetch from guest pc (0 ok, MIPS_FAULT on fault). */
int mips_fetch(mips32_ctx_t *ctx, uint32_t pc, uint32_t *word);

/* Reference interpreter (src/interp/interp.c, lane L1b). */
int interp_step(mips32_ctx_t *ctx);
int interp_run(mips32_ctx_t *ctx);

/* Guest memory window + accessors (src/os/mem.c, lane L1c). */
int guest_mem_init(mips32_ctx_t *ctx);
int guest_ld8(mips32_ctx_t *ctx, uint32_t va, uint32_t *out);
int guest_ld16(mips32_ctx_t *ctx, uint32_t va, uint32_t *out);   /* aligned-only */
int guest_ld32(mips32_ctx_t *ctx, uint32_t va, uint32_t *out);   /* aligned-only */
int guest_st8(mips32_ctx_t *ctx, uint32_t va, uint32_t val);
int guest_st16(mips32_ctx_t *ctx, uint32_t va, uint32_t val);    /* aligned-only */
int guest_st32(mips32_ctx_t *ctx, uint32_t va, uint32_t val);    /* aligned-only */
/* Synchronous fault: records EXIT_FAULT (lane L1c; signals in Phase 4). */
void mips_fault(mips32_ctx_t *ctx, uint32_t addr);

/* Minimal O32 syscall dispatcher (src/os/syscall_min.c, lane L1c). */
int32_t mips_syscall(mips32_ctx_t *ctx);

#endif /* MIPS32RT_H */
