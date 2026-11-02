/* Round-3 regression probes (M32-R3-1..R3-7 plus cross-RT classes).
 *
 * Part of mips32rt, Apache-2.0, Copyright 2026 Moritz Angermann
 * <moritz@zw3rk.com>, zw3rk pte. ltd.
 *
 * Host-native, deterministic, exit 0 only when every probe passes:
 *   T1  brk(0) after a peer mapping change refreshes the full VMA
 *       snapshot with the new generation (M32-R3-1).
 *   T2  host-page protection is the union of overlapping guest VMAs
 *       (M32-R3-3).
 *   T3  syscall copyout advances LL/SC epochs: a same-value copyout
 *       between LL and SC fails the SC (M32-R3-4).
 *   T4  a full real-time queue reports -EAGAIN instead of silently
 *       dropping the occurrence (M32-R3-5).
 *   T5  rt_sigaction/rt_sigprocmask/sigaltstack snapshot guest input
 *       before writing old output: identical in/out pointers apply
 *       the request (cross-RT aliasing class).
 *   T6  signal delivery saves the exact interrupted $sp (M32-R3-7).
 *   T7  execve preserves mask, pending, and ignored dispositions
 *       while resetting caught handlers (M32-R3-6).
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "mips32rt.h"

#include "os/sigframe_mips32rt.h"
#include "os/syscalls_priv.h"
#include "rt32/rt32.h"
#include "rt32/vm_priv.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond) do { \
        checks++; \
        if (cond) { \
            printf("ok %d: %s\n", checks, #cond); \
        } else { \
            printf("FAIL %d: %s (line %d)\n", checks, #cond, __LINE__); \
            failures++; \
        } \
    } while (0)

/* ---- Minimal link stubs: the probes exercise signals.c, sigqueue.c,
 * mem.c, and the rt32 VM without the syscall dispatcher or the A2
 * regime.  mips_sc_* emulates guest memory on a malloc-style fake
 * window; the real rt32 table backs the T1..T3 probes. ---- */

#define FAKE_WIN_SIZE (128U * 1024U)

static uint8_t fake_win[FAKE_WIN_SIZE];

static int fake_range_ok(uint32_t va, uint32_t len)
{
    return len <= FAKE_WIN_SIZE && (uint64_t)va + (uint64_t)len <= (uint64_t)FAKE_WIN_SIZE;
}

uint32_t mips_sc_arg(mips32_ctx_t *ctx, uint32_t sp, unsigned i, int *ok)
{
    (void)sp;
    if (i < 4U) {
        *ok = 1;
        return ctx->gpr[MIPS32_REG_A0 + i];
    }
    *ok = 0;
    return 0U;
}

int32_t mips_sc_ret(mips32_ctx_t *ctx, int32_t raw)
{
    if (raw < 0) {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)mips_errno_from_host((int)(-raw));
        ctx->gpr[MIPS32_REG_A3] = 1U;
    } else {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)raw;
        ctx->gpr[MIPS32_REG_A3] = 0U;
    }
    return raw;
}

void mips_sc_advance_pc_once(mips32_ctx_t *ctx)
{
    if (ctx != NULL && ctx->sc_pc_advanced == 0U) {
        ctx->pc += 4U;
        ctx->next_pc = ctx->pc + 4U;
        ctx->in_delay_slot = 0U;
        ctx->sc_pc_advanced = 1U;
    }
}

int mips_sc_range_ok(const mips32_ctx_t *ctx, uint32_t va, uint32_t len, uint32_t need)
{
    (void)ctx;
    (void)need;
    return fake_range_ok(va, len);
}

int mips_sc_copy_from(const mips32_ctx_t *ctx, void *dst, uint32_t va, uint32_t len)
{
    (void)ctx;
    if (len > 0U && !fake_range_ok(va, len)) {
        return -EFAULT;
    }
    if (len > 0U) {
        memcpy(dst, fake_win + va, len);
    }
    return 0;
}

int mips_sc_copy_to(mips32_ctx_t *ctx, uint32_t va, const void *src, uint32_t len)
{
    (void)ctx;
    if (len > 0U && !fake_range_ok(va, len)) {
        return -EFAULT;
    }
    if (len > 0U) {
        memcpy(fake_win + va, src, len);
    }
    return 0;
}

/* sigqueue delivery destinations: never delivered by these probes
 * (mips_signal_is_ignored comes from the real signals.c). */
int mips_signal_default_ignore(int signo)
{
    (void)signo;
    return 0;
}

int mips_signal_default_stop(int signo)
{
    (void)signo;
    return 0;
}

void mips_signal_default_die(int signo)
{
    (void)signo;
    _Exit(128 + (signo & 0x7F));
}

int mips_raise_guest_code(mips32_ctx_t *ctx, int signo, int32_t si_code, uint32_t fault_addr);

/* A2/host stubs: never entered (regime stays direct, no guest_mem_init). */
void mips32_vm_invalidate_range(mips32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    (void)ctx;
    (void)start;
    (void)end;
}

int mips32_file_populate_private(mips32_ctx_t *ctx, uint32_t gva, uint32_t len,
                                 int fd, uint64_t file_off)
{
    (void)ctx;
    (void)gva;
    (void)len;
    (void)fd;
    (void)file_off;
    return 0;
}

void rt32_host_probe(mips32_ctx_t *ctx)
{
    (void)ctx;
}

void mips32_fixade_init(mips32_ctx_t *ctx)
{
    (void)ctx;
}

int mips32_vm32_init(mips32_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

int mips32_vm_tlb_miss(mips32_ctx_t *ctx, uint32_t gva, int is_write, uint32_t width)
{
    (void)ctx;
    (void)gva;
    (void)is_write;
    (void)width;
    return 0;
}

extern void mips_ll_record(mips32_ctx_t *ctx, uint32_t addr, uint32_t val);

/* Strong no-op: the probes never execute translated code, and vm.c
 * references the DBT invalidator only weakly. */
void mips32_dbt_invalidate_range(mips32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    (void)ctx;
    (void)start;
    (void)end;
}

/* Little-endian guest word helpers (all probes run LE guests). */
static void gst_put32(uint32_t va, uint32_t v)
{
    fake_win[va] = (uint8_t)(v & 0xFFU);
    fake_win[va + 1U] = (uint8_t)((v >> 8) & 0xFFU);
    fake_win[va + 2U] = (uint8_t)((v >> 16) & 0xFFU);
    fake_win[va + 3U] = (uint8_t)((v >> 24) & 0xFFU);
}

static uint32_t gst_get32(uint32_t va)
{
    return (uint32_t)fake_win[va] | ((uint32_t)fake_win[va + 1U] << 8) |
           ((uint32_t)fake_win[va + 2U] << 16) | ((uint32_t)fake_win[va + 3U] << 24);
}

static uint64_t gst_get64(uint32_t va)
{
    uint64_t lo = (uint64_t)gst_get32(va);
    uint64_t hi = (uint64_t)gst_get32(va + 4U);
    return lo | (hi << 32);
}

/* Query a disposition handler through rt_sigaction(sig, 0, out). */
static uint32_t query_handler(mips32_ctx_t *ctx, uint32_t sig, uint32_t out_va)
{
    ctx->gpr[MIPS32_REG_A0] = sig;
    ctx->gpr[MIPS32_REG_A0 + 1U] = 0U;
    ctx->gpr[MIPS32_REG_A0 + 2U] = out_va;
    ctx->gpr[MIPS32_REG_A0 + 3U] = 16U;
    (void)mips_sc_rt_sigaction(ctx, 0U);
    return gst_get32(out_va + 4U);
}

/* Every handler return writes guest V0/A3 (mips_sc_ret), so each call
 * site must reload all four argument registers like real dispatch. */
static void set_args(mips32_ctx_t *ctx, uint32_t a0, uint32_t a1,
                     uint32_t a2, uint32_t a3)
{
    ctx->gpr[MIPS32_REG_A0] = a0;
    ctx->gpr[MIPS32_REG_A0 + 1U] = a1;
    ctx->gpr[MIPS32_REG_A0 + 2U] = a2;
    ctx->gpr[MIPS32_REG_A0 + 3U] = a3;
}

static mips32_ctx_t tA;
static mips32_ctx_t tB;
static mips32_ctx_t fctx;

int main(void)
{
    memset(&tA, 0, sizeof(tA));
    memset(&tB, 0, sizeof(tB));
    memset(&fctx, 0, sizeof(fctx));
    memset(fake_win, 0, sizeof(fake_win));

    /* T1: peer mapping change, then brk(0) on a second context. */
    CHECK(rt32_vm_init(&tA, UINT64_MAX) == 0);
    {
        uint32_t va = rt32_vm_mmap2(&tA, 0U, 0x1000U,
                                    (uint32_t)(PROT_READ | PROT_WRITE),
                                    0x02U | 0x20U, -1, 0U);
        uint32_t got;

        CHECK(va <= 0xFFFFF000U);
        got = rt32_vm_brk(&tB, 0U);
        (void)got;
        CHECK(tB.region_count == 1U);
        CHECK(tB.vm_gen == g_vm_gen);
        CHECK(tB.regions[0].start == va);
    }

    /* T2: adjacent RO + RW VMAs in one host page read back RW. */
    {
        uint32_t r1 = rt32_vm_mmap2(&tA, 0x40000000U, 0x1000U, (uint32_t)PROT_READ,
                                    0x02U | 0x20U | 0x10U, -1, 0U);
        uint32_t r2 = rt32_vm_mmap2(&tA, 0x40001000U, 0x1000U,
                                    (uint32_t)(PROT_READ | PROT_WRITE),
                                    0x02U | 0x20U | 0x10U, -1, 0U);
        int uni;

        CHECK(r1 == 0x40000000U);
        CHECK(r2 == 0x40001000U);
        uni = vm_union_host_prot_locked(0x40000000U, 0x40004000U);
        CHECK(uni == (PROT_READ | PROT_WRITE));
    }

    /* T3: same-value copyout between LL and SC fails the SC. */
    {
        uint32_t addr = 0x40001000U;
        uint32_t v = 0xA5A5A5A5U;
        int ok = -1;
        int rc;

        mips_ll_record(&tA, addr, v);
        CHECK(tA.llbit == 1U);
        CHECK(rt32_vm_copy_to(&tA, addr, &v, 4U) == 0);
        tA.llbit = 1U; /* same thread wrote: re-arm, keep old snapshot */
        rc = guest_sc32(&tA, addr, v, 0xDEADBEAFU, &ok);
        CHECK(rc == 0);
        CHECK(ok == 0);
    }

    /* T4: real-time queue overflow is observable. */
    {
        mips32_ctx_t q;
        int i;
        int last = 0;

        memset(&q, 0, sizeof(q));
        for (i = 0; i < 64; i++) {
            CHECK(mips_signal_pend(&q, 33, -6) == 0);
        }
        last = mips_signal_pend(&q, 33, -6);
        CHECK(last == -11);
        CHECK(q.sig_rt_count == 64U);
        CHECK(mips_signal_pend(&q, 5, -1) == 0);
    }

    fctx.guest_base = (uint64_t)(uintptr_t)fake_win;

    /* T5a: rt_sigaction with act == oact installs the request. */
    {
        gst_put32(0x1000U, 0U);
        gst_put32(0x1004U, 0x1234U);
        gst_put32(0x1008U, 0U);
        gst_put32(0x100CU, 0U);
        gst_put32(0x1010U, 0U);
        gst_put32(0x1014U, 0U);
        set_args(&fctx, 10U, 0x1000U, 0x1000U, 16U);
        CHECK(mips_sc_rt_sigaction(&fctx, 0U) == 0);
        CHECK(query_handler(&fctx, 10U, 0x2000U) == 0x1234U);
    }

    /* T5b: rt_sigprocmask with set == oldset applies the request. */
    {
        gst_put32(0x3000U, (uint32_t)(1U << 19));
        gst_put32(0x3004U, 0U);
        gst_put32(0x3008U, 0U);
        gst_put32(0x300CU, 0U);
        set_args(&fctx, 3U, 0x3000U, 0x3000U, 16U);
        CHECK(mips_l4a_rt_sigprocmask(&fctx, 0U) == 0);
        CHECK(fctx.sig_blocked[0] == (uint32_t)(1U << 19));
        CHECK(gst_get32(0x3000U) == 0U);
    }

    /* T5c: sigaltstack with ss == oss installs the request. */
    {
        gst_put32(0x4000U, 0x50000U);
        gst_put32(0x4004U, 8192U);
        gst_put32(0x4008U, 0U);
        set_args(&fctx, 0x4000U, 0x4000U, 0U, 0U);
        CHECK(mips_sc_sigaltstack(&fctx, 0U) == 0);
        CHECK(fctx.sigalt_sp == 0x50000U);
        CHECK(fctx.sigalt_size == 8192U);
        CHECK(fctx.sigalt_flags == 0U);
    }

    /* T6: the saved $sp is the exact interrupted value. */
    {
        uint32_t newsp;
        uint64_t saved;

        memset(fctx.sig_blocked, 0, sizeof(fctx.sig_blocked));
        fctx.gpr[MIPS32_REG_SP] = 0x1F001U;
        fctx.pc = 0x400000U;
        fctx.next_pc = 0x400004U;
        fctx.in_delay_slot = 0U;
        fctx.sig_depth = 0U;
        fctx.region_count = 1U;
        fctx.regions[0].start = 0x7FFF7000U & ~0xFFFU;
        fctx.regions[0].end = fctx.regions[0].start + 0x1000U;
        fctx.regions[0].prot = (uint32_t)(PROT_READ | PROT_WRITE);
        fctx.regions[0].flags = 0U;
        fctx.regions[0].name[0] = '\0';
        fctx.vm_gen = g_vm_gen;
        CHECK(mips_raise_guest(&fctx, 10, 0U) == 0);
        newsp = fctx.gpr[MIPS32_REG_SP];
        CHECK((newsp & 7U) == 0U);
        saved = gst_get64(newsp + 192U + 8U * 29U);
        CHECK(saved == 0x1F001ULL);
    }

    /* T7: exec preserves mask/pending/ignored, resets caught. */
    {
        gst_put32(0x6000U, 0U);
        gst_put32(0x6004U, 1U);
        gst_put32(0x6008U, 0U);
        gst_put32(0x600CU, 0U);
        gst_put32(0x6010U, 0U);
        gst_put32(0x6014U, 0U);
        set_args(&fctx, 20U, 0x6000U, 0U, 16U);
        CHECK(mips_sc_rt_sigaction(&fctx, 0U) == 0);
        gst_put32(0x6004U, 0x5678U);
        set_args(&fctx, 11U, 0x6000U, 0U, 16U);
        CHECK(mips_sc_rt_sigaction(&fctx, 0U) == 0);
        fctx.sig_blocked[0] |= (uint32_t)(1U << 4);
        CHECK(mips_signal_pend(&fctx, 5, -1) == 0);
        CHECK(mips_signal_pend(&fctx, 33, -6) == 0);
        fctx.sig_depth = 1U;
        fctx.sig_frame_sp[0] = 0x1E000U;
        fctx.sigalt_sp = 0x60000U;
        fctx.sigalt_size = 8192U;
        fctx.sigalt_flags = 0U;
        mips32_signals_reset_for_exec(&fctx);
        CHECK((fctx.sig_blocked[0] & (uint32_t)(1U << 4)) != 0U);
        CHECK((fctx.sig_pending[0] & (uint32_t)(1U << 4)) != 0U);
        CHECK(fctx.sig_rt_count == 1U);
        CHECK(query_handler(&fctx, 20U, 0x7000U) == 1U);
        CHECK(query_handler(&fctx, 11U, 0x7000U) == 0U);
        CHECK(fctx.sig_depth == 0U);
        CHECK(fctx.sigalt_size == 0U);
        CHECK(fctx.sigalt_flags == 2U);
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
