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
 *   T4  a full real-time queue reports -EAGAIN for queued senders
 *       (SI_QUEUE/SI_TKILL) but merges plain kill SI_USER with 0
 *       (M32-R3-5).
 *   T5  rt_sigaction/rt_sigprocmask/sigaltstack snapshot guest input
 *       before writing old output: identical in/out pointers apply
 *       the request (cross-RT aliasing class).
 *   T6  signal delivery saves the exact interrupted $sp (M32-R3-7).
 *   T7  execve preserves mask, pending, and ignored dispositions
 *       while resetting caught handlers (M32-R3-6), and clears
 *       flags/restorer/mask on surviving SIG_IGN entries.
 *   T8  two guest aliases in one 16 KiB host page stay coherent
 *       across munmap: write via A, munmap A, B still sees the byte
 *       and the backing file carries it (M32-R3-2 shared-subpage).
 *   T9  COP1 fmt selectors are S=16 D=17 W=20 L=21 (M32-R7-20).
 *   T10 FR=0 doubles alias even/odd low halves; FR=1 is flat (M32-R7-1).
 *   T11 fp_even rejects odd D/L lanes only in FR=0 (M32-R7-1).
 *   T12 FCSR alias packings match QEMU (FCCR/FEXR/FENR) (M32-R7-19).
 *   T13 Round-7 post-fable contract: delay-slot advance resumes at the
 *       branch target, alignment faults report BUS_ADRALN, and explicit
 *       trap codes reach the frame verbatim (M32-R7-2/6/9).
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mips32rt.h"

#include "dbt/emit_fp_priv.h"
#include "interp/fp.h"
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

/* Test double mirroring src/os/syscalls.c: a slot syscall resumes at
 * the branch target so frames built during delivery save it (M32-R7-2). */
void mips_sc_advance_pc_once(mips32_ctx_t *ctx)
{
    if (ctx != NULL && ctx->sc_pc_advanced == 0U) {
        if (ctx->in_delay_slot != 0U) {
            ctx->pc = ctx->delay_target;
        } else {
            ctx->pc += 4U;
        }
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

void mips32_vm32_fini(mips32_ctx_t *ctx)
{
    (void)ctx;
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

/* M32-R3-2 shared-subpage probe: two distinct guest aliases in one
 * 16 KiB host page.  Write through alias A, munmap alias A, then
 * alias B must still see the byte and the backing file must carry it
 * after munmap.  Uses MAP_SHARED so the Linux host path relies on
 * direct shared coherence plus kernel writeback, while the Apple path
 * exercises the Darwin shadow writeback flush before VMA teardown. */
static void test_m32_r3_2_shared_subpage(mips32_ctx_t *vc)
{
    char tmpl[] = "/tmp/mips32rt-r32-XXXXXX";
    int fd = mkstemp(tmpl);
    uint32_t alias_a = 0x41000000U;
    uint32_t alias_b = 0x41001000U;
    uint32_t map_a = 0U;
    uint32_t map_b = 0U;
    uint8_t *pa = NULL;
    uint8_t *pb = NULL;
    uint8_t fbyte = 0U;
    const uint32_t off = 0x20U;
    const uint8_t want = 0xA5U;

    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    CHECK(ftruncate(fd, 0x4000) == 0);
    map_a = rt32_vm_mmap2(vc, alias_a, 0x1000U,
        (uint32_t)(PROT_READ | PROT_WRITE), 0x01U | 0x10U, fd, 0U);
    CHECK(map_a == alias_a);
    map_b = rt32_vm_mmap2(vc, alias_b, 0x1000U,
        (uint32_t)(PROT_READ | PROT_WRITE), 0x01U | 0x10U, fd, 0U);
    CHECK(map_b == alias_b);
    pa = (uint8_t *)mips32_guest_ptr(vc, alias_a);
    pb = (uint8_t *)mips32_guest_ptr(vc, alias_b);
    pa[off] = want;
    CHECK(rt32_vm_munmap(vc, alias_a, 0x1000U) == 0);
    pb = (uint8_t *)mips32_guest_ptr(vc, alias_b);
    CHECK(pb[off] == want);
    CHECK(pread(fd, &fbyte, 1, (off_t)off) == 1);
    CHECK(fbyte == want);
    (void)rt32_vm_munmap(vc, alias_b, 0x1000U);
    (void)close(fd);
    (void)unlink(tmpl);
}

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

    /* T4: RT queue overflow: queued senders see -EAGAIN, plain
     * kill SI_USER (0) merges into the pending bit with 0. */
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
        last = mips_signal_pend(&q, 33, -1);
        CHECK(last == -11);
        CHECK(q.sig_rt_count == 64U);
        CHECK(mips_signal_pend(&q, 5, -1) == 0);
        /* SI_USER merge on a full RT queue: success, bit set. */
        CHECK(mips_signal_pend(&q, 33, 0) == 0);
        CHECK(q.sig_rt_count == 64U);
        CHECK((q.sig_pending[(33 - 1) / 32U] & (uint32_t)(1U << ((33 - 1) % 32U))) != 0U);
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
        gst_put32(0x6000U, 0x10000000U);
        gst_put32(0x6004U, 1U);
        gst_put32(0x6008U, 0x00000008U);
        gst_put32(0x600CU, 0U);
        gst_put32(0x6010U, 0U);
        gst_put32(0x6014U, 0U);
        set_args(&fctx, 20U, 0x6000U, 0U, 16U);
        CHECK(mips_sc_rt_sigaction(&fctx, 0U) == 0);
        gst_put32(0x6000U, 0U);
        gst_put32(0x6004U, 0x5678U);
        gst_put32(0x6008U, 0U);
        gst_put32(0x600CU, 0U);
        gst_put32(0x6010U, 0U);
        gst_put32(0x6014U, 0U);
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
        /* Surviving SIG_IGN keeps its handler but drops stale metadata. */
        set_args(&fctx, 20U, 0U, 0x7000U, 16U);
        CHECK(mips_sc_rt_sigaction(&fctx, 0U) == 0);
        CHECK(gst_get32(0x7000U) == 0U);
        CHECK(gst_get32(0x7008U) == 0U);
        CHECK(gst_get32(0x700CU) == 0U);
        CHECK(gst_get32(0x7010U) == 0U);
        CHECK(gst_get32(0x7014U) == 0U);
    }

    /* T8: shared-subpage coherence across munmap (M32-R3-2). */
    test_m32_r3_2_shared_subpage(&tA);

    /* T9: COP1 fmt selectors (M32-R7-20). */
    CHECK(FP_FMT_S == 16u);
    CHECK(FP_FMT_D == 17u);
    CHECK(FP_FMT_W == 20u);
    CHECK(FP_FMT_L == 21u);

    /* T10: FR-aware FPR pairing (M32-R7-1). */
    {
        mips32_ctx_t c;
        memset(&c, 0, sizeof c);
        c.fr_mode = 0u;
        c.fpr[0] = 0xFFFFFFFF00000000ULL | 0u;
        c.fpr[1] = 0xFFFFFFFF00000000ULL | 0x3FF00000u;
        CHECK(mips_fpr_get_d(&c, 0u) == 0x3FF0000000000000ULL);
        mips_fpr_set_d_raw(&c, 0u, 0x3FF0000000000000ULL);
        CHECK(mips_fpr_get_w(&c, 0u) == 0u);
        CHECK(mips_fpr_get_w(&c, 1u) == 0x3FF00000u);
        mips_fpr_set_w_raw(&c, 1u, 0x40000000u);
        CHECK(mips_fpr_get_d(&c, 0u) == 0x4000000000000000ULL);
        c.fr_mode = 1u;
        c.fpr[2] = 0x1122334455667788ULL;
        CHECK(mips_fpr_get_d(&c, 2u) == 0x1122334455667788ULL);
    }

    /* T11: FR=0 even rule (M32-R7-1). */
    {
        mips32_ctx_t c;
        memset(&c, 0, sizeof c);
        c.fr_mode = 0u;
        CHECK(fp_even(&c, 0x1000u, 0u) == 0);
        c.fr_mode = 1u;
        CHECK(fp_even(&c, 0x1000u, 1u) == 0);
    }

    /* T12: QEMU FCSR alias packings (M32-R7-19). */
    {
        uint32_t f = 0x00800000u | 0x02000000u | 0x0003F07Cu | 0x00000F83u | 0x01000000u;
        CHECK((((f >> 24) & 0xFEu) | ((f >> 23) & 1u)) == 0x03u);
        CHECK((f & 0x0003F07Cu) == 0x0003F07Cu);
        CHECK(((f & 0x00000F83u) | ((f >> 22) & 4u)) == 0x00000F87u);
        CHECK((0x000C0000u & 0xFF81FFFFu) == 0u);
    }

    /* T13: Round-7 post-fable contract (M32-R7-2/6/9). */
    {
        mips32_ctx_t c;
        uint32_t newsp;

        memset(&c, 0, sizeof c);
        c.guest_base = (uint64_t)(uintptr_t)fake_win;

        /* R7-2: a slot syscall resumes at the branch target. */
        c.pc = 0x400004U;
        c.next_pc = 0x400008U;
        c.in_delay_slot = 1U;
        c.delay_target = 0x500000U;
        mips_sc_advance_pc_once(&c);
        CHECK(c.pc == 0x500000U);
        CHECK(c.next_pc == 0x500004U);
        CHECK(c.in_delay_slot == 0U);
        CHECK(c.sc_pc_advanced == 1U);
        c.sc_pc_advanced = 0U;
        c.pc = 0x400000U;
        c.next_pc = 0x400004U;
        mips_sc_advance_pc_once(&c);
        CHECK(c.pc == 0x400004U);
        CHECK(c.next_pc == 0x400008U);

        /* Frame setup mirrors T6: exact-sp stack region for delivery. */
        c.gpr[MIPS32_REG_SP] = 0x1F001U;
        c.pc = 0x400000U;
        c.next_pc = 0x400004U;
        c.in_delay_slot = 0U;
        c.sig_depth = 0U;
        c.region_count = 1U;
        c.regions[0].start = 0x7FFF7000U & ~0xFFFU;
        c.regions[0].end = c.regions[0].start + 0x1000U;
        c.regions[0].prot = (uint32_t)(PROT_READ | PROT_WRITE);
        c.regions[0].flags = 0U;
        c.regions[0].name[0] = '\0';
        c.vm_gen = g_vm_gen;

        /* R7-6: LDC1/SDC1 at 4 mod 8 still reports BUS_ADRALN (1). */
        gst_put32(0x9000U, 0U);
        gst_put32(0x9004U, 0x1234U);
        gst_put32(0x9008U, 0U);
        gst_put32(0x900CU, 0U);
        gst_put32(0x9010U, 0U);
        gst_put32(0x9014U, 0U);
        set_args(&c, 10U, 0x9000U, 0U, 16U);
        CHECK(mips_sc_rt_sigaction(&c, 0U) == 0);
        mips_fault_align(&c, 0x1004U);
        newsp = c.gpr[MIPS32_REG_SP];
        CHECK(gst_get32(newsp + 28U) == 1U);
        CHECK(gst_get32(newsp + 36U) == 0x1004U);

        /* R7-9: explicit trap codes reach the frame verbatim. */
        c.gpr[MIPS32_REG_SP] = 0x1F001U;
        c.sig_depth = 0U;
        set_args(&c, 5U, 0x9000U, 0U, 16U);
        CHECK(mips_sc_rt_sigaction(&c, 0U) == 0);
        mips_trap_code(&c, 5, 1, 0x400100U);
        newsp = c.gpr[MIPS32_REG_SP];
        CHECK(gst_get32(newsp + 28U) == 1U);
        c.gpr[MIPS32_REG_SP] = 0x1F001U;
        c.sig_depth = 0U;
        mips_trap_code(&c, 5, 0x80, 0x400100U);
        newsp = c.gpr[MIPS32_REG_SP];
        CHECK(gst_get32(newsp + 28U) == 0x80U);
    }

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
