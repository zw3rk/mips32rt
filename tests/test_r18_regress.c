/* Round-13/14/16/18 regression probes (M32-R13-2/11, M32-R14-1/2, M32-R18-1).
 *
 * Part of mips32rt, Apache-2.0, Copyright 2026 Moritz Angermann
 * <moritz@zw3rk.com>, zw3rk pte. ltd.
 *
 * Host-native, deterministic, exit 0 only when every probe passes:
 *   T1  interp ADD on 0x7fffffff + 1 traps SIGFPE si_code 2, rd unchanged.
 *   T2  interp SUB underflow traps SIGFPE si_code 2, rd unchanged.
 *   T3  interp ADDI on 0x7fffffff + 1 traps SIGFPE si_code 2, rt unchanged.
 *   T4  ADD in a branch delay slot reports the branch pc with rd unchanged.
 *   T5  dbt_emit_int declines ADD in a delay slot (SINGLE_STEP at the
 *       branch) but compiles ADDU slots and straight-line ADD inline.
 *   T6  dbt_compile on an unaligned block start delivers SIGBUS
 *       BUS_ADRALN (si_code 1), not SIGSEGV.
 *   T7  SC with llbit == 0 on a PROT_READ page faults with rt and the
 *       word preserved; on RW it fails quietly with rt = 0.
 *   T8  rt32_vm_mremap grows/moves/faults correctly and the O32 mremap
 *       syscall (4167) wires fixed/new addresses through mips_syscall.
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

#include "dbt/dbt.h"
#include "interp/decode.h"
#include "os/syscalls_priv.h"
#include "rt32/rt32.h"
#include "rt32/vm_priv.h"
#include "vm/vm32.h"

extern void mips_ll_record(mips32_ctx_t *ctx, uint32_t addr, uint32_t val);

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

/* ---- Link stubs: syscall-shaped guest access on the real window ---- */

uint32_t mips_sc_arg(mips32_ctx_t *ctx, uint32_t sp, unsigned i, int *ok)
{
    if (ctx == NULL || ok == NULL) {
        if (ok != NULL) {
            *ok = 0;
        }
        return 0U;
    }
    if (i < 4U) {
        *ok = 1;
        return ctx->gpr[MIPS32_REG_A0 + i];
    }
    {
        uint8_t b[4];
        uint32_t va = sp + 16U + 4U * (i - 4U);
        int be = mips_is_be(ctx);

        if (rt32_vm_copy_from(ctx, b, va, 4U) != 0) {
            *ok = 0;
            return 0U;
        }
        *ok = 1;
        if (be != 0) {
            return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
                   ((uint32_t)b[2] << 8) | (uint32_t)b[3];
        }
        return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
               ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    }
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

int mips_sc_range_ok(const mips32_ctx_t *ctx, uint32_t va, uint32_t len,
                     uint32_t need)
{
    return mips32_range_ok(ctx, va, len, need);
}

int mips_sc_copy_from(const mips32_ctx_t *ctx, void *dst, uint32_t va,
                      uint32_t len)
{
    return rt32_vm_copy_from(ctx, dst, va, len);
}

int mips_sc_copy_to(mips32_ctx_t *ctx, uint32_t va, const void *src,
                    uint32_t len)
{
    return rt32_vm_copy_to(ctx, va, src, len);
}

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

void rt32_host_probe(mips32_ctx_t *ctx)
{
    (void)ctx;
}

long mips_trace_tid(void)
{
    return 0L;
}

/* Uncalled syscall back ends (the probes never leave the switch). */
int32_t mips_syscall_extra(mips32_ctx_t *ctx, uint32_t sp)
{
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
}

int32_t mips_proc_fork(mips32_ctx_t *ctx, uint32_t sp)
{
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
}

int32_t mips_proc_execve(mips32_ctx_t *ctx, uint32_t sp)
{
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
}

int32_t mips_proc_wait4(mips32_ctx_t *ctx, uint32_t sp)
{
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
}

int32_t mips_proc_waitpid(mips32_ctx_t *ctx, uint32_t sp)
{
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
}

int32_t mips_sc_clone(mips32_ctx_t *ctx, uint32_t sp)
{
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
}

int32_t mips_sc_kill(mips32_ctx_t *ctx, uint32_t sp)
{
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
}

void mips_thread_exit(mips32_ctx_t *ctx, int status)
{
    (void)ctx;
    _Exit(status & 0xFF);
}

/* AOT note/warm/flush: silent best-effort in production; no-ops here. */
void mips32_aot_note_block(mips32_ctx_t *ctx, uint32_t guest_pc,
                           uint32_t guest_end)
{
    (void)ctx;
    (void)guest_pc;
    (void)guest_end;
}

void mips32_aot_warm(mips32_ctx_t *ctx)
{
    (void)ctx;
}

void mips32_aot_flush(mips32_ctx_t *ctx)
{
    (void)ctx;
}

/* Host-fault guard: only dbt_main arms it; the probes never run code. */
void mips_hostfault_install(const void *pool, size_t len)
{
    (void)pool;
    (void)len;
}

int mips_hostfault_run(mips32_ctx_t *ctx, void *code, uint32_t *reasonp)
{
    (void)ctx;
    (void)code;
    (void)reasonp;
    return 0;
}

void mips_hostfault_disarm(void)
{
}

void mips_dump_regs(const mips32_ctx_t *ctx, FILE *out)
{
    (void)ctx;
    (void)out;
}

uint32_t dbt_trampoline_enter(mips32_ctx_t *ctx, void *code)
{
    (void)ctx;
    (void)code;
    return 0U;
}

/* ---- Little-endian guest helpers (all probes run LE guests) ---- */

static void put32(mips32_ctx_t *c, uint32_t va, uint32_t v)
{
    uint8_t *h = (uint8_t *)mips32_guest_ptr(c, va);

    h[0] = (uint8_t)(v & 0xFFU);
    h[1] = (uint8_t)((v >> 8) & 0xFFU);
    h[2] = (uint8_t)((v >> 16) & 0xFFU);
    h[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static uint32_t get32(mips32_ctx_t *c, uint32_t va)
{
    const uint8_t *h = (const uint8_t *)mips32_guest_ptr(c, va);

    return (uint32_t)h[0] | ((uint32_t)h[1] << 8) |
           ((uint32_t)h[2] << 16) | ((uint32_t)h[3] << 24);
}

static uint64_t get64(mips32_ctx_t *c, uint32_t va)
{
    uint64_t lo = (uint64_t)get32(c, va);

    return lo | ((uint64_t)get32(c, va + 4U) << 32);
}

/* Install a signal handler the way the O32 dispatcher sees it. */
static void install_handler(mips32_ctx_t *c, uint32_t signo, uint32_t handler)
{
    put32(c, 0x60001000U, 0U);
    put32(c, 0x60001004U, handler);
    put32(c, 0x60001008U, 0U);
    put32(c, 0x6000100CU, 0U);
    put32(c, 0x60001010U, 0U);
    put32(c, 0x60001014U, 0U);
    c->gpr[MIPS32_REG_A0] = signo;
    c->gpr[MIPS32_REG_A0 + 1U] = 0x60001000U;
    c->gpr[MIPS32_REG_A0 + 2U] = 0U;
    c->gpr[MIPS32_REG_A0 + 3U] = 16U;
    CHECK(mips_sc_rt_sigaction(c, 0U) == 0);
}

static void prep_delivery(mips32_ctx_t *c)
{
    memset(c->sig_blocked, 0, sizeof(c->sig_blocked));
    c->gpr[MIPS32_REG_SP] = 0x60001F00U;
    c->sig_depth = 0U;
    c->in_delay_slot = 0U;
    c->exit_reason = MIPS32_EXIT_NONE;
    c->exit_info = 0U;
}

static mips32_ctx_t vmctx;

#define CODE_BASE 0x40000000U

int main(void)
{
    mips32_ctx_t *c = &vmctx;
    uint32_t r;
    uint32_t newsp;

    memset(c, 0, sizeof(*c));
    CHECK(rt32_vm_init(c, UINT64_MAX) == 0);
    CHECK(mips32_vm32_init(c) == 0);
    CHECK(rt32_vm_mmap2(c, CODE_BASE, 0x2000U,
                        (uint32_t)(PROT_READ | PROT_WRITE | PROT_EXEC),
                        0x02U | 0x20U | 0x10U, -1, 0U) == CODE_BASE);
    CHECK(rt32_vm_mmap2(c, 0x60000000U, 0x2000U,
                        (uint32_t)(PROT_READ | PROT_WRITE),
                        0x02U | 0x20U | 0x10U, -1, 0U) == 0x60000000U);

    /* T1: ADD overflow -> SIGFPE si_code 2, rd unchanged. */
    install_handler(c, 8U, 0x5000U);
    put32(c, CODE_BASE, 0x012A4020U);
    c->gpr[9] = 0x7FFFFFFFU;
    c->gpr[10] = 1U;
    c->gpr[8] = 0U;
    c->pc = CODE_BASE;
    c->next_pc = CODE_BASE + 4U;
    prep_delivery(c);
    CHECK(interp_step(c) == MIPS_FAULT);
    CHECK(c->exit_reason == MIPS32_EXIT_NONE);
    CHECK(c->pc == 0x5000U);
    newsp = c->gpr[MIPS32_REG_SP];
    CHECK(get32(c, newsp + 24U) == 8U);
    CHECK(get32(c, newsp + 28U) == 2U);
    CHECK(get32(c, newsp + 36U) == CODE_BASE);
    CHECK(c->gpr[8] == 0U);

    /* T2: SUB underflow -> SIGFPE si_code 2, rd unchanged. */
    put32(c, CODE_BASE, 0x012A4022U);
    c->gpr[9] = 0x80000000U;
    c->gpr[10] = 1U;
    c->gpr[8] = 0x12345678U;
    c->pc = CODE_BASE;
    c->next_pc = CODE_BASE + 4U;
    prep_delivery(c);
    CHECK(interp_step(c) == MIPS_FAULT);
    CHECK(c->pc == 0x5000U);
    newsp = c->gpr[MIPS32_REG_SP];
    CHECK(get32(c, newsp + 24U) == 8U);
    CHECK(get32(c, newsp + 28U) == 2U);
    CHECK(c->gpr[8] == 0x12345678U);

    /* T3: ADDI overflow -> SIGFPE si_code 2, rt unchanged. */
    put32(c, CODE_BASE, 0x21280001U);
    c->gpr[9] = 0x7FFFFFFFU;
    c->gpr[8] = 0xAAAAAAAAU;
    c->pc = CODE_BASE;
    c->next_pc = CODE_BASE + 4U;
    prep_delivery(c);
    CHECK(interp_step(c) == MIPS_FAULT);
    CHECK(c->pc == 0x5000U);
    newsp = c->gpr[MIPS32_REG_SP];
    CHECK(get32(c, newsp + 28U) == 2U);
    CHECK(c->gpr[8] == 0xAAAAAAAAU);

    /* T4: faulting ADD in a delay slot names the branch, keeps rd. */
    put32(c, CODE_BASE + 0x100U, 0x10000002U);
    put32(c, CODE_BASE + 0x104U, 0x012A4020U);
    c->gpr[9] = 0x7FFFFFFFU;
    c->gpr[10] = 1U;
    c->gpr[8] = 0xBBBBBBBBU;
    c->pc = CODE_BASE + 0x100U;
    c->next_pc = CODE_BASE + 0x104U;
    prep_delivery(c);
    CHECK(interp_step(c) == MIPS_FAULT);
    CHECK(c->pc == 0x5000U);
    newsp = c->gpr[MIPS32_REG_SP];
    CHECK(get32(c, newsp + 28U) == 2U);
    CHECK(get64(c, newsp + 184U) == (uint64_t)(CODE_BASE + 0x100U));
    CHECK(c->gpr[8] == 0xBBBBBBBBU);

    /* T5: emitter declines trapping ALU in delay slots (M32-R14-1). */
    {
        static uint8_t staging[65536];
        mips_dec_t insns[2];
        mips32_ctx_t ec;
        size_t out_len = 0U;
        uint32_t out_end = 0U;

        memset(&ec, 0, sizeof(ec));
        mips_decode(0x10000002U, &insns[0]);
        mips_decode(0x012A4020U, &insns[1]);
        CHECK(dbt_emit_int(&ec, CODE_BASE + 0x100U, insns, 2U, staging,
                           sizeof(staging), &out_len, &out_end) == 0);
        CHECK(out_end == CODE_BASE + 0x100U);
        mips_decode(0x012A4021U, &insns[1]);
        out_len = 0U;
        out_end = 0U;
        CHECK(dbt_emit_int(&ec, CODE_BASE + 0x100U, insns, 2U, staging,
                           sizeof(staging), &out_len, &out_end) == 0);
        CHECK(out_end == CODE_BASE + 0x108U);
        mips_decode(0x012A4020U, &insns[1]);
        out_len = 0U;
        out_end = 0U;
        CHECK(dbt_emit_int(&ec, CODE_BASE, &insns[1], 1U, staging,
                           sizeof(staging), &out_len, &out_end) == 0);
        CHECK(out_end == CODE_BASE + 4U);
    }

    /* T6: unaligned block start faults as align, not mapping (M32-R14-2). */
    install_handler(c, 10U, 0x5004U);
    c->pc = CODE_BASE + 1U;
    c->next_pc = CODE_BASE + 5U;
    prep_delivery(c);
    CHECK(dbt_compile(c, CODE_BASE + 1U) == MIPS_FAULT);
    CHECK(c->pc == 0x5004U);
    newsp = c->gpr[MIPS32_REG_SP];
    CHECK(get32(c, newsp + 24U) == 10U);
    CHECK(get32(c, newsp + 28U) == 1U);
    CHECK(get32(c, newsp + 36U) == CODE_BASE + 1U);

    /* T7: dead SC on PROT_READ faults with rt and the word kept. */
    CHECK(rt32_vm_mmap2(c, 0x41000000U, 0x1000U,
                        (uint32_t)(PROT_READ | PROT_WRITE),
                        0x02U | 0x20U | 0x10U, -1, 0U) == 0x41000000U);
    put32(c, 0x41000000U, 0xDEADBEEFU);
    CHECK(rt32_vm_mprotect(c, 0x41000000U, 0x1000U,
                           (uint32_t)PROT_READ) == 0);
    install_handler(c, 11U, 0x5008U);
    {
        int ok = -1;
        c->llbit = 0U;
        c->lladdr = 0U;
        CHECK(guest_sc32(c, 0x41000000U, 0xDEADBEEFU, 0x12345678U,
                         &ok) == MIPS_FAULT);
        CHECK(ok == -1);
        CHECK(get32(c, 0x41000000U) == 0xDEADBEEFU);
    }
    CHECK(rt32_vm_mprotect(c, 0x41000000U, 0x1000U,
                           (uint32_t)(PROT_READ | PROT_WRITE)) == 0);
    {
        int ok = -1;
        c->llbit = 0U;
        CHECK(guest_sc32(c, 0x41000000U, 0xDEADBEEFU, 0x12345678U,
                         &ok) == 0);
        CHECK(ok == 0);
        CHECK(get32(c, 0x41000000U) == 0xDEADBEEFU);
    }
    {
        int ok = -1;
        put32(c, 0x41000000U, 0x11111111U);
        mips_ll_record(c, 0x41000000U, 0x11111111U);
        CHECK(guest_sc32(c, 0x41000000U, 0x11111111U, 0x22222222U,
                         &ok) == 0);
        CHECK(ok == 1);
        CHECK(get32(c, 0x41000000U) == 0x22222222U);
    }
    put32(c, CODE_BASE + 0x200U, 0xE1280000U);
    CHECK(rt32_vm_mprotect(c, 0x41000000U, 0x1000U,
                           (uint32_t)PROT_READ) == 0);
    c->gpr[9] = 0x41000000U;
    c->gpr[8] = 0xCCCCCCCCU;
    c->llbit = 0U;
    c->pc = CODE_BASE + 0x200U;
    c->next_pc = CODE_BASE + 0x204U;
    prep_delivery(c);
    CHECK(interp_step(c) == MIPS_FAULT);
    CHECK(c->pc == 0x5008U);
    CHECK(c->gpr[8] == 0xCCCCCCCCU);
    newsp = c->gpr[MIPS32_REG_SP];
    CHECK(get32(c, newsp + 24U) == 11U);
    CHECK(rt32_vm_mprotect(c, 0x41000000U, 0x1000U,
                           (uint32_t)(PROT_READ | PROT_WRITE)) == 0);

    /* T8: mremap grows, moves, faults, and wires through mips_syscall. */
    CHECK(4167U == 4000U + 167U);
    CHECK(rt32_vm_mmap2(c, 0x42000000U, 0x2000U,
                        (uint32_t)(PROT_READ | PROT_WRITE),
                        0x02U | 0x20U | 0x10U, -1, 0U) == 0x42000000U);
    put32(c, 0x42000100U, 0xA5A5A5A5U);
    r = rt32_vm_mremap(c, 0x42000000U, 0x1000U, 0x1000U, 0U, 0U);
    CHECK(r == 0x42000000U);
    CHECK(get32(c, 0x42000100U) == 0xA5A5A5A5U);
    r = rt32_vm_mremap(c, 0x42000000U, 0x1000U, 0x2000U, 1U, 0U);
    CHECK(r <= 0xFFFFF000U);
    CHECK(get32(c, r + 0x100U) == 0xA5A5A5A5U);
    if (r != 0x42000000U) {
        CHECK(!mips32_range_ok(c, 0x42000000U, 1U, 0U));
    }
    CHECK(rt32_vm_mmap2(c, 0x43000000U, 0x1000U,
                        (uint32_t)(PROT_READ | PROT_WRITE),
                        0x02U | 0x20U | 0x10U, -1, 0U) == 0x43000000U);
    put32(c, 0x43000000U, 0x5A5A5A5AU);
    r = rt32_vm_mremap(c, 0x43000000U, 0x1000U, 0x1000U, 1U | 2U,
                       0x44000000U);
    CHECK(r == 0x44000000U);
    CHECK(get32(c, 0x44000000U) == 0x5A5A5A5AU);
    CHECK(!mips32_range_ok(c, 0x43000000U, 1U, 0U));
    CHECK(rt32_vm_mremap(c, 0x45000000U, 0x1000U, 0x1000U, 1U,
                         0U) == (uint32_t)-(int32_t)14);
    CHECK(rt32_vm_mremap(c, 0x44000000U, 0x1000U, 0U, 1U,
                         0U) == (uint32_t)-(int32_t)22);
    CHECK(rt32_vm_mremap(c, 0x44000000U, 0x1000U, 0x1000U, 4U,
                         0U) == (uint32_t)-(int32_t)22);
    CHECK(rt32_vm_mmap2(c, 0x46000000U, 0x1000U,
                        (uint32_t)(PROT_READ | PROT_WRITE),
                        0x02U | 0x20U | 0x10U, -1, 0U) == 0x46000000U);
    put32(c, 0x46000000U, 0xDEADCAFEU);
    c->gpr[MIPS32_REG_V0] = 4167U;
    c->gpr[MIPS32_REG_SP] = 0x60001F00U;
    c->gpr[MIPS32_REG_A0] = 0x46000000U;
    c->gpr[MIPS32_REG_A0 + 1U] = 0x1000U;
    c->gpr[MIPS32_REG_A0 + 2U] = 0x1000U;
    c->gpr[MIPS32_REG_A0 + 3U] = 0U;
    CHECK(mips_syscall(c) == (int32_t)0x46000000);
    CHECK(c->gpr[MIPS32_REG_V0] == 0x46000000U);
    CHECK(c->gpr[MIPS32_REG_A3] == 0U);
    CHECK(get32(c, 0x46000000U) == 0xDEADCAFEU);
    put32(c, 0x60001F00U + 16U, 0x47000000U);
    c->gpr[MIPS32_REG_V0] = 4167U;
    c->gpr[MIPS32_REG_A0] = 0x46000000U;
    c->gpr[MIPS32_REG_A0 + 1U] = 0x1000U;
    c->gpr[MIPS32_REG_A0 + 2U] = 0x1000U;
    c->gpr[MIPS32_REG_A0 + 3U] = 1U | 2U;
    CHECK(mips_syscall(c) == (int32_t)0x47000000);
    CHECK(c->gpr[MIPS32_REG_V0] == 0x47000000U);
    CHECK(c->gpr[MIPS32_REG_A3] == 0U);
    CHECK(get32(c, 0x47000000U) == 0xDEADCAFEU);
    CHECK(!mips32_range_ok(c, 0x46000000U, 1U, 0U));

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
