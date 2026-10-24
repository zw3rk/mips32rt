/* ABI invariant suite: verifies every SPEC 2.1 mips32_ctx_t offset/size
 * and every sigframe/ucontext/stat offset/size from
 * experiments/E04/FINDINGS.md, both at compile time (_Static_assert)
 * and at runtime (printf per check). Exit 0 only if all pass.
 *
 * Part of mips32rt, Apache-2.0, Copyright 2026 Moritz Angermann
 * <moritz@zw3rk.com>, zw3rk pte. ltd.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "mips32rt.h"
#include "os/sigframe_mips32rt.h"

static int failures = 0;
static int checks = 0;

#define CHECK_SIZE(type, want) do { \
		checks++; \
		if (sizeof(type) == (want)) { \
			printf("ok: sizeof(%s) == %u\n", #type, (unsigned)(want)); \
		} else { \
			printf("FAIL: sizeof(%s) == %u, want %u\n", \
			    #type, (unsigned)sizeof(type), (unsigned)(want)); \
			failures++; \
		} \
	} while (0)

#define CHECK_OFF(type, member, want) do { \
		checks++; \
		if (offsetof(type, member) == (want)) { \
			printf("ok: offsetof(%s, %s) == %u\n", \
			    #type, #member, (unsigned)(want)); \
		} else { \
			printf("FAIL: offsetof(%s, %s) == %u, want %u\n", \
			    #type, #member, \
			    (unsigned)offsetof(type, member), (unsigned)(want)); \
			failures++; \
		} \
	} while (0)

/* SPEC 2.1 mips32_ctx_t layout. */
_Static_assert(sizeof(mips32_ctx_t) == 0x1c0, "ctx size 0x1c0");
_Static_assert(offsetof(mips32_ctx_t, gpr) == 0x000, "gpr at 0x000");
_Static_assert(offsetof(mips32_ctx_t, pc) == 0x080, "pc at 0x080");
_Static_assert(offsetof(mips32_ctx_t, next_pc) == 0x084, "next_pc at 0x084");
_Static_assert(offsetof(mips32_ctx_t, hi) == 0x088, "hi at 0x088");
_Static_assert(offsetof(mips32_ctx_t, lo) == 0x08c, "lo at 0x08c");
_Static_assert(offsetof(mips32_ctx_t, ulr) == 0x090, "ulr at 0x090");
_Static_assert(offsetof(mips32_ctx_t, fcsr) == 0x094, "fcsr at 0x094");
_Static_assert(offsetof(mips32_ctx_t, in_delay_slot) == 0x098, "ids at 0x098");
_Static_assert(offsetof(mips32_ctx_t, fr_mode) == 0x099, "fr at 0x099");
_Static_assert(offsetof(mips32_ctx_t, llbit) == 0x09a, "llbit at 0x09a");
_Static_assert(offsetof(mips32_ctx_t, nan2008) == 0x09b, "nan2008 at 0x09b");
_Static_assert(offsetof(mips32_ctx_t, lladdr) == 0x09c, "lladdr at 0x09c");
_Static_assert(offsetof(mips32_ctx_t, llval) == 0x0a0, "llval at 0x0a0");
_Static_assert(offsetof(mips32_ctx_t, cp0_config1) == 0x0a4, "cfg1 at 0x0a4");
_Static_assert(offsetof(mips32_ctx_t, guest_base) == 0x0a8, "gbase at 0x0a8");
_Static_assert(offsetof(mips32_ctx_t, ibtc_ptr) == 0x0b0, "ibtc at 0x0b0");
_Static_assert(offsetof(mips32_ctx_t, exit_reason) == 0x0b8, "ereason at 0x0b8");
_Static_assert(offsetof(mips32_ctx_t, exit_info) == 0x0bc, "einfo at 0x0bc");
_Static_assert(offsetof(mips32_ctx_t, fpr) == 0x0c0, "fpr at 0x0c0");

/* Frozen UAPI sizes (E04 sections 3, 6, 7, 8). */
_Static_assert(sizeof(mips_sigset_t) == 16, "sigset 16");
_Static_assert(sizeof(mips_siginfo_t) == 128, "siginfo 128");
_Static_assert(sizeof(mips_stack_t) == 12, "stack 12");
_Static_assert(sizeof(mips_sigcontext_t) == 592, "sigcontext 592");
_Static_assert(sizeof(mips_ucontext_t) == 632, "ucontext 632");
_Static_assert(sizeof(mips_rt_sigframe_t) == 784, "sigframe 784");
_Static_assert(sizeof(mips_stat64_t) == 104, "stat64 104");

int main(void)
{
	/* SPEC 2.1 context. */
	CHECK_SIZE(mips32_ctx_t, 0x1c0);
	CHECK_OFF(mips32_ctx_t, gpr, 0x000);
	CHECK_OFF(mips32_ctx_t, pc, 0x080);
	CHECK_OFF(mips32_ctx_t, next_pc, 0x084);
	CHECK_OFF(mips32_ctx_t, hi, 0x088);
	CHECK_OFF(mips32_ctx_t, lo, 0x08c);
	CHECK_OFF(mips32_ctx_t, ulr, 0x090);
	CHECK_OFF(mips32_ctx_t, fcsr, 0x094);
	CHECK_OFF(mips32_ctx_t, in_delay_slot, 0x098);
	CHECK_OFF(mips32_ctx_t, fr_mode, 0x099);
	CHECK_OFF(mips32_ctx_t, llbit, 0x09a);
	CHECK_OFF(mips32_ctx_t, nan2008, 0x09b);
	CHECK_OFF(mips32_ctx_t, lladdr, 0x09c);
	CHECK_OFF(mips32_ctx_t, llval, 0x0a0);
	CHECK_OFF(mips32_ctx_t, cp0_config1, 0x0a4);
	CHECK_OFF(mips32_ctx_t, guest_base, 0x0a8);
	CHECK_OFF(mips32_ctx_t, ibtc_ptr, 0x0b0);
	CHECK_OFF(mips32_ctx_t, exit_reason, 0x0b8);
	CHECK_OFF(mips32_ctx_t, exit_info, 0x0bc);
	CHECK_OFF(mips32_ctx_t, fpr, 0x0c0);

	/* Sigset / siginfo / stack. */
	CHECK_SIZE(mips_sigset_t, 16);
	CHECK_SIZE(mips_siginfo_t, 128);
	CHECK_OFF(mips_siginfo_t, si_signo, 0);
	CHECK_OFF(mips_siginfo_t, si_code, 4);
	CHECK_OFF(mips_siginfo_t, si_errno, 8);
	CHECK_SIZE(mips_stack_t, 12);
	CHECK_OFF(mips_stack_t, ss_sp, 0);
	CHECK_OFF(mips_stack_t, ss_size, 4);
	CHECK_OFF(mips_stack_t, ss_flags, 8);

	/* Sigcontext (E04 section 4). */
	CHECK_SIZE(mips_sigcontext_t, 592);
	CHECK_OFF(mips_sigcontext_t, sc_regmask, 0);
	CHECK_OFF(mips_sigcontext_t, sc_status, 4);
	CHECK_OFF(mips_sigcontext_t, sc_pc, 8);
	CHECK_OFF(mips_sigcontext_t, sc_regs, 16);
	CHECK_OFF(mips_sigcontext_t, sc_fpregs, 272);
	CHECK_OFF(mips_sigcontext_t, sc_ownedfp, 528);
	CHECK_OFF(mips_sigcontext_t, sc_fpc_csr, 532);
	CHECK_OFF(mips_sigcontext_t, sc_fpc_eir, 536);
	CHECK_OFF(mips_sigcontext_t, sc_used_math, 540);
	CHECK_OFF(mips_sigcontext_t, sc_dsp, 544);
	CHECK_OFF(mips_sigcontext_t, sc_mdhi, 552);
	CHECK_OFF(mips_sigcontext_t, sc_mdlo, 560);
	CHECK_OFF(mips_sigcontext_t, sc_hi1, 568);
	CHECK_OFF(mips_sigcontext_t, sc_lo1, 572);
	CHECK_OFF(mips_sigcontext_t, sc_hi2, 576);
	CHECK_OFF(mips_sigcontext_t, sc_lo2, 580);
	CHECK_OFF(mips_sigcontext_t, sc_hi3, 584);
	CHECK_OFF(mips_sigcontext_t, sc_lo3, 588);

	/* Kernel ucontext (E04 section 8). */
	CHECK_SIZE(mips_ucontext_t, 632);
	CHECK_OFF(mips_ucontext_t, uc_flags, 0);
	CHECK_OFF(mips_ucontext_t, uc_link, 4);
	CHECK_OFF(mips_ucontext_t, uc_stack, 8);
	CHECK_OFF(mips_ucontext_t, uc_mcontext, 24);
	CHECK_OFF(mips_ucontext_t, uc_sigmask, 616);

	/* rt_sigframe (E04 section 8). */
	CHECK_SIZE(mips_rt_sigframe_t, 784);
	CHECK_OFF(mips_rt_sigframe_t, rs_ass, 0);
	CHECK_OFF(mips_rt_sigframe_t, rs_pad, 16);
	CHECK_OFF(mips_rt_sigframe_t, rs_info, 24);
	CHECK_OFF(mips_rt_sigframe_t, rs_uc, 152);

	/* Kernel stat64 (E04 section 6). */
	CHECK_SIZE(mips_stat64_t, 104);
	CHECK_OFF(mips_stat64_t, st_dev, 0);
	CHECK_OFF(mips_stat64_t, st_ino, 16);
	CHECK_OFF(mips_stat64_t, st_mode, 24);
	CHECK_OFF(mips_stat64_t, st_nlink, 28);
	CHECK_OFF(mips_stat64_t, st_uid, 32);
	CHECK_OFF(mips_stat64_t, st_gid, 36);
	CHECK_OFF(mips_stat64_t, st_size, 56);
	CHECK_OFF(mips_stat64_t, st_blksize, 88);
	CHECK_OFF(mips_stat64_t, st_blocks, 96);

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
