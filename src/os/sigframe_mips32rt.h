/* Frozen target O32 Linux UAPI signal-frame types for mips32rt.
 *
 * Models the MIPS O32 kernel ABI (arch/mips/include/uapi/asm/):
 * 24-byte rt_sigframe prefix, 128-byte siginfo_t, 628-byte kernel
 * ucontext (with 592-byte sigcontext), 16-byte kernel sigset_t and
 * the 104-byte kernel stat64. All sizes and offsets match the
 * qemu-verified table in experiments/E04/FINDINGS.md.
 *
 * NOTE: the kernel rt_sigframe reconstruction itself was NOT observed
 * at runtime (qemu-user cannot execute kernel signal.c); it is derived
 * from the installed UAPI headers. See E04 section 8.
 *
 * Part of mips32rt, Apache-2.0, Copyright 2026 Moritz Angermann
 * <moritz@zw3rk.com>, zw3rk pte. ltd.
 */
#ifndef SIGFRAME_MIPS32RT_H
#define SIGFRAME_MIPS32RT_H

#include <stddef.h>
#include <stdint.h>

/* Kernel sigset_t on O32: _NSIG_WORDS x 4 = 16 bytes (E04 section 7).
 * This is the KERNEL 16-byte set, never the 128-byte glibc sigset_t. */
typedef struct {
	uint32_t sig[4];
} mips_sigset_t;

_Static_assert(sizeof(mips_sigset_t) == 16, "kernel sigset_t must be 16 bytes");
_Static_assert(offsetof(mips_sigset_t, sig) == 0, "sig word array at 0");

/* Kernel siginfo_t: 128 bytes, signo@0 code@4 errno@8 (E04 section 3).
 * si_code comes BEFORE si_errno. */
typedef struct {
	int32_t si_signo;
	int32_t si_code;
	int32_t si_errno;
	uint8_t sifields[116];
} mips_siginfo_t;

_Static_assert(sizeof(mips_siginfo_t) == 128, "siginfo_t must be 128 bytes");
_Static_assert(offsetof(mips_siginfo_t, si_signo) == 0, "si_signo at 0");
_Static_assert(offsetof(mips_siginfo_t, si_code) == 4, "si_code at 4");
_Static_assert(offsetof(mips_siginfo_t, si_errno) == 8, "si_errno at 8");

/* Kernel stack_t: 12 bytes, sp@0 size@4 flags@8 (E04 section 3). */
typedef struct {
	uint32_t ss_sp;
	uint32_t ss_size;
	int32_t ss_flags;
} mips_stack_t;

_Static_assert(sizeof(mips_stack_t) == 12, "stack_t must be 12 bytes");
_Static_assert(offsetof(mips_stack_t, ss_sp) == 0, "ss_sp at 0");
_Static_assert(offsetof(mips_stack_t, ss_size) == 4, "ss_size at 4");
_Static_assert(offsetof(mips_stack_t, ss_flags) == 8, "ss_flags at 8");

/* O32 sigcontext (= mcontext layout): 592 bytes (E04 section 4).
 * sc_regs and sc_fpregs use 64-bit slots even on O32. */
typedef struct {
	uint32_t sc_regmask;
	uint32_t sc_status;
	uint64_t sc_pc;
	uint64_t sc_regs[32];
	uint64_t sc_fpregs[32];
	uint32_t sc_ownedfp;
	uint32_t sc_fpc_csr;
	uint32_t sc_fpc_eir;
	uint32_t sc_used_math;
	uint32_t sc_dsp;
	uint32_t sc_pad;
	uint64_t sc_mdhi;
	uint64_t sc_mdlo;
	uint32_t sc_hi1;
	uint32_t sc_lo1;
	uint32_t sc_hi2;
	uint32_t sc_lo2;
	uint32_t sc_hi3;
	uint32_t sc_lo3;
} mips_sigcontext_t;

_Static_assert(sizeof(mips_sigcontext_t) == 592, "sigcontext must be 592 bytes");
_Static_assert(offsetof(mips_sigcontext_t, sc_regmask) == 0, "sc_regmask at 0");
_Static_assert(offsetof(mips_sigcontext_t, sc_status) == 4, "sc_status at 4");
_Static_assert(offsetof(mips_sigcontext_t, sc_pc) == 8, "sc_pc at 8");
_Static_assert(offsetof(mips_sigcontext_t, sc_regs) == 16, "sc_regs at 16");
_Static_assert(offsetof(mips_sigcontext_t, sc_fpregs) == 272, "sc_fpregs at 272");
_Static_assert(offsetof(mips_sigcontext_t, sc_ownedfp) == 528, "sc_ownedfp at 528");
_Static_assert(offsetof(mips_sigcontext_t, sc_fpc_csr) == 532, "sc_fpc_csr at 532");
_Static_assert(offsetof(mips_sigcontext_t, sc_fpc_eir) == 536, "sc_fpc_eir at 536");
_Static_assert(offsetof(mips_sigcontext_t, sc_used_math) == 540, "sc_used_math at 540");
_Static_assert(offsetof(mips_sigcontext_t, sc_dsp) == 544, "sc_dsp at 544");
_Static_assert(offsetof(mips_sigcontext_t, sc_mdhi) == 552, "sc_mdhi at 552");
_Static_assert(offsetof(mips_sigcontext_t, sc_mdlo) == 560, "sc_mdlo at 560");
_Static_assert(offsetof(mips_sigcontext_t, sc_hi1) == 568, "sc_hi1 at 568");
_Static_assert(offsetof(mips_sigcontext_t, sc_lo1) == 572, "sc_lo1 at 572");
_Static_assert(offsetof(mips_sigcontext_t, sc_hi2) == 576, "sc_hi2 at 576");
_Static_assert(offsetof(mips_sigcontext_t, sc_lo2) == 580, "sc_lo2 at 580");
_Static_assert(offsetof(mips_sigcontext_t, sc_hi3) == 584, "sc_hi3 at 584");
_Static_assert(offsetof(mips_sigcontext_t, sc_lo3) == 588, "sc_lo3 at 588");

/* Kernel struct ucontext (O32): 632 bytes (E04 section 8, UNVERIFIED by
 * execution: derived from UAPI headers asm/signal.h, asm/ucontext.h,
 * asm/sigcontext.h, not observed at runtime).
 * CAUTION: this deliberately differs from E04 section 8's naive
 * 4+4+12+592+16 = 628 arithmetic, which omits alignment padding. The
 * 592-byte sigcontext needs 8-byte alignment (its u64 members sit at
 * 8-aligned offsets per E04 section 4), so a 4-byte pad follows the
 * 12-byte stack_t and uc_mcontext sits at 24, exactly as E04 section 3
 * proves for the identically-shaped glibc ucontext (mcontext@24). */
typedef struct {
	uint32_t uc_flags;
	uint32_t uc_link;
	mips_stack_t uc_stack;
	uint32_t uc_pad;
	mips_sigcontext_t uc_mcontext;
	mips_sigset_t uc_sigmask;
} mips_ucontext_t;

_Static_assert(sizeof(mips_ucontext_t) == 632, "kernel ucontext must be 632 bytes");
_Static_assert(offsetof(mips_ucontext_t, uc_flags) == 0, "uc_flags at 0");
_Static_assert(offsetof(mips_ucontext_t, uc_link) == 4, "uc_link at 4");
_Static_assert(offsetof(mips_ucontext_t, uc_stack) == 8, "uc_stack at 8");
_Static_assert(offsetof(mips_ucontext_t, uc_mcontext) == 24, "uc_mcontext at 24");
_Static_assert(offsetof(mips_ucontext_t, uc_sigmask) == 616, "uc_sigmask at 616");

/* Kernel rt_sigframe (O32): 24-byte prefix + siginfo + ucontext = 784
 * bytes (E04 section 8, UNVERIFIED by execution: exact final
 * size/alignments come from arch/mips/kernel/signal.c
 * setup_rt_frame, left to Phase 0 against real-kernel sources). */
typedef struct {
	uint32_t rs_ass[4];
	uint32_t rs_pad[2];
	mips_siginfo_t rs_info;
	mips_ucontext_t rs_uc;
} mips_rt_sigframe_t;

_Static_assert(sizeof(mips_rt_sigframe_t) == 784, "rt_sigframe must be 784 bytes");
_Static_assert(offsetof(mips_rt_sigframe_t, rs_ass) == 0, "rs_ass at 0");
_Static_assert(offsetof(mips_rt_sigframe_t, rs_pad) == 16, "rs_pad at 16");
_Static_assert(offsetof(mips_rt_sigframe_t, rs_info) == 24, "rs_info at 24");
_Static_assert(offsetof(mips_rt_sigframe_t, rs_uc) == 152, "rs_uc at 152");

/* Kernel UAPI struct stat64 (asm/stat.h, ABI32): 104 bytes, hand-computed
 * from the installed header (E04 section 6). This is the KERNEL layout
 * used for stat64/lstat64/fstat64, NOT the 160-byte glibc struct. */
typedef struct {
	uint32_t st_dev;
	uint32_t st_pad1[3];
	uint64_t st_ino;
	uint32_t st_mode;
	uint32_t st_nlink;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t st_rdev;
	uint32_t st_pad2[3];
	int64_t st_size;
	int32_t st_atime;
	uint32_t st_atime_nsec;
	int32_t st_mtime;
	uint32_t st_mtime_nsec;
	int32_t st_ctime;
	uint32_t st_ctime_nsec;
	uint32_t st_blksize;
	uint32_t st_pad3;
	int64_t st_blocks;
} mips_stat64_t;

_Static_assert(sizeof(mips_stat64_t) == 104, "kernel stat64 must be 104 bytes");
_Static_assert(offsetof(mips_stat64_t, st_dev) == 0, "st_dev at 0");
_Static_assert(offsetof(mips_stat64_t, st_ino) == 16, "st_ino at 16");
_Static_assert(offsetof(mips_stat64_t, st_mode) == 24, "st_mode at 24");
_Static_assert(offsetof(mips_stat64_t, st_nlink) == 28, "st_nlink at 28");
_Static_assert(offsetof(mips_stat64_t, st_uid) == 32, "st_uid at 32");
_Static_assert(offsetof(mips_stat64_t, st_gid) == 36, "st_gid at 36");
_Static_assert(offsetof(mips_stat64_t, st_size) == 56, "st_size at 56");
_Static_assert(offsetof(mips_stat64_t, st_blksize) == 88, "st_blksize at 88");
_Static_assert(offsetof(mips_stat64_t, st_blocks) == 96, "st_blocks at 96");

#endif
