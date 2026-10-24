/* E04: O32 rt_sigframe layout and 128-signal UAPI probe (mipsel O32).
 *
 * Compile-time: sizeof/offsetof table for sigset_t, struct sigaction,
 *   ucontext_t, mcontext_t, struct sigcontext, siginfo_t, struct stat64.
 *   (glibc <signal.h> struct sigcontext is layout-identical to the
 *   kernel arch/mips struct sigcontext; the kernel rt_sigframe is
 *   { siginfo_t + ucontext_t } + trampoline, reconstructed in FINDINGS.)
 * Runtime: sigaction with 16-byte mask + raise(35) RT delivery proving
 *   the _NSIG=128 path works. Run under qemu-mipsel (LE) / qemu-mips (BE).
 *
 * Cross: mipsel-linux-gnu-gcc -std=c11 -Wall -Wextra -static probe.c
 */
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#define PS(T) \
	printf("sizeof(%s)=%lu\n", #T, (unsigned long)sizeof(T))
#define PO(T, m) \
	printf("offsetof(%s,%s)=%lu\n", #T, #m, \
	    (unsigned long)offsetof(T, m))

static volatile sig_atomic_t got_sig = 0;
static volatile int got_code = 0;
static unsigned long long seen_pc;
static unsigned long long seen_sp;	/* gregs[29] */
static unsigned int seen_fpc_csr;

static void rt_handler(int sig, siginfo_t *si, void *uc)
{
#ifdef __mips__
	ucontext_t *u = (ucontext_t *)uc;
#endif

	got_sig = sig;
	got_code = si ? si->si_code : -999;
#ifdef __mips__
	seen_pc = (unsigned long long)u->uc_mcontext.pc;
	seen_sp = (unsigned long long)u->uc_mcontext.gregs[29];
	seen_fpc_csr = u->uc_mcontext.fpc_csr;
#else
	seen_pc = 1;	/* non-MIPS native contrast: layout differs */
	seen_sp = 1;
	seen_fpc_csr = 0;
#endif
	(void)uc;
}

int main(void)
{
	struct sigaction sa;
	sigset_t full;

	/* ---- compile-time layout table ---- */
	printf("--- sizes ---\n");
	PS(sigset_t);
	PS(struct sigaction);
	PS(siginfo_t);
	PS(ucontext_t);
#ifdef __mips__
	PS(mcontext_t);
	PS(gregset_t);
	PS(fpregset_t);
	PS(greg_t);
	PS(struct sigcontext);
#endif
	PS(struct stat64);
	PS(stack_t);
	printf("--- sigaction offsets ---\n");
	PO(struct sigaction, sa_handler);
	PO(struct sigaction, sa_mask);
	PO(struct sigaction, sa_flags);
	PO(struct sigaction, sa_restorer);
	printf("--- ucontext offsets ---\n");
	PO(ucontext_t, uc_flags);
	PO(ucontext_t, uc_link);
	PO(ucontext_t, uc_stack);
	PO(ucontext_t, uc_mcontext);
	PO(ucontext_t, uc_sigmask);
	printf("--- stack_t offsets ---\n");
	PO(stack_t, ss_sp);
	PO(stack_t, ss_flags);
	PO(stack_t, ss_size);
	printf("--- mcontext (glibc o32) offsets ---\n");
#ifdef __mips__
	PO(mcontext_t, regmask);
	PO(mcontext_t, status);
	PO(mcontext_t, pc);
	PO(mcontext_t, gregs);
	PO(mcontext_t, fpregs);
	PO(mcontext_t, fp_owned);
	PO(mcontext_t, fpc_csr);
	PO(mcontext_t, fpc_eir);
	PO(mcontext_t, used_math);
	PO(mcontext_t, dsp);
	PO(mcontext_t, mdhi);
	PO(mcontext_t, mdlo);
	PO(mcontext_t, hi1);
	PO(mcontext_t, lo1);
	PO(mcontext_t, hi2);
	PO(mcontext_t, lo2);
	PO(mcontext_t, hi3);
	PO(mcontext_t, lo3);
	printf("--- sigcontext (kernel ABI32 layout) offsets ---\n");
	PO(struct sigcontext, sc_regmask);
	PO(struct sigcontext, sc_status);
	PO(struct sigcontext, sc_pc);
	PO(struct sigcontext, sc_regs);
	PO(struct sigcontext, sc_fpregs);
	PO(struct sigcontext, sc_ownedfp);
	PO(struct sigcontext, sc_fpc_csr);
	PO(struct sigcontext, sc_fpc_eir);
	PO(struct sigcontext, sc_used_math);
	PO(struct sigcontext, sc_dsp);
	PO(struct sigcontext, sc_mdhi);
	PO(struct sigcontext, sc_mdlo);
	PO(struct sigcontext, sc_hi1);
	PO(struct sigcontext, sc_lo1);
	PO(struct sigcontext, sc_hi2);
	PO(struct sigcontext, sc_lo2);
	PO(struct sigcontext, sc_hi3);
	PO(struct sigcontext, sc_lo3);
#endif
	printf("--- siginfo offsets ---\n");
	PO(siginfo_t, si_signo);
	PO(siginfo_t, si_errno);
	PO(siginfo_t, si_code);
	printf("--- stat64 ---\n");
	PO(struct stat64, st_dev);
	PO(struct stat64, st_ino);
	PO(struct stat64, st_mode);
	PO(struct stat64, st_nlink);
	PO(struct stat64, st_uid);
	PO(struct stat64, st_gid);
	PO(struct stat64, st_size);
	PO(struct stat64, st_blksize);
	PO(struct stat64, st_blocks);

	/* ---- UAPI constants ---- */
	printf("--- constants ---\n");
	printf("_NSIG=%d\n", _NSIG);
	printf("NSIG=%d\n", NSIG);
	printf("SIGRTMIN=%d\n", SIGRTMIN);
	printf("SIGRTMAX=%d\n", SIGRTMAX);
	printf("SI_QUEUE=%d\n", SI_QUEUE);

	/* ---- 16-byte (128-bit) sigset coverage ---- */
	sigfillset(&full);
	printf("--- sigset128 ---\n");
	printf("sigismember(1)=%d\n", sigismember(&full, 1));
	printf("sigismember(31)=%d\n", sigismember(&full, 31));
	printf("sigismember(32)=%d\n", sigismember(&full, 32));
	printf("sigismember(64)=%d\n", sigismember(&full, 64));
	printf("sigismember(120)=%d\n", sigismember(&full, 120));
	printf("sigismember(127)=%d\n", sigismember(&full, 127));

	/* ---- RT delivery via raise(35), masked set spans both halves ---- */
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = rt_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, 64);	/* upper half of the 16-byte set */
	sigaddset(&sa.sa_mask, 120);	/* deep RT range */
	if (sigaction(35, &sa, NULL) != 0) {
		printf("sigaction(35) FAILED errno=%d\n", errno);
		return 2;
	}
	if (raise(35) != 0) {
		printf("raise(35) FAILED errno=%d\n", errno);
		return 3;
	}
	printf("--- delivery ---\n");
	printf("got_sig=%d\n", (int)got_sig);
	printf("got_code=%d\n", (int)got_code);
	printf("seen_pc=0x%llx\n", seen_pc);
	printf("seen_sp=0x%llx\n", seen_sp);
	printf("seen_fpc_csr=0x%x\n", seen_fpc_csr);
	if (got_sig != 35) {
		printf("RESULT=FAIL expected 35\n");
		return 4;
	}
	if (seen_pc == 0 || seen_sp == 0) {
		printf("RESULT=FAIL null context\n");
		return 5;
	}

	/* ---- raw rt_sigprocmask: kernel sigsetsize probe ----
	 * Kernel sigset_t is _NSIG_WORDS x 4 bytes = 16 bytes on O32
	 * (linux/posix_types.h: _NSIG_WORDS = _NSIG/__BITS_PER_LONG).
	 * glibc passes _NSIG/8 = 16 for every rt_*sig syscall. */
	{
		sigset_t cur;
		long r;
		int e;

		memset(&cur, 0xA5, sizeof(cur));
		errno = 0;
		r = syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &cur, 16);
		e = errno;
		printf("raw_sigprocmask_size16=%ld errno=%d\n", r, e);
		errno = 0;
		r = syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &cur, 8);
		e = errno;
		printf("raw_sigprocmask_size8=%ld errno=%d\n", r, e);
		printf("kernel_sigset_bytes=%d\n", _NSIG / 8);
	}
	printf("RESULT=PASS\n");
	return 0;
}
