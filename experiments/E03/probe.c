/*
 * E03 probe: FR=0 vs FR=1 and Legacy vs 2008 NaN / ABS FPU semantics.
 *
 * Curated C11 (-std=c11 -pedantic -Wall -Wextra -Werror).
 * Cross-compiled for MIPS32r2 O32 (mipsel LE, mips BE) and run under
 * qemu-mipsel / qemu-mips. All machine-specific behaviour below is
 * observed ground truth from those runs, recorded in FINDINGS.md.
 *
 * Covers:
 *  (1) quiet vs signaling NaN bit patterns (float + double);
 *  (2) MFC1/MTC1 32-bit and MFHC1/MTHC1 64-bit GPR<->FPR moves;
 *  (3) ABS.S/ABS.D on sNaN: trap (Legacy) vs silent (2008), via SIGFPE
 *      with the FCSR Invalid-Operation enable bit set;
 *  plus FCSR/FIR dumps and sizeof/offsetof tables.
 */
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t f_bits(float f)
{
	uint32_t u;

	memcpy(&u, &f, sizeof u);
	return u;
}

static float u_float(uint32_t u)
{
	float f;

	memcpy(&f, &u, sizeof f);
	return f;
}

static uint64_t d_bits(double d)
{
	uint64_t u;

	memcpy(&u, &d, sizeof u);
	return u;
}

static double u_double(uint64_t u)
{
	double d;

	memcpy(&d, &u, sizeof d);
	return d;
}

static uint32_t read_fcsr(void)
{
	uint32_t v;

	__asm__ volatile("cfc1 %0, $31" : "=r"(v));
	return v;
}

static void write_fcsr(uint32_t v)
{
	__asm__ volatile("ctc1 %0, $31" : : "r"(v));
}

static uint32_t read_fir(void)
{
	uint32_t v;

	__asm__ volatile("cfc1 %0, $0" : "=r"(v));
	return v;
}

/* (2a) 32-bit GPR<->FPR round trip through $f0. */
static uint32_t mfc1_roundtrip(uint32_t in)
{
	uint32_t out;

	__asm__ volatile("mtc1 %1, $f0\n\tmfc1 %0, $f0"
			 : "=r"(out)
			 : "r"(in));
	return out;
}

/* (2b) 64-bit GPR<->FPR round trip through the $f0/$f1 pair
 * (MIPS32r2 MFHC1/MTHC1). Requires -march=mips32r2 or later. */
static void mfhc1_roundtrip(uint32_t lo, uint32_t hi, uint32_t *rlo,
			    uint32_t *rhi)
{
	uint32_t o0;
	uint32_t o1;

	__asm__ volatile("mtc1 %2, $f0\n\t"
			 "mthc1 %3, $f0\n\t"
			 "mfc1 %0, $f0\n\t"
			 "mfhc1 %1, $f0\n\t"
			 : "=r"(o0), "=r"(o1)
			 : "r"(lo), "r"(hi));
	*rlo = o0;
	*rhi = o1;
}

static float abs_s(float f)
{
	float r;

	__asm__ volatile("abs.s %0, %1" : "=f"(r) : "f"(f));
	return r;
}

static double abs_d(double d)
{
	double r;

	__asm__ volatile("abs.d %0, %1" : "=f"(r) : "f"(d));
	return r;
}

static float add_s(float a, float b)
{
	float r;

	__asm__ volatile("add.s %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
	return r;
}

static jmp_buf sj;
static volatile sig_atomic_t got_sigfpe;

static void on_fpe(int s)
{
	(void)s;
	got_sigfpe = 1;
	longjmp(sj, 1);
}

/*
 * Run ABS.S on the given bit pattern with the FCSR Invalid-Operation
 * trap ENABLED (enable bit V, FCSR bit 11). Returns 1 if SIGFPE was
 * raised (Legacy trap), 0 if it completed silently (2008). Result bits
 * and the post-op FCSR are reported through the out parameters.
 */
static int abs_s_trap_test(uint32_t bits, uint32_t *res, uint32_t *fcsr)
{
	float f = u_float(bits);

	got_sigfpe = 0;
	write_fcsr(1u << 11); /* enable Invalid-Operation trap only */
	if (setjmp(sj) == 0) {
		float r = abs_s(f);

		*res = f_bits(r);
		*fcsr = read_fcsr();
		write_fcsr(0u);
		return 0;
	}
	*res = 0xdead0000u;
	*fcsr = read_fcsr();
	write_fcsr(0u);
	return 1;
}

static int add_s_trap_test(uint32_t bits, uint32_t *res, uint32_t *fcsr)
{
	float f = u_float(bits);

	got_sigfpe = 0;
	write_fcsr(1u << 11); /* enable Invalid-Operation trap only */
	if (setjmp(sj) == 0) {
		float r = add_s(f, 1.0f);

		*res = f_bits(r);
		*fcsr = read_fcsr();
		write_fcsr(0u);
		return 0;
	}
	*res = 0xdead0000u;
	*fcsr = read_fcsr();
	write_fcsr(0u);
	return 1;
}

static int abs_d_trap_test(uint64_t bits, uint64_t *res, uint32_t *fcsr)
{
	double d = u_double(bits);

	got_sigfpe = 0;
	write_fcsr(1u << 11); /* enable Invalid-Operation trap only */
	if (setjmp(sj) == 0) {
		double r = abs_d(d);

		*res = d_bits(r);
		*fcsr = read_fcsr();
		write_fcsr(0u);
		return 0;
	}
	*res = 0xdead0000dead0000ull;
	*fcsr = read_fcsr();
	write_fcsr(0u);
	return 1;
}

static void print_fcsr(const char *tag, uint32_t fcsr)
{
	unsigned cause = (fcsr >> 12) & 0x3fu;
	unsigned en = (fcsr >> 7) & 0x1fu;
	unsigned fl = (fcsr >> 2) & 0x1fu;

	printf("%s: FCSR=0x%08x cause[VZOU IX]=0x%02x en=0x%02x flags=0x%02x "
	       "RM=%u FS=%u FO=%u FN=%u\n",
	       tag, fcsr, cause, en, fl, fcsr & 3u, (fcsr >> 24) & 1u,
	       (fcsr >> 22) & 1u, (fcsr >> 21) & 1u);
}

int main(void)
{
	uint32_t rlo;
	uint32_t rhi;
	uint32_t fcsr0;
	uint32_t fir;
	/* Legacy float: bit22=0 -> QNaN, bit22=1 -> SNaN.
	 * IEEE-2008 float: bit22=1 -> QNaN, bit22=0 -> SNaN. */
	const uint32_t f_lo_bit = 0x7fbfffffu; /* Legacy QNaN / 2008 SNaN */
	const uint32_t f_hi_bit = 0x7fffffffu; /* Legacy SNaN / 2008 QNaN */
	/* Legacy double: bit51=0 -> QNaN, bit51=1 -> SNaN (mirror of float). */
	const uint64_t d_lo_bit = 0x7ff7ffffffffffffull;
	const uint64_t d_hi_bit = 0x7ffffffffffbffffull;
	float qf;
	double qd;
	int i;

	if (signal(SIGFPE, on_fpe) == SIG_ERR) {
		printf("FAIL: cannot install SIGFPE handler\n");
		return 2;
	}

	printf("== sizes ==\n");
	printf("sizeof(float)=%u sizeof(double)=%u sizeof(void*)=%u\n",
	       (unsigned)sizeof(float), (unsigned)sizeof(double),
	       (unsigned)sizeof(void *));
	{
		uint16_t e = 1u;
		unsigned char c;

		memcpy(&c, &e, 1);
		printf("endian=%s\n", c == 1u ? "little" : "big");
	}

	fcsr0 = read_fcsr();
	fir = read_fir();
	printf("== FPU id ==\n");
	printf("FIR=0x%08x FCSR(reset)=0x%08x\n", fir, fcsr0);
	print_fcsr("fcsr-reset", fcsr0);
	printf("FIR: F64=%u L=%u W=%u 3D=%u PS=%u D=%u S=%u procid=0x%02x\n",
	       (fir >> 22) & 1u, (fir >> 21) & 1u, (fir >> 20) & 1u,
	       (fir >> 19) & 1u, (fir >> 18) & 1u, (fir >> 17) & 1u,
	       (fir >> 16) & 1u, (fir >> 8) & 0xffu);

	printf("== (1) NaN bit patterns ==\n");
	qf = 0.0f / 0.0f;
	qd = 0.0 / 0.0;
	printf("0.0f/0.0f bits=0x%08x\n", f_bits(qf));
	printf("0.0/0.0  bits=0x%016llx\n", (unsigned long long)d_bits(qd));
	printf("f_lo_bit=0x%08x (Legacy QNaN / 2008 SNaN)\n", f_lo_bit);
	printf("f_hi_bit=0x%08x (Legacy SNaN / 2008 QNaN)\n", f_hi_bit);
	printf("d_lo_bit=0x%016llx\n", (unsigned long long)d_lo_bit);
	printf("d_hi_bit=0x%016llx\n", (unsigned long long)d_hi_bit);
	/* sNaN quieting through arithmetic, Invalid trap still disabled. */
	write_fcsr(0u);
	for (i = 0; i < 2; i++) {
		uint32_t in = (i == 0) ? f_lo_bit : f_hi_bit;
		float r = add_s(u_float(in), 1.0f);
		uint32_t fc = read_fcsr();

		printf("add.s(0x%08x,1.0)=0x%08x fcsr=0x%08x\n", in,
		       f_bits(r), fc);
		write_fcsr(0u);
	}

	printf("== (2) GPR<->FPR moves ==\n");
	{
		const uint32_t pats[3] = { 0x12345678u, 0x00000000u,
					   0xffffffffu
		};

		for (i = 0; i < 3; i++) {
			uint32_t back = mfc1_roundtrip(pats[i]);

			printf("mtc1/mfc1 in=0x%08x out=0x%08x %s\n",
			       pats[i], back,
			       back == pats[i] ? "OK" : "MISMATCH");
		}
	}
	mfhc1_roundtrip(0xdeadbeefu, 0x12345678u, &rlo, &rhi);
	printf("mtc1/mthc1/mfc1/mfhc1 lo=0xdeadbeef hi=0x12345678 -> "
	       "lo=0x%08x hi=0x%08x %s\n",
	       rlo, rhi,
	       (rlo == 0xdeadbeefu && rhi == 0x12345678u) ? "OK" : "MISMATCH");

	printf("== (3) ABS.S/ABS.D on sNaN (Invalid trap ENABLED) ==\n");
	{
		uint32_t res;
		uint32_t fc;
		int trapped;

		trapped = abs_s_trap_test(f_lo_bit, &res, &fc);
		printf("abs.s(0x%08x): trapped=%d res=0x%08x fcsr=0x%08x\n",
		       f_lo_bit, trapped, res, fc);
		trapped = abs_s_trap_test(f_hi_bit, &res, &fc);
		printf("abs.s(0x%08x): trapped=%d res=0x%08x fcsr=0x%08x\n",
		       f_hi_bit, trapped, res, fc);
	}
	{
		uint64_t res;
		uint32_t fc;
		int trapped;

		trapped = abs_d_trap_test(d_lo_bit, &res, &fc);
		printf("abs.d(0x%016llx): trapped=%d res=0x%016llx "
		       "fcsr=0x%08x\n",
		       (unsigned long long)d_lo_bit, trapped,
		       (unsigned long long)res, fc);
		trapped = abs_d_trap_test(d_hi_bit, &res, &fc);
		printf("abs.d(0x%016llx): trapped=%d res=0x%016llx "
		       "fcsr=0x%08x\n",
		       (unsigned long long)d_hi_bit, trapped,
		       (unsigned long long)res, fc);
	}
	/* Control: ADD.S on sNaN with the trap enabled must raise SIGFPE,
	 * proving the handler path works and abs results are meaningful. */
	{
		uint32_t res;
		uint32_t fc;
		int trapped;

		trapped = add_s_trap_test(f_lo_bit, &res, &fc);
		printf("add.s(0x%08x)+trap: trapped=%d res=0x%08x "
		       "fcsr=0x%08x\n",
		       f_lo_bit, trapped, res, fc);
		trapped = add_s_trap_test(f_hi_bit, &res, &fc);
		printf("add.s(0x%08x)+trap: trapped=%d res=0x%08x "
		       "fcsr=0x%08x\n",
		       f_hi_bit, trapped, res, fc);
	}

	/* Plain ABS on -1 (sanity: must just clear the sign bit). */
	printf("abs.s(-1.0f)=0x%08x (expect 0x3f800000)\n",
	       f_bits(abs_s(-1.0f)));
	printf("abs.d(-1.0)=0x%016llx (expect 0x3ff0000000000000)\n",
	       (unsigned long long)d_bits(abs_d(-1.0)));

	write_fcsr(0u);
	print_fcsr("fcsr-final", read_fcsr());
	printf("DONE\n");
	return 0;
}
