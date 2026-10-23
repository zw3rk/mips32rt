/*
 * E01: MIPS O32 syscall stack arguments 5..8 and the $a3 error flag.
 *
 * What this verifies under qemu-mipsel (and qemu-mips for BE):
 *  1. Syscall args 5..8 travel on the user stack at $sp+16/+20/+24/+28.
 *     Both the C calling convention (callee8 observation) and raw
 *     syscalls (mmap2 6-arg success, 8-arg invalid-syscall) prove it.
 *  2. 64-bit args align to even register pairs ($a0:$a1 or $a2:$a3).
 *  3. Success returns $a3=0/$v0=ret; errors return $a3=1/$v0=+errno.
 *
 * Curated C11: -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror.
 * No VLAs, no Annex K, no <threads.h>, no _Generic.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Sanity: these MIPS errno values are load-bearing for the checks below. */
/* MIPS is NOT asm-generic: ENOSYS is 89 on MIPS (EL2NSYNC owns 38). */
_Static_assert(ENOENT == 2, "ENOENT must be 2");
_Static_assert(EBADF == 9, "EBADF must be 9");
_Static_assert(ENOSYS == 89, "ENOSYS must be 89 on MIPS");

/* ------------------------------------------------------------------ */
/* Raw syscalls (musl-style): number in $v0, args 1..4 in $a0..$a3,    */
/* args 5..8 in caller-owned stack slots 16/20/24/28($sp). The        */
/* kernel answers $v0=ret/$a3=0 on success, $v0=+errno/$a3=1 on error. */
/* The trap itself is the `syscall` mnemonic -> word 0x0000000c.       */
/* ------------------------------------------------------------------ */

typedef struct {
	long v0;
	long a3;
} scres_t;

static scres_t raw_sys0(long n)
{
	register long r2 __asm__("$2") = n;
	register long r7 __asm__("$7") = 0;
	scres_t r;

	__asm__ volatile("syscall"
			 : "+r"(r2), "+r"(r7)
			 : /* no inputs */
			 : "memory");
	r.v0 = r2;
	r.a3 = r7;
	return r;
}

static scres_t raw_sys1(long n, long a)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r7 __asm__("$7") = 0;
	scres_t r;

	__asm__ volatile("syscall"
			 : "+r"(r2), "+r"(r7)
			 : "r"(r4)
			 : "memory");
	r.v0 = r2;
	r.a3 = r7;
	return r;
}

static scres_t raw_sys2(long n, long a, long b)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r5 __asm__("$5") = b;
	register long r7 __asm__("$7") = 0;
	scres_t r;

	__asm__ volatile("syscall"
			 : "+r"(r2), "+r"(r7)
			 : "r"(r4), "r"(r5)
			 : "memory");
	r.v0 = r2;
	r.a3 = r7;
	return r;
}

static scres_t raw_sys3(long n, long a, long b, long c)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r5 __asm__("$5") = b;
	register long r6 __asm__("$6") = c;
	register long r7 __asm__("$7") = 0;
	scres_t r;

	__asm__ volatile("syscall"
			 : "+r"(r2), "+r"(r7)
			 : "r"(r4), "r"(r5), "r"(r6)
			 : "memory");
	r.v0 = r2;
	r.a3 = r7;
	return r;
}

static scres_t raw_sys5(long n, long a, long b, long c, long d, long e)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r5 __asm__("$5") = b;
	register long r6 __asm__("$6") = c;
	register long r7 __asm__("$7") = d;
	register long r8 __asm__("$8") = e;
	scres_t r;

	__asm__ volatile("subu $sp, $sp, 32\n\t"
			 "sw $8, 16($sp)\n\t"
			 "syscall\n\t"
			 "move %[o0], $2\n\t"
			 "move %[o1], $7\n\t"
			 "addu $sp, $sp, 32"
			 : [o0] "=&r"(r.v0), [o1] "=&r"(r.a3)
			 : "r"(r2), "r"(r4), "r"(r5), "r"(r6), "r"(r7), "r"(r8)
			 : "memory");
	return r;
}

static scres_t raw_sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r5 __asm__("$5") = b;
	register long r6 __asm__("$6") = c;
	register long r7 __asm__("$7") = d;
	register long r8 __asm__("$8") = e;
	register long r9 __asm__("$9") = f;
	scres_t r;

	__asm__ volatile("subu $sp, $sp, 32\n\t"
			 "sw $8, 16($sp)\n\t"
			 "sw $9, 20($sp)\n\t"
			 "syscall\n\t"
			 "move %[o0], $2\n\t"
			 "move %[o1], $7\n\t"
			 "addu $sp, $sp, 32"
			 : [o0] "=&r"(r.v0), [o1] "=&r"(r.a3)
			 : "r"(r2), "r"(r4), "r"(r5), "r"(r6), "r"(r7),
			   "r"(r8), "r"(r9)
			 : "memory");
	return r;
}

static scres_t raw_sys8(long n, long a, long b, long c, long d,
			long e, long f, long g, long h)
{
	register long r2 __asm__("$2") = n;
	register long r4 __asm__("$4") = a;
	register long r5 __asm__("$5") = b;
	register long r6 __asm__("$6") = c;
	register long r7 __asm__("$7") = d;
	register long r8 __asm__("$8") = e;
	register long r9 __asm__("$9") = f;
	register long r10 __asm__("$10") = g;
	register long r11 __asm__("$11") = h;
	scres_t r;

	__asm__ volatile("subu $sp, $sp, 32\n\t"
			 "sw $8, 16($sp)\n\t"
			 "sw $9, 20($sp)\n\t"
			 "sw $10, 24($sp)\n\t"
			 "sw $11, 28($sp)\n\t"
			 "syscall\n\t"
			 "move %[o0], $2\n\t"
			 "move %[o1], $7\n\t"
			 "addu $sp, $sp, 32"
			 : [o0] "=&r"(r.v0), [o1] "=&r"(r.a3)
			 : "r"(r2), "r"(r4), "r"(r5), "r"(r6), "r"(r7),
			   "r"(r8), "r"(r9), "r"(r10), "r"(r11)
			 : "memory");
	return r;
}

/* ------------------------------------------------------------------ */
/* Callee-side observation in hand-written asm (no C prologue to skew  */
/* $sp): on entry $a0..$a3 hold args 1..4 and 16/20/24/28($sp) hold    */
/* args 5..8. Values are parked in globals for main() to report.       */
/* ------------------------------------------------------------------ */

uint32_t g_a0, g_a1, g_a2, g_a3;
uint32_t g_s5, g_s6, g_s7, g_s8;
uint32_t g_sp;

uint32_t h_a0, h_a1, h_a2, h_a3, h_s;
uint32_t h_sp;

/* Absolute %hi/%lo addressing: the translation unit assembles in PIC
 * (.abicalls) mode, where a bare `sw $4, sym` would go through $gp --
 * which non-PIC startup code never initializes. Explicit relocs stay
 * absolute in any mode, so these observers are safe in static PIE and
 * non-PIE links alike. Only $8/$9 (caller-saved temps) are touched. */
__asm__(
".text\n"
".globl callee8\n"
".ent callee8\n"
"callee8:\n"
"lui $8, %hi(g_a0)\n"
"sw $4, %lo(g_a0)($8)\n"
"lui $8, %hi(g_a1)\n"
"sw $5, %lo(g_a1)($8)\n"
"lui $8, %hi(g_a2)\n"
"sw $6, %lo(g_a2)($8)\n"
"lui $8, %hi(g_a3)\n"
"sw $7, %lo(g_a3)($8)\n"
"lw $9, 16($sp)\n"
"lui $8, %hi(g_s5)\n"
"sw $9, %lo(g_s5)($8)\n"
"lw $9, 20($sp)\n"
"lui $8, %hi(g_s6)\n"
"sw $9, %lo(g_s6)($8)\n"
"lw $9, 24($sp)\n"
"lui $8, %hi(g_s7)\n"
"sw $9, %lo(g_s7)($8)\n"
"lw $9, 28($sp)\n"
"lui $8, %hi(g_s8)\n"
"sw $9, %lo(g_s8)($8)\n"
"lui $8, %hi(g_sp)\n"
"sw $29, %lo(g_sp)($8)\n"
"jr $31\n"
".end callee8\n"
".globl caller8\n"
".ent caller8\n"
"caller8:\n"
"lw $8, 16($sp)\n"
"lw $9, 20($sp)\n"
"lw $10, 24($sp)\n"
"lw $11, 28($sp)\n"
"addiu $sp, $sp, -32\n"
"sw $31, 0($sp)\n"
"sw $8, 16($sp)\n"
"sw $9, 20($sp)\n"
"sw $10, 24($sp)\n"
"sw $11, 28($sp)\n"
"jal callee8\n"
"nop\n"
"lw $31, 0($sp)\n"
"addiu $sp, $sp, 32\n"
"jr $31\n"
"nop\n"
".end caller8\n"
".globl callee_ll\n"
".ent callee_ll\n"
"callee_ll:\n"
"lui $8, %hi(h_a0)\n"
"sw $4, %lo(h_a0)($8)\n"
"lui $8, %hi(h_a1)\n"
"sw $5, %lo(h_a1)($8)\n"
"lui $8, %hi(h_a2)\n"
"sw $6, %lo(h_a2)($8)\n"
"lui $8, %hi(h_a3)\n"
"sw $7, %lo(h_a3)($8)\n"
"lw $9, 16($sp)\n"
"lui $8, %hi(h_s)\n"
"sw $9, %lo(h_s)($8)\n"
"lui $8, %hi(h_sp)\n"
"sw $29, %lo(h_sp)($8)\n"
"jr $31\n"
".end callee_ll\n"
".globl callee_ll0\n"
".ent callee_ll0\n"
"callee_ll0:\n"
"lui $8, %hi(h_a0)\n"
"sw $4, %lo(h_a0)($8)\n"
"lui $8, %hi(h_a1)\n"
"sw $5, %lo(h_a1)($8)\n"
"lui $8, %hi(h_a2)\n"
"sw $6, %lo(h_a2)($8)\n"
"lui $8, %hi(h_a3)\n"
"sw $7, %lo(h_a3)($8)\n"
"lw $9, 16($sp)\n"
"lui $8, %hi(h_s)\n"
"sw $9, %lo(h_s)($8)\n"
"lui $8, %hi(h_sp)\n"
"sw $29, %lo(h_sp)($8)\n"
"jr $31\n"
".end callee_ll0\n");

void callee8(uint32_t m1, uint32_t m2, uint32_t m3, uint32_t m4,
	     uint32_t m5, uint32_t m6, uint32_t m7, uint32_t m8);
void caller8(uint32_t m1, uint32_t m2, uint32_t m3, uint32_t m4,
	     uint32_t m5, uint32_t m6, uint32_t m7, uint32_t m8);
void callee_ll(uint32_t tag, unsigned long long ll, uint32_t tail);
void callee_ll0(unsigned long long ll, uint32_t tail);

/* ------------------------------------------------------------------ */

static int g_fail = 0;

static void check(int cond, const char *msg)
{
	printf("  [%s] %s\n", cond ? "PASS" : "FAIL", msg);
	if (!cond)
		g_fail++;
}

static void print_u64(const char *name, unsigned long long v)
{
	printf("  %-10s = 0x%08lx%08lx (%llu)\n", name,
	       (unsigned long)(uint32_t)(v >> 32),
	       (unsigned long)(uint32_t)v, v);
}

int main(void)
{
	scres_t r;
	unsigned long long res;
	int fd;
	char tmp[64];
	const char msg[] = "e01-write-probe\n";
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	const char *endian = "little";
#else
	const char *endian = "big";
#endif

	printf("E01 O32 syscall stack-args + $a3 probe (%s-endian guest)\n",
	       endian);
	printf("sizeof(long)=%lu sizeof(long long)=%lu sizeof(void*)=%lu "
	       "sizeof(scres_t)=%lu offsetof(a3)=%lu\n",
	       (unsigned long)sizeof(long),
	       (unsigned long)sizeof(unsigned long long),
	       (unsigned long)sizeof(void *),
	       (unsigned long)sizeof(scres_t),
	       (unsigned long)offsetof(scres_t, a3));
	printf("__NR_Linux=%d write=%d open=%d close=%d getpid=%d "
	       "_llseek=%d mmap2=%d munmap=%d\n",
	       __NR_Linux, __NR_write, __NR_open, __NR_close, __NR_getpid,
	       __NR__llseek, __NR_mmap2, __NR_munmap);

	/* --- 1a. C-compiler 8-arg call: callee sees stack slots --- */
	{
		static const uint32_t m[8] = {
			0x10101010u, 0x20202020u, 0x30303030u, 0x40404040u,
			0x50505050u, 0x60606060u, 0x70707070u, 0x80808080u
		};

		callee8(m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]);
		printf("compiler-call obs: a0..a3=%08x %08x %08x %08x "
		       "s5..s8=%08x %08x %08x %08x sp=%08x\n",
		       g_a0, g_a1, g_a2, g_a3,
		       g_s5, g_s6, g_s7, g_s8, g_sp);
		check(g_a0 == m[0] && g_a1 == m[1] && g_a2 == m[2] &&
		      g_a3 == m[3], "args1-4 arrive in $a0..$a3");
		check(g_s5 == m[4] && g_s6 == m[5] && g_s7 == m[6] &&
		      g_s8 == m[7], "args5-8 arrive at $sp+16/+20/+24/+28");
		check((g_sp & 7u) == 0, "callee $sp is 8-byte aligned");
	}

	/* --- 1b. hand-asm forward: same slots, same values --- */
	{
		caller8(0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u,
			0x55555555u, 0x66666666u, 0x77777777u, 0x88888888u);
		printf("asm-fwd obs:     a0..a3=%08x %08x %08x %08x "
		       "s5..s8=%08x %08x %08x %08x sp=%08x\n",
		       g_a0, g_a1, g_a2, g_a3,
		       g_s5, g_s6, g_s7, g_s8, g_sp);
		check(g_a0 == 0x11111111u && g_a1 == 0x22222222u &&
		      g_a2 == 0x33333333u && g_a3 == 0x44444444u &&
		      g_s5 == 0x55555555u && g_s6 == 0x66666666u &&
		      g_s7 == 0x77777777u && g_s8 == 0x88888888u,
		      "hand-asm forward preserves all 8 slots");
	}

	/* --- 2. 64-bit even-pair alignment --- */
	{
		const unsigned long long ll = 0x2222222233333333ull;

		/* Poison $a1 right before the call: the compiler must skip
		 * it for the 64-bit arg, placing lo/hi in $a2:$a3 (LE). */
		__asm__ volatile("li $5, 0xdeadbeef" ::: "$5", "memory");
		callee_ll(0x11111111u, ll, 0x44444444u);
		printf("ll-mid obs: a0=%08x a1=%08x a2=%08x a3=%08x "
		       "stack=%08x\n", h_a0, h_a1, h_a2, h_a3, h_s);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		check(h_a0 == 0x11111111u && h_a2 == 0x33333333u &&
		      h_a3 == 0x22222222u && h_s == 0x44444444u,
		      "u64 after one u32 lands in $a2:$a3 (lo,hi), "
		      "tail on stack");
#else
		check(h_a0 == 0x11111111u && h_a2 == 0x22222222u &&
		      h_a3 == 0x33333333u && h_s == 0x44444444u,
		      "u64 after one u32 lands in $a2:$a3 (hi,lo), "
		      "tail on stack");
#endif
		printf("  (info) skipped $a1 observed as %08x\n", h_a1);

		callee_ll0(0xAAAAAAAA55555555ull, 0x77777777u);
		printf("ll-first obs: a0=%08x a1=%08x a2=%08x s=%08x\n",
		       h_a0, h_a1, h_a2, h_s);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		check(h_a0 == 0x55555555u && h_a1 == 0xAAAAAAAAu &&
		      h_a2 == 0x77777777u,
		      "leading u64 lands in $a0:$a1 (lo,hi)");
#else
		check(h_a0 == 0xAAAAAAAAu && h_a1 == 0x55555555u &&
		      h_a2 == 0x77777777u,
		      "leading u64 lands in $a0:$a1 (hi,lo)");
#endif
	}

	/* --- 3a. success paths: $a3=0 --- */
	r = raw_sys0(__NR_getpid);
	printf("getpid: v0=%ld a3=%ld (libc=%d)\n", r.v0, r.a3, getpid());
	check(r.a3 == 0 && r.v0 > 0 && r.v0 == (long)getpid(),
	      "getpid success: $a3=0, $v0=pid");

	r = raw_sys3(__NR_write, 1L, (long)msg, (long)(sizeof(msg) - 1));
	printf("write(1): v0=%ld a3=%ld\n", r.v0, r.a3);
	check(r.a3 == 0 && r.v0 == (long)(sizeof(msg) - 1),
	      "write success: $a3=0, $v0=len");

	/* --- 3b. error paths: $a3=1, $v0=+errno --- */
	r = raw_sys3(__NR_write, -1L, (long)msg, 3L);
	printf("write(-1): v0=%ld a3=%ld\n", r.v0, r.a3);
	check(r.a3 == 1 && r.v0 == EBADF, "bad-fd write: $a3=1, $v0=EBADF(9)");

	r = raw_sys3(__NR_open, (long)"/nonexistent-e01-xyz", O_RDONLY, 0L);
	printf("open(bad): v0=%ld a3=%ld\n", r.v0, r.a3);
	check(r.a3 == 1 && r.v0 == ENOENT, "bad open: $a3=1, $v0=ENOENT(2)");

	/* --- 1c. 6-arg mmap2 through the stack slots --- */
	{
		void *p;

		r = raw_sys6(__NR_mmap2, 0L, 4096L,
			     (long)(PROT_READ | PROT_WRITE),
			     (long)(MAP_PRIVATE | MAP_ANONYMOUS), -1L, 0L);
		printf("mmap2(anon): v0=0x%lx a3=%ld\n", (unsigned long)r.v0,
		       r.a3);
		check(r.a3 == 0 && r.v0 != -1L,
		      "6-arg mmap2 success via stack args 5,6");
		if (r.a3 == 0 && r.v0 != -1L) {
			p = (void *)r.v0;
			*(volatile uint32_t *)p = 0xA5A5A5A5u;
			check(*(volatile uint32_t *)p == 0xA5A5A5A5u,
			      "anonymous mapping is writable");
			r = raw_sys2(__NR_munmap, (long)p, 4096L);
			check(r.a3 == 0 && r.v0 == 0, "munmap ok");
		}

		r = raw_sys6(__NR_mmap2, 0L, 4096L, (long)PROT_READ,
			     (long)MAP_PRIVATE, -2L, 0L);
		printf("mmap2(badfd): v0=%ld a3=%ld\n", r.v0, r.a3);
		check(r.a3 == 1 && r.v0 > 0,
		      "6-arg mmap2 error: $a3=1, $v0=+errno");
	}

	/* --- 1d. 8-arg raw syscall: invalid number carries 8 magics --- */
	r = raw_sys8(4999L, 0x11111111L, 0x22222222L, 0x33333333L,
		     0x44444444L, 0x55555555L, 0x66666666L, 0x77777777L,
		     0x88888888L);
	printf("syscall#4999/8args: v0=%ld a3=%ld\n", r.v0, r.a3);
	check(r.a3 == 1 && r.v0 == ENOSYS,
	      "8-arg bad syscall: $a3=1, $v0=ENOSYS(89)");

	r = raw_sys8(__NR_getpid, 0x11111111L, 0x22222222L, 0x33333333L,
		     0x44444444L, 0x55555555L, 0x66666666L, 0x77777777L,
		     0x88888888L);
	printf("getpid/8args: v0=%ld a3=%ld\n", r.v0, r.a3);
	check(r.a3 == 0 && r.v0 == (long)getpid(),
	      "8-arg getpid ignores extras, $a3=0");

	/* --- 2b. syscall-level u64 pair: _llseek(fd, hi, lo, &res, wh) --- */
	{
		static const char payload[] = "0123456789ABC"; /* 13 bytes */

		snprintf(tmp, sizeof(tmp), "/tmp/e01probe-%d.bin", getpid());
		fd = open(tmp, O_CREAT | O_RDWR | O_TRUNC, 0600);
		check(fd >= 0, "temp file created");
		if (fd >= 0) {
			if (write(fd, payload, sizeof(payload) - 1) != 13) {
				check(0, "temp file has 13 bytes");
			} else {
				res = 0;
				r = raw_sys5(__NR__llseek, (long)fd, 0L, 0L,
					     (long)&res, (long)SEEK_END);
				printf("_llseek(END): v0=%ld a3=%ld ",
				       r.v0, r.a3);
				print_u64("res", res);
				check(r.a3 == 0 && res == 13ull,
				      "_llseek SEEK_END reports 13");

				res = 0;
				r = raw_sys5(__NR__llseek, (long)fd, 0L, 7L,
					     (long)&res, (long)SEEK_SET);
				printf("_llseek(SET 0,7): v0=%ld a3=%ld ",
				       r.v0, r.a3);
				print_u64("res", res);
				check(r.a3 == 0 && res == 7ull,
				      "_llseek small offset via pair");

				res = 0;
				r = raw_sys5(__NR__llseek, (long)fd, 1L, 2L,
					     (long)&res, (long)SEEK_SET);
				printf("_llseek(SET hi=1,lo=2): v0=%ld a3=%ld ",
				       r.v0, r.a3);
				print_u64("res", res);
				check(r.a3 == 0 && res == 0x100000002ull,
				      "_llseek pair order (hi,lo)");
			}
			r = raw_sys1(__NR_close, (long)fd);
			check(r.a3 == 0 && r.v0 == 0, "raw close ok");
			r = raw_sys1(__NR_close, (long)fd);
			printf("close(again): v0=%ld a3=%ld\n", r.v0, r.a3);
			check(r.a3 == 1 && r.v0 == EBADF,
			      "double close: $a3=1, $v0=EBADF(9)");
			unlink(tmp);
		}
	}

	printf("E01-RESULT: %s (%d checks failed)\n",
	       g_fail ? "FAIL" : "PASS", g_fail);
	return g_fail != 0;
}
