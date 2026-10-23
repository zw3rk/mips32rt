/* E06: TLS (rdhwr $29 / set_thread_area) and LL/SC probe (MIPS O32, mipsel).
 *
 * Build (in debian linux/arm64 container):
 *   mipsel-linux-gnu-gcc -static -O2 -mabi=32 -o probe_mipsel probe.c -pthread
 * Run:
 *   qemu-mipsel ./probe_mipsel
 *
 * Verifies:
 *  (1) rdhwr $29 returns the TLS pointer installed by set_thread_area(4283);
 *  (2) LL/SC atomic increment is atomic across two pthreads;
 *  (3) SC returns 0 after an intervening plain store to the same address.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_set_thread_area
#define __NR_set_thread_area 4283
#endif

/* rdhwr rt,$29 via mnemonic (assembler picks rt). */
static unsigned long rdhwr_ulr(void)
{
	unsigned long v;

	__asm__ volatile("rdhwr %0, $29" : "=r"(v));
	return v;
}

/* rdhwr $v1($3),$29 via its exact 32-bit encoding 0x7c03e83b.
 * $3 is saved/restored around the raw word so no compiler live value
 * in $v1 is harmed (no reliance on clobber-name spelling). */
static unsigned long rdhwr_v1_fixed(void)
{
	unsigned long v, save3;

	__asm__ volatile(
		"move %1, $3\n\t"
		".word 0x7c03e83b\n\t"
		"move %0, $3\n\t"
		"move $3, %1\n\t"
		: "=r"(v), "=&r"(save3)
		:
		: "memory");
	return v;
}

/* LL/SC encodings (documented, also cross-checked via objdump in run.sh):
 *   ll rt,0(rs) : 110000 rs rt 0x0000  -> 0xc0000000 | rs<<21 | rt<<16
 *   sc rt,0(rs) : 111000 rs rt 0x0000  -> 0xe0000000 | rs<<21 | rt<<16
 */

/* Atomic add-1 with an LL/SC retry loop. Returns the previous value. */
static int llsc_add1(volatile int *p)
{
	int oldval, newval;

	__asm__ volatile(
		"1:\n\t"
		"ll %0, 0(%2)\n\t"
		"addu %1, %0, 1\n\t"
		"sc %1, 0(%2)\n\t"
		"beqz %1, 1b\n\t"
		"nop\n\t"
		: "=&r"(oldval), "=&r"(newval)
		: "r"(p)
		: "memory");
	return oldval;
}

/* LL then an intervening plain store, then SC.
 * The store must clear the LL linkage so SC returns 0 (failure). */
static int sc_after_store(volatile int *p, int interfere, int scval)
{
	int oldval, scres;

	__asm__ volatile(
		"ll %0, 0(%2)\n\t"
		"sw %3, 0(%2)\n\t"
		"sc %4, 0(%2)\n\t"
		"move %1, %4\n\t"
		: "=&r"(oldval), "=&r"(scres)
		: "r"(p), "r"(interfere), "r"(scval)
		: "memory");
	(void)oldval;
	return scres;
}

static __thread int tls_var = 42;

#define NTHREADS 2
#define NINCR 200000

static volatile int shared_counter = 0;

static void *hammer(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < NINCR; i++)
		llsc_add1(&shared_counter);
	return NULL;
}

int main(void)
{
	unsigned long ulr_before, ulr_v1, ulr_test, ulr_restored;
	unsigned long set_val = 0x51ab0001UL;
	long rc;
	int failures = 0;
	pthread_t th[NTHREADS];
	volatile int sc_cell = 0;
	int scres, i;
	long expected;

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("E06 TLS + LL/SC probe\n");
	printf("__NR_set_thread_area=%d (expect 4283)\n", __NR_set_thread_area);
	if (__NR_set_thread_area != 4283) {
		printf("FAIL: __NR mismatch\n");
		failures++;
	}

	/* (1) TLS: initial ULR vs __thread address relationship. */
	ulr_before = rdhwr_ulr();
	ulr_v1 = rdhwr_v1_fixed();
	printf("rdhwr-mnemonic ulr_before=0x%08lx\n", ulr_before);
	printf("rdhwr-fixed-0x7c03e83b ulr=0x%08lx\n", ulr_v1);
	printf("&tls_var=%p tls_var=%d pthread_self=%p\n",
	    (void *)&tls_var, tls_var, (void *)pthread_self());
	if (ulr_before == 0) {
		printf("FAIL: initial ULR is 0\n");
		failures++;
	} else {
		printf("ok: initial ULR nonzero\n");
	}
	if (ulr_v1 != ulr_before) {
		printf("FAIL: fixed-encoding rdhwr disagrees with mnemonic\n");
		failures++;
	} else {
		printf("ok: rdhwr $v1,$29 (0x7c03e83b) matches mnemonic read\n");
	}
	/* ULR points at the thread pointer; the __thread var lives nearby. */
	{
		unsigned long a = (unsigned long)&tls_var;
		unsigned long d = a > ulr_before ? a - ulr_before : ulr_before - a;

		printf("tls_var-ulr distance=%lu bytes\n", d);
		if (d > 65536) {
			printf("FAIL: __thread var implausibly far from ULR\n");
			failures++;
		} else {
			printf("ok: __thread var adjacent to ULR\n");
		}
	}

	/* set_thread_area(test) must be visible via rdhwr, then restore.
	 * No libc calls between set and restore: libc (errno, stdio
	 * locks) needs the real TLS pointer, so read ULR and restore
	 * back-to-back, printing only afterwards. */
	rc = syscall(__NR_set_thread_area, set_val);
	if (rc != 0) {
		printf("FAIL: set_thread_area(0x%lx) rc=%ld errno=%d (%s)\n",
		    set_val, rc, errno, strerror(errno));
		failures++;
		ulr_test = 0;
	} else {
		ulr_test = rdhwr_ulr();
		rc = syscall(__NR_set_thread_area, ulr_before);
		printf("after set_thread_area(0x%08lx): rdhwr=0x%08lx\n",
		    set_val, ulr_test);
		if (ulr_test != (set_val & 0xffffffffUL)) {
			printf("FAIL: rdhwr did not return set value\n");
			failures++;
		} else {
			printf("ok: rdhwr $29 returns set_thread_area value\n");
		}
		if (rc != 0) {
			printf("FAIL: restore set_thread_area rc=%ld errno=%d\n",
			    rc, errno);
			failures++;
		}
		ulr_restored = rdhwr_ulr();
		printf("after restore: rdhwr=0x%08lx (expect 0x%08lx)\n",
		    ulr_restored, ulr_before);
		if (ulr_restored != ulr_before) {
			printf("FAIL: ULR restore mismatch\n");
			failures++;
		} else {
			printf("ok: ULR restored\n");
		}
	}
	if (tls_var != 42) {
		printf("FAIL: tls_var clobbered (%d)\n", tls_var);
		failures++;
	} else {
		printf("ok: __thread var intact after TLS round-trip\n");
	}

	/* (2) LL/SC atomicity across two hammer threads. */
	shared_counter = 0;
	for (i = 0; i < NTHREADS; i++) {
		if (pthread_create(&th[i], NULL, hammer, NULL) != 0) {
			perror("pthread_create");
			return 2;
		}
	}
	for (i = 0; i < NTHREADS; i++)
		pthread_join(th[i], NULL);
	expected = (long)NTHREADS * NINCR;
	printf("ll/sc hammer: final=%d expected=%ld\n", shared_counter, expected);
	if (shared_counter != expected) {
		printf("FAIL: lost updates under LL/SC hammer\n");
		failures++;
	} else {
		printf("ok: LL/SC increment atomic across %d threads\n", NTHREADS);
	}

	/* (3) SC must fail after an intervening store. */
	sc_cell = 0;
	scres = sc_after_store(&sc_cell, 0x11111111, 0x22222222);
	printf("sc_after_store: scres=%d cell=0x%x\n", scres, sc_cell);
	if (scres != 0) {
		printf("FAIL: SC succeeded despite intervening store\n");
		failures++;
	} else {
		printf("ok: SC returns 0 after intervening store\n");
	}

	if (failures == 0)
		printf("E06 RESULT: PASS\n");
	else
		printf("E06 RESULT: FAIL (%d)\n", failures);
	return failures != 0;
}
