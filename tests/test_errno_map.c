/* Focused host -> MIPS O32 errno translation test (follow-up N-3).
 *
 * Part of mips32rt, Apache-2.0, Copyright 2026 Moritz Angermann
 * <moritz@zw3rk.com>, zw3rk pte. ltd.
 *
 * Guards mips_errno_from_host (src/os/syscalls_priv.h): host
 * ENAMETOOLONG must map to MIPS 78 (not pass through to EIDRM/ENOSR),
 * and a distinct host ENOTSUP (Darwin 45) must map to MIPS 122 (not
 * pass through to EDEADLK). Exit 0 only if all pass.
 */
#include <errno.h>
#include <stdio.h>

#include "os/syscalls_priv.h"

static int failures = 0;
static int checks = 0;

#define CHECK_ERRNO(host, want) do { \
		checks++; \
		if (mips_errno_from_host(host) == (want)) { \
			printf("ok: host errno %d -> MIPS %d\n", \
			    (host), (want)); \
		} else { \
			printf("FAIL: host errno %d -> MIPS %d, want %d\n", \
			    (host), (int)mips_errno_from_host(host), \
			    (want)); \
			failures++; \
		} \
	} while (0)

#define CHECK(cond) do { \
		checks++; \
		if (cond) { \
			printf("ok: %s\n", #cond); \
		} else { \
			printf("FAIL: %s (line %d)\n", #cond, __LINE__); \
			failures++; \
		} \
	} while (0)

int main(void)
{
#ifdef ENAMETOOLONG
	CHECK_ERRNO(ENAMETOOLONG, 78);
#endif
#if defined(ENOTSUP) && (!defined(EOPNOTSUPP) || ENOTSUP != EOPNOTSUPP)
	CHECK_ERRNO(ENOTSUP, 122);
#endif
	CHECK_ERRNO(EOPNOTSUPP, 122);
	CHECK_ERRNO(EBADMSG, 77);
	CHECK_ERRNO(EOVERFLOW, 79);
	CHECK_ERRNO(ENOSYS, 89);

	/* rt_sigframe uc_sigmask offset shared by the builder, the
	 * sigreturn reader, and the pselect/ppoll wait tail. */
	CHECK(MIPS_RT_SIGFRAME_SIGMASK_OFF == 768);

	/* MIPS O32 poll bits (asm/poll.h) against the host. */
	CHECK(mips_poll_events_to_host(0x0001) == POLLIN);
	CHECK(mips_poll_events_to_host(0x0004) ==
	    (short)((unsigned)POLLOUT | (unsigned)POLLWRNORM));
	CHECK(mips_poll_revents_from_host(POLLWRNORM) == 0x0004);
#ifdef __APPLE__
	CHECK(mips_poll_events_to_host(0x0100) == POLLWRBAND);
	CHECK(mips_poll_revents_from_host(0x2000) == 0x0000);
#else
	CHECK(mips_poll_events_to_host(0x0100) == POLLWRBAND);
	CHECK(mips_poll_revents_from_host(POLLWRBAND) == 0x0100);
	CHECK(mips_poll_revents_from_host(POLLRDHUP) == 0x2000);
	CHECK(mips_poll_events_to_host(0x003f) ==
	    (short)(0x003fU | (unsigned)POLLWRNORM));
#endif

	/* MIPS O32 flock l_type (RDLCK 0, WRLCK 1, UNLCK 2) round-trips
	 * through the host mapping on every host. */
	CHECK(mips_flock_type_from_host(mips_flock_type_to_host(0)) == 0);
	CHECK(mips_flock_type_from_host(mips_flock_type_to_host(1)) == 1);
	CHECK(mips_flock_type_from_host(mips_flock_type_to_host(2)) == 2);
#ifndef __APPLE__
	CHECK(mips_flock_type_to_host(0) == 0);
	CHECK(mips_flock_type_to_host(1) == 1);
	CHECK(mips_flock_type_to_host(2) == 2);
#else
	CHECK(mips_flock_type_to_host(0) == F_RDLCK);
	CHECK(mips_flock_type_to_host(1) == F_WRLCK);
	CHECK(mips_flock_type_to_host(2) == F_UNLCK);
#endif

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
