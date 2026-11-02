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

	printf("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
