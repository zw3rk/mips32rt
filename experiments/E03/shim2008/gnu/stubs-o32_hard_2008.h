/* Shim for Debian cross glibc (2.36) which ships only the legacy-NaN
 * O32 stubs header (gnu/stubs-o32_hard.h) and not the NaN-2008 variant
 * (gnu/stubs-o32_hard_2008.h) that <gnu/stubs.h> selects when compiling
 * with -mnan=2008 (__mips_nan2008).
 *
 * Content mirrors the identically-generated upstream legacy file: the
 * listed BSD-legacy calls are ENOSYS stubs under every O32 variant.
 * Used ONLY via -I for the -mnan=2008 experiment builds so that the
 * compiler's real 2008-NaN codegen and ELF NaN2008 marking can be
 * observed under qemu; the shim changes no codegen itself.
 * See experiments/E03/FINDINGS.md.
 */

#ifdef _LIBC
# error Applications may not define the macro _LIBC
#endif

#define __stub_chflags
#define __stub_fchflags
#define __stub_gtty
#define __stub_revoke
#define __stub_setlogin
#define __stub_sigreturn
#define __stub_stty
