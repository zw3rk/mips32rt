/*
 * src/os/syscall_nr.h — MIPS O32 Linux syscall numbers for mips32rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * O32 numbers are offsets from __NR_Linux = 4000 (SPEC 2.3: the syscall
 * instruction 0x0000000c takes its number in $v0 as 4000 + table index).
 *
 * Source: Linux arch/mips/kernel/syscalls/syscall_o32.tbl as published in
 * torvalds/linux master (fetched 2026-10-24; a second fetch in the same
 * session compared byte-identical).  Each entry below is 4000 + the table
 * index quoted in the per-line comment.  MIPS O32 defines no vfork entry
 * (clone is used instead); mmap2 is present at index 210 (-> 4210).
 *
 * Phase 2 (lane L2a) extension: the numbers below were additionally
 * verified one by one against /usr/mipsel-linux-gnu/include/asm/unistd.h
 * (indirecting to unistd_o32.h) from libc6-dev-mipsel-cross 2.36-8cross2
 * (Debian bookworm-slim, linux/arm64); each cites its __NR_Linux offset.
 */

#ifndef MIPS32_SYSCALL_NR_H
#define MIPS32_SYSCALL_NR_H

#define MIPS32_NR_LINUX_BASE 4000

/* Process lifecycle */
#define MIPS32_NR_exit        4001 /* o32 index 1:   sys_exit */
#define MIPS32_NR_fork        4002 /* o32 index 2:   __sys_fork */
#define MIPS32_NR_execve      4011 /* o32 index 11:  sys_execve */
#define MIPS32_NR_exit_group  4246 /* o32 index 246: sys_exit_group */
#define MIPS32_NR_clone       4120 /* o32 index 120: __sys_clone */

/* Basic I/O */
#define MIPS32_NR_read   4003 /* o32 index 3: sys_read */
#define MIPS32_NR_write  4004 /* o32 index 4: sys_write */
#define MIPS32_NR_open   4005 /* o32 index 5: sys_open (compat_sys_open) */
#define MIPS32_NR_openat 4288 /* o32 index 288: sys_openat */
#define MIPS32_NR_unlink 4010 /* o32 index 10: sys_unlink (asm/unistd_o32.h) */
#define MIPS32_NR_unlinkat 4294 /* o32 index 294: sys_unlinkat (asm/unistd_o32.h) */
#define MIPS32_NR_close  4006 /* o32 index 6: sys_close */
#define MIPS32_NR_lseek  4019 /* o32 index 19: sys_lseek */
#define MIPS32_NR_llseek 4140 /* o32 index 140: sys_llseek (__NR__llseek) */
#define MIPS32_NR_readv  4145 /* o32 index 145: sys_readv */
#define MIPS32_NR_writev 4146 /* o32 index 146: sys_writev */
#define MIPS32_NR_dup    4041 /* o32 index 41: sys_dup */
#define MIPS32_NR_dup2   4063 /* o32 index 63: sys_dup2 */
#define MIPS32_NR_dup3   4327 /* o32 index 327: sys_dup3 */
#define MIPS32_NR_pipe   4042 /* o32 index 42: sysm_pipe */
#define MIPS32_NR_pipe2  4328 /* o32 index 328: sys_pipe2 */
#define MIPS32_NR_fcntl  4055 /* o32 index 55: sys_fcntl (compat) */
#define MIPS32_NR_fcntl64 4220 /* o32 index 220: sys_fcntl64 */
#define MIPS32_NR_ioctl  4054 /* o32 index 54: sys_ioctl (compat) */

/* File metadata (104-byte struct stat64 per SPEC 2.3) */
#define MIPS32_NR_stat64    4213 /* o32 index 213: sys_stat64 */
#define MIPS32_NR_lstat64   4214 /* o32 index 214: sys_lstat64 */
#define MIPS32_NR_fstat64   4215 /* o32 index 215: sys_fstat64 */
#define MIPS32_NR_fstatat64 4293 /* o32 index 293: sys_fstatat64 */
#define MIPS32_NR_statx     4366 /* o32 index 366: sys_statx */

/* Directory / link / access */
#define MIPS32_NR_getdents64 4219 /* o32 index 219: sys_getdents64 */
#define MIPS32_NR_readlink   4085 /* o32 index 85: sys_readlink */
#define MIPS32_NR_readlinkat 4298 /* o32 index 298: sys_readlinkat */
#define MIPS32_NR_access     4033 /* o32 index 33: sys_access */
#define MIPS32_NR_close_range 4436 /* o32 index 436: sys_close_range */

/* Time, randomness, futex */
#define MIPS32_NR_nanosleep        4166 /* o32 index 166: sys_nanosleep */
#define MIPS32_NR_clock_gettime    4263 /* o32 index 263: sys_clock_gettime */
#define MIPS32_NR_clock_gettime64  4403 /* o32 index 403: sys_clock_gettime64 */
#define MIPS32_NR_getrandom        4353 /* o32 index 353: sys_getrandom */
#define MIPS32_NR_futex            4238 /* o32 index 238: sys_futex */

/* Robust futex lists (recorded in ctx; woken by Phase 4) */
#define MIPS32_NR_set_robust_list 4309 /* o32 index 309 */
#define MIPS32_NR_get_robust_list 4310 /* o32 index 310 */
#define MIPS32_NR_set_tid_address 4252 /* o32 index 252: sys_set_tid_address */

/* Memory management */
#define MIPS32_NR_brk      4045 /* o32 index 45:  sys_brk */
#define MIPS32_NR_mmap     4090 /* o32 index 90:  sys_mips_mmap */
#define MIPS32_NR_mmap2    4210 /* o32 index 210: sys_mips_mmap2 */
#define MIPS32_NR_munmap   4091 /* o32 index 91:  sys_munmap */
#define MIPS32_NR_mprotect 4125 /* o32 index 125: sys_mprotect */

/* Identity / uname */
#define MIPS32_NR_getpid  4020 /* o32 index 20: sys_getpid */
#define MIPS32_NR_getppid 4064 /* o32 index 64: sys_getppid */
#define MIPS32_NR_getuid  4024 /* o32 index 24: sys_getuid */
#define MIPS32_NR_geteuid 4049 /* o32 index 49: sys_geteuid */
#define MIPS32_NR_getgid  4047 /* o32 index 47: sys_getgid */
#define MIPS32_NR_getegid 4050 /* o32 index 50: sys_getegid */
#define MIPS32_NR_uname   4122 /* o32 index 122: sys_newuname */

/* Signals (wired in Phase 4; numbers frozen here) */
#define MIPS32_NR_kill          4037 /* o32 index 37:  sys_kill */
#define MIPS32_NR_rt_sigaction  4194 /* o32 index 194: sys_rt_sigaction */
#define MIPS32_NR_rt_sigreturn  4193 /* o32 index 193: sys_rt_sigreturn */
#define MIPS32_NR_rt_sigprocmask 4195 /* o32 index 195: sys_rt_sigprocmask */

/* Thread pointer (SPEC 2.2: sets ctx->ulr) */
#define MIPS32_NR_set_thread_area 4283 /* o32 index 283: sys_set_thread_area */

/* Process wait (Phase 4 fork/exec/wait4) */
#define MIPS32_NR_waitpid 4007 /* o32 index 7:   sys_waitpid */
#define MIPS32_NR_wait4 4114 /* o32 index 114: sys_wait4 */
/*
 * MIPS O32 defines no __NR_vfork (verified absent from unistd_o32.h):
 * glibc vfork lowers to clone (lane L4b); see mips_proc_vfork in
 * src/os/proc.c for the documented fork-equivalent.
 */

#endif /* MIPS32_SYSCALL_NR_H */
