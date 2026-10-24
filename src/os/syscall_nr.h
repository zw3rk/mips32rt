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
#define MIPS32_NR_close  4006 /* o32 index 6: sys_close */
#define MIPS32_NR_lseek  4019 /* o32 index 19: sys_lseek */
#define MIPS32_NR_dup    4041 /* o32 index 41: sys_dup */
#define MIPS32_NR_dup2   4063 /* o32 index 63: sys_dup2 */
#define MIPS32_NR_pipe   4042 /* o32 index 42: sysm_pipe */

/* Memory management */
#define MIPS32_NR_brk      4045 /* o32 index 45:  sys_brk */
#define MIPS32_NR_mmap     4090 /* o32 index 90:  sys_mips_mmap */
#define MIPS32_NR_mmap2    4210 /* o32 index 210: sys_mips_mmap2 */
#define MIPS32_NR_munmap   4091 /* o32 index 91:  sys_munmap */
#define MIPS32_NR_mprotect 4125 /* o32 index 125: sys_mprotect */

/* Identity / uname */
#define MIPS32_NR_getpid 4020 /* o32 index 20: sys_getpid */
#define MIPS32_NR_getppid 4064 /* o32 index 64: sys_getppid */
#define MIPS32_NR_uname  4122 /* o32 index 122: sys_newuname */

/* Signals (wired in Phase 4; numbers frozen here) */
#define MIPS32_NR_kill         4037 /* o32 index 37:  sys_kill */
#define MIPS32_NR_rt_sigaction 4194 /* o32 index 194: sys_rt_sigaction */
#define MIPS32_NR_rt_sigreturn 4193 /* o32 index 193: sys_rt_sigreturn */

/* Thread pointer (SPEC 2.2: sets ctx->ulr) */
#define MIPS32_NR_set_thread_area 4283 /* o32 index 283: sys_set_thread_area */

/* Process wait (Phase 4 fork/exec/wait4) */
#define MIPS32_NR_wait4 4114 /* o32 index 114: sys_wait4 */

#endif /* MIPS32_SYSCALL_NR_H */
