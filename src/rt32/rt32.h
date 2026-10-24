/*
 * src/rt32/rt32.h — Interfaces of the vendored ISA-agnostic core
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first vendoring from ../i686rt/src/rt32/: mechanical renames
 * i686_ -> mips32_, I686_ -> MIPS32_ and `#include "i686rt.h"` ->
 * `#include "mips32rt.h"`, all code retyped on the frozen `mips32_ctx_t`
 * from src/mips32rt.h.  a32h_* / A32H_* handshake symbols are untouched
 * (include/a32host.h is byte-identical).
 *
 * Per-file i686rt origins:
 *   vm.c            <- rt32_vm.c      (window init, regions, brk, reset)
 *   vm_mmap.c       <- rt32_vm.c      (mmap2/mprotect/munmap/mremap split
 *                      out to honor the 900-line file limit)
 *   elf32.c         <- rt32_elf32.c   (ELF32 loader, PT_INTERP via
 *                      sysroot; EM_MIPS, LE+BE, O32 e_flags admission)
 *   stack32.c       <- rt32_stack32.c (initial stack; minimal O32 auxv —
 *                      abiflags/vdso entries arrive in later phases)
 *   host.c          <- rt32_host.c    (/dev/a32host probe)
 *   a64_emit.[ch]   <- rt32_a64_emit.[ch] (host-side AArch64 encoder
 *                      reused by the Phase 2 DBT; the i686-only block-exit
 *                      chaining sequences and ARM-DSP lowering helpers
 *                      were dropped — they hardcode the i686 ctx layout
 *                      and return with src/dbt/ in Phase 2)
 *   safe_syscall_a64.S (D18 signal-window race-free host syscall gate)
 *
 * Environment variables read by this code (i686rt names mapped to MIPS32RT_*):
 *   MIPS32RT_WINDOW — requested guest window base G for rt32_vm_init
 *   MIPS32RT_HOST   — set to "none" to skip the /dev/a32host probe
 */

#ifndef RT32_H
#define RT32_H

#include "mips32rt.h"

/* Host handshake (host.c) */
void rt32_host_probe(mips32_ctx_t *ctx);

/* Guest window & memory management (vm.c, vm_mmap.c) */
int      rt32_vm_init(mips32_ctx_t *ctx, uint64_t requested_window);
int      rt32_vm_record_region(mips32_ctx_t *ctx, uint32_t start, uint32_t end,
                              uint32_t prot, uint32_t flags, const char *name);
uint32_t rt32_vm_brk(mips32_ctx_t *ctx, uint32_t new_brk);
void rt32_vm_reset_for_exec(mips32_ctx_t *ctx);
uint32_t rt32_vm_mmap2(mips32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                       uint32_t flags, int fd, uint32_t pgoffset);
int      rt32_vm_mprotect(mips32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot);
int      rt32_vm_munmap(mips32_ctx_t *ctx, uint32_t addr, uint32_t len);
uint32_t rt32_vm_mremap(mips32_ctx_t *ctx, uint32_t old_addr, uint32_t old_len,
                        uint32_t new_len, uint32_t flags, uint32_t new_addr);
void     rt32_vm_sync_ctx(mips32_ctx_t *ctx);

/* ELF32 loader & initial stack (elf32.c, stack32.c) */
typedef struct rt32_elf_info {
    uint32_t entry;
    uint32_t phdr_vaddr;
    uint32_t phent;
    uint32_t phnum;
    uint32_t load_bias;
    uint32_t max_vaddr;
    uint32_t interp_base;
    uint32_t text_start;
    uint32_t text_end;
    uint32_t is_be;    /* 1 = mips BE guest, 0 = mipsel */
    uint32_t nan2008;  /* 1 = EF_MIPS_NAN2008 seen in e_flags */
    char     interp_path[256];
} rt32_elf_info_t;

int rt32_open_guest_ro(const mips32_ctx_t *ctx, const char *guest_path);
int rt32_elf_load(mips32_ctx_t *ctx, int exec_fd, const char *path,
                  rt32_elf_info_t *out_info);
int rt32_stack_setup(mips32_ctx_t *ctx, const rt32_elf_info_t *elf_info,
                     int guest_argc, char **guest_argv, char **host_envp,
                     uint32_t *out_sp);

/* D18 signal-window host syscall gate (safe_syscall_a64.S, Linux AArch64).
 * Issues one raw host syscall (nr + 6 args) only if *gen still equals
 * expected at the SVC boundary; a host signal handler redirects a
 * pre-commit interruption to mips32_safe_syscall_abort (-EINTR), while a
 * completed SVC result always wins.  Never touches x18. */
long mips32_safe_syscall6(long nr, const long args[6],
                          const _Atomic uint32_t *gen, uint32_t expected);
extern const char mips32_safe_syscall_window_begin[];
extern const char mips32_safe_syscall_post_svc[];
extern const char mips32_safe_syscall_abort[];

#endif /* RT32_H */
