/*
 * src/rt32/elf32.c — ELFCLASS32 (EM_MIPS) O32 loader, mipsel + mips
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from ../i686rt/src/rt32/rt32_elf32.c: retyped on mips32_ctx_t,
 * EM_386 -> EM_MIPS(8) with dual-endian admission (SPEC 1.1): ELFDATA2LSB
 * (mipsel, primary) and ELFDATA2MSB (mips BE, byte-swapped after read),
 * (e_flags & EF_MIPS_ABI2) == 0 and (e_flags & EF_MIPS_ABI) in
 * {0, E_MIPS_ABI_O32}.  Guest TASK_SIZE is 0x7fff8000 (SPEC 1.1).
 */

#define _GNU_SOURCE
#include "rt32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define EI_NIDENT    16U
#define EI_CLASS     4U
#define EI_DATA      5U
#define ELFCLASS32   1U
#define ELFDATA2LSB  1U
#define ELFDATA2MSB  2U
#define ET_EXEC      2U
#define ET_DYN       3U
#define EM_MIPS      8U

#define EF_MIPS_ABI2      0x00000020U
#define EF_MIPS_ABI       0x0000F000U
#define E_MIPS_ABI_O32    0x00001000U
#define EF_MIPS_NAN2008   0x00000400U

#define PT_LOAD   1U
#define PT_INTERP 3U
#define PT_PHDR   6U

#define PF_X 0x1U
#define PF_W 0x2U
#define PF_R 0x4U

static uint16_t swap16(uint16_t v)
{
    return (uint16_t)(((uint16_t)(v << 8)) | (uint16_t)(v >> 8));
}

static uint32_t swap32(uint32_t v)
{
    return ((v & 0x000000FFU) << 24) | ((v & 0x0000FF00U) << 8) |
           ((v & 0x00FF0000U) >> 8) | ((v & 0xFF000000U) >> 24);
}

typedef struct elf32_ehdr {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf32_ehdr_t;

typedef struct elf32_phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf32_phdr_t;

int rt32_open_guest_ro(const mips32_ctx_t *ctx, const char *guest_path)
{
    if (guest_path == NULL || guest_path[0] == '\0') {
        return -1;
    }
    /* Resolve absolute guest paths against the sysroot here; the full
     * resolver (relative paths, /proc magic) arrives with the Phase 2
     * syscall marshal. */
    if (ctx != NULL && guest_path[0] == '/' &&
        ctx->sysroot != NULL && ctx->sysroot[0] != '\0') {
        char resolved[PATH_MAX];
        int n = snprintf(resolved, sizeof(resolved), "%s%s", ctx->sysroot, guest_path);
        if (n > 0 && (size_t)n < sizeof(resolved)) {
            int fd = open(resolved, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                return fd;
            }
        }
    }
    return open(guest_path, O_RDONLY | O_CLOEXEC);
}

static int pread_full(int fd, void *buf, size_t count, off_t offset)
{
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0;
    while (total < count) {
        ssize_t n = pread(fd, p + total, count - total, offset + (off_t)total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

static int protect_and_record_seg(mips32_ctx_t *ctx, uint32_t start, uint32_t end,
                                  uint32_t guest_prot, const char *label)
{
    rt32_vm_record_region(ctx, start, end, guest_prot, 0x12U, label);
#ifdef __APPLE__
    uint32_t h_start = start & ~0x3FFFU;
    uint32_t h_end   = (end + 0x3FFFU) & ~0x3FFFU;
    for (uint32_t p = h_start; p < h_end; p += 0x4000U) {
        uint32_t u_prot = guest_prot;
        for (size_t r = 0U; r < ctx->region_count; r++) {
            if (ctx->regions[r].start < p + 0x4000U && ctx->regions[r].end > p) {
                u_prot |= ctx->regions[r].prot;
            }
        }
        if (mprotect(mips32_guest_ptr(ctx, p), 0x4000U, mips32_host_prot(ctx, u_prot)) != 0) {
            fprintf(stderr, "mips32rt: %s: mprotect failed on [0x%x, 0x%x): %s\n",
                    label, p, p + 0x4000U, strerror(errno));
            return -1;
        }
    }
#else
    if (mprotect(mips32_guest_ptr(ctx, start), end - start, mips32_host_prot(ctx, guest_prot)) != 0) {
        fprintf(stderr, "mips32rt: %s: mprotect failed on [0x%x, 0x%x): %s\n",
                label, start, end, strerror(errno));
        return -1;
    }
#endif
    return 0;
}

static int load_elf32_image(mips32_ctx_t *ctx, int fd, uint32_t default_pie_base,
                            const char *label, rt32_elf_info_t *out)
{
    elf32_ehdr_t ehdr;
    if (pread_full(fd, &ehdr, sizeof(ehdr), 0) != 0) {
        fprintf(stderr, "mips32rt: %s: failed to read ELF header\n", label);
        return -1;
    }

    if (ehdr.e_ident[0] != 0x7fU || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
        fprintf(stderr, "mips32rt: %s: not an ELF file\n", label);
        return -1;
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS32 ||
        (ehdr.e_ident[EI_DATA] != ELFDATA2LSB &&
         ehdr.e_ident[EI_DATA] != ELFDATA2MSB)) {
        fprintf(stderr, "mips32rt: %s: not a 32-bit MIPS ELF\n", label);
        return -1;
    }
    bool is_be = ehdr.e_ident[EI_DATA] == ELFDATA2MSB;
    if (is_be) {
        /* BE (mips) guest on an LE host: swap every multibyte header
         * field once, right after read, so the rest of the loader is
         * endian-neutral. */
        ehdr.e_type      = swap16(ehdr.e_type);
        ehdr.e_machine   = swap16(ehdr.e_machine);
        ehdr.e_version   = swap32(ehdr.e_version);
        ehdr.e_entry     = swap32(ehdr.e_entry);
        ehdr.e_phoff     = swap32(ehdr.e_phoff);
        ehdr.e_shoff     = swap32(ehdr.e_shoff);
        ehdr.e_flags     = swap32(ehdr.e_flags);
        ehdr.e_ehsize    = swap16(ehdr.e_ehsize);
        ehdr.e_phentsize = swap16(ehdr.e_phentsize);
        ehdr.e_phnum     = swap16(ehdr.e_phnum);
        ehdr.e_shentsize = swap16(ehdr.e_shentsize);
        ehdr.e_shnum     = swap16(ehdr.e_shnum);
        ehdr.e_shstrndx  = swap16(ehdr.e_shstrndx);
    }
    if (ehdr.e_machine != EM_MIPS) {
        fprintf(stderr, "mips32rt: %s: not a MIPS (EM_MIPS) ELF\n", label);
        return -1;
    }
    if ((ehdr.e_flags & EF_MIPS_ABI2) != 0U ||
        ((ehdr.e_flags & EF_MIPS_ABI) != 0U &&
         (ehdr.e_flags & EF_MIPS_ABI) != E_MIPS_ABI_O32)) {
        fprintf(stderr, "mips32rt: %s: unsupported MIPS ABI flags 0x%x\n",
                label, ehdr.e_flags);
        return -1;
    }
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        fprintf(stderr, "mips32rt: %s: unsupported ELF type %u\n", label, ehdr.e_type);
        return -1;
    }
    if (ehdr.e_phentsize != sizeof(elf32_phdr_t) || ehdr.e_phnum == 0U || ehdr.e_phnum > 64U) {
        fprintf(stderr, "mips32rt: %s: invalid program header table\n", label);
        return -1;
    }

    elf32_phdr_t phdrs[64];
    size_t phdr_bytes = (size_t)ehdr.e_phnum * sizeof(elf32_phdr_t);
    if (pread_full(fd, phdrs, phdr_bytes, (off_t)ehdr.e_phoff) != 0) {
        fprintf(stderr, "mips32rt: %s: failed to read program headers\n", label);
        return -1;
    }
    if (is_be) {
        for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
            phdrs[i].p_type   = swap32(phdrs[i].p_type);
            phdrs[i].p_offset = swap32(phdrs[i].p_offset);
            phdrs[i].p_vaddr  = swap32(phdrs[i].p_vaddr);
            phdrs[i].p_paddr  = swap32(phdrs[i].p_paddr);
            phdrs[i].p_filesz = swap32(phdrs[i].p_filesz);
            phdrs[i].p_memsz  = swap32(phdrs[i].p_memsz);
            phdrs[i].p_flags  = swap32(phdrs[i].p_flags);
            phdrs[i].p_align  = swap32(phdrs[i].p_align);
        }
    }

    uint32_t min_vaddr = UINT32_MAX;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_memsz > 0U) {
            if (phdrs[i].p_vaddr < min_vaddr) {
                min_vaddr = phdrs[i].p_vaddr;
            }
        }
    }
    if (min_vaddr == UINT32_MAX) {
        fprintf(stderr, "mips32rt: %s: no PT_LOAD segments\n", label);
        return -1;
    }

    uint32_t load_bias = 0U;
    if (ehdr.e_type == ET_DYN && min_vaddr < 0x10000U) {
        load_bias = default_pie_base;
    }

    if (ehdr.e_entry == 0U) {
        fprintf(stderr, "mips32rt: %s: missing entry point (e_entry == 0)\n", label);
        return -1;
    }
    if ((ehdr.e_entry & 0x3U) != 0U) {
        /* MIPS32 instructions are always 4-byte aligned. */
        fprintf(stderr, "mips32rt: %s: misaligned entry point 0x%x\n",
                label, ehdr.e_entry);
        return -1;
    }

    uint64_t entry64 = 0ULL;
    if (ehdr.e_entry != 0U) {
        entry64 = (uint64_t)ehdr.e_entry + (uint64_t)load_bias;
        if (entry64 < 0x10000ULL || entry64 >= (uint64_t)MIPS32_TASK_SIZE_TOP) {
            fprintf(stderr, "mips32rt: %s: entry point 0x%llx out of guest bounds\n",
                    label, (unsigned long long)entry64);
            return -1;
        }
    }

    memset(out, 0, sizeof(*out));
    out->load_bias = load_bias + mips32_page_down(min_vaddr);
    out->entry     = (uint32_t)entry64;
    out->phent     = ehdr.e_phentsize;
    out->phnum     = ehdr.e_phnum;
    /* Endianness and FP-mode flags for the ctx (SPEC 2.1/2.2): the BE bit
     * lives in cp0_config1 bit 0; nan2008 comes from e_flags (FR mode
     * needs .MIPS.abiflags and arrives with the Phase 5 dynamic loader). */
    out->is_be   = is_be ? 1U : 0U;
    out->nan2008 = (ehdr.e_flags & EF_MIPS_NAN2008) != 0U ? 1U : 0U;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const elf32_phdr_t *ph = &phdrs[i];
        if (ph->p_type == PT_PHDR) {
            uint64_t phdr_va64 = (uint64_t)load_bias + (uint64_t)ph->p_vaddr;
            if (phdr_va64 + phdr_bytes <= (uint64_t)MIPS32_TASK_SIZE_TOP) {
                out->phdr_vaddr = (uint32_t)phdr_va64;
            }
        } else if (ph->p_type == PT_INTERP) {
            if (ph->p_filesz == 0U || ph->p_filesz >= sizeof(out->interp_path)) {
                fprintf(stderr, "mips32rt: %s: invalid PT_INTERP filesz %u\n", label, ph->p_filesz);
                return -1;
            }
            if (pread_full(fd, out->interp_path, ph->p_filesz, (off_t)ph->p_offset) != 0) {
                return -1;
            }
            out->interp_path[ph->p_filesz] = '\0';
            if (out->interp_path[0] == '\0') {
                return -1;
            }
        }
    }

    uint32_t highest_mapped_end  = 0U;
    uint32_t highest_mapped_prot = 0U;
    uint32_t prev_seg_end        = 0U;
    uint32_t fallback_phdr_vaddr = 0U;
    bool     entry_in_load       = false;
    bool     phdr_in_load        = false;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const elf32_phdr_t *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0U) {
            continue;
        }
        if (ph->p_filesz > ph->p_memsz) {
            fprintf(stderr, "mips32rt: %s: invalid segment filesz (0x%x) > memsz (0x%x)\n",
                    label, ph->p_filesz, ph->p_memsz);
            return -1;
        }

        uint64_t seg_vaddr64 = (uint64_t)load_bias + (uint64_t)ph->p_vaddr;
        uint64_t memsz       = (uint64_t)ph->p_memsz;
        if (seg_vaddr64 >= (uint64_t)MIPS32_TASK_SIZE_TOP ||
            seg_vaddr64 + memsz > (uint64_t)MIPS32_TASK_SIZE_TOP) {
            fprintf(stderr, "mips32rt: %s: segment [0x%llx, 0x%llx) out of guest bounds\n",
                    label, (unsigned long long)seg_vaddr64,
                    (unsigned long long)(seg_vaddr64 + memsz));
            return -1;
        }

        uint32_t seg_vaddr = (uint32_t)seg_vaddr64;
        uint64_t seg_end64 = seg_vaddr64 + memsz;
        if (seg_vaddr < prev_seg_end) {
            fprintf(stderr, "mips32rt: %s: overlapping or out-of-order PT_LOAD segment at 0x%x\n",
                    label, seg_vaddr);
            return -1;
        }
        prev_seg_end = (uint32_t)seg_end64;

        if (out->entry != 0U) {
            /* MIPS: fixed 4-byte instructions, entry needs no ISA-bit masking. */
            uint32_t entry_pc      = out->entry;
            uint32_t entry_min_len = 1U;
            if ((ph->p_flags & PF_X) != 0U &&
                entry_pc >= seg_vaddr &&
                (uint64_t)entry_pc + entry_min_len <= seg_vaddr64 + memsz) {
                entry_in_load = true;
            }
        }
        uint32_t page_start = mips32_page_down(seg_vaddr);
        uint64_t map_end64  = (seg_end64 + 0xFFFULL) & ~0xFFFULL;
        if (page_start < 0x10000U || map_end64 > (uint64_t)MIPS32_TASK_SIZE_TOP) {
            fprintf(stderr, "mips32rt: %s: segment [0x%x, 0x%llx) out of guest bounds\n",
                    label, page_start, (unsigned long long)map_end64);
            return -1;
        }
        uint32_t map_end   = (uint32_t)map_end64;
        uint32_t map_start = (page_start < highest_mapped_end) ? highest_mapped_end : page_start;
        for (size_t r = 0U; r < ctx->region_count; r++) {
            if (map_start < ctx->regions[r].end && map_end > ctx->regions[r].start) {
                fprintf(stderr, "mips32rt: %s: segment [0x%x, 0x%x) overlaps existing region\n",
                        label, map_start, map_end);
                return -1;
            }
        }

        uint32_t guest_prot = ((ph->p_flags & PF_R) ? (uint32_t)PROT_READ : 0U) |
                              ((ph->p_flags & PF_W) ? (uint32_t)PROT_WRITE : 0U) |
                              ((ph->p_flags & PF_X) ? (uint32_t)PROT_EXEC : 0U);

        uint32_t shared_end  = (map_end < map_start) ? map_end : map_start;
        uint32_t merged_prot = highest_mapped_prot | guest_prot;
        if (page_start < map_start) {
#ifdef __APPLE__
            uint32_t hs = page_start & ~0x3FFFU;
            uint32_t he = (shared_end + 0x3FFFU) & ~0x3FFFU;
            if (mprotect(mips32_guest_ptr(ctx, hs), he - hs, PROT_READ | PROT_WRITE) != 0) {
#else
            if (mprotect(mips32_guest_ptr(ctx, page_start), shared_end - page_start,
                         PROT_READ | PROT_WRITE) != 0) {
#endif
                fprintf(stderr, "mips32rt: %s: mprotect RW failed on shared page [0x%x, 0x%x): %s\n",
                        label, page_start, shared_end, strerror(errno));
                return -1;
            }
        }

        if (map_end > map_start) {
#ifdef __APPLE__
            uint32_t hs = map_start & ~0x3FFFU;
            uint32_t he = (map_end + 0x3FFFU) & ~0x3FFFU;
            if (mprotect(mips32_guest_ptr(ctx, hs), he - hs, PROT_READ | PROT_WRITE) != 0) {
                fprintf(stderr, "mips32rt: %s: failed to map segment [0x%x, 0x%x): %s\n",
                        label, map_start, map_end, strerror(errno));
                return -1;
            }
            memset(mips32_guest_ptr(ctx, map_start), 0, map_end - map_start);
#else
            void *res = mmap(mips32_guest_ptr(ctx, map_start), map_end - map_start,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (res == MAP_FAILED) {
                fprintf(stderr, "mips32rt: %s: failed to map segment [0x%x, 0x%x): %s\n",
                        label, map_start, map_end, strerror(errno));
                return -1;
            }
#endif
        }

        uint32_t read_file_off = ph->p_offset;
        uint32_t read_file_len = ph->p_filesz;
        if (ph->p_filesz > 0U) {
            uint32_t page_off = ph->p_vaddr & 0xFFFU;
            uint32_t dst_va   = seg_vaddr;
            if (page_start == map_start && page_off != 0U && ph->p_offset >= page_off) {
                read_file_off = ph->p_offset - page_off;
                read_file_len = ph->p_filesz + page_off;
                dst_va        = map_start;
            }
            if (pread_full(fd, mips32_guest_ptr(ctx, dst_va), read_file_len,
                           (off_t)read_file_off) != 0) {
                fprintf(stderr, "mips32rt: %s: failed to read segment payload\n", label);
                return -1;
            }
        }

        if (ph->p_memsz > ph->p_filesz) {
            memset(mips32_guest_ptr(ctx, seg_vaddr + ph->p_filesz), 0,
                   (size_t)(ph->p_memsz - ph->p_filesz));
        }

        if (page_start < map_start) {
            if (protect_and_record_seg(ctx, page_start, shared_end, merged_prot, label) != 0) {
                return -1;
            }
            highest_mapped_prot = merged_prot;
        }
        if (map_end > map_start) {
            if (protect_and_record_seg(ctx, map_start, map_end, guest_prot, label) != 0) {
                return -1;
            }
            highest_mapped_end  = map_end;
            highest_mapped_prot = guest_prot;
        }

        if (ph->p_flags & PF_X) {
            if (out->text_start == 0U || seg_vaddr < out->text_start) {
                out->text_start = seg_vaddr;
            }
            if (seg_vaddr + ph->p_memsz > out->text_end) {
                out->text_end = seg_vaddr + ph->p_memsz;
            }
        }

        uint32_t base_va = (read_file_off < ph->p_offset) ? page_start : seg_vaddr;
        if (out->phdr_vaddr != 0U &&
            out->phdr_vaddr >= base_va &&
            (uint64_t)out->phdr_vaddr + phdr_bytes <= (uint64_t)base_va + (uint64_t)read_file_len) {
            phdr_in_load = true;
        }
        if (fallback_phdr_vaddr == 0U && read_file_off <= ehdr.e_phoff &&
            (uint64_t)ehdr.e_phoff + phdr_bytes <= (uint64_t)read_file_off + (uint64_t)read_file_len) {
            fallback_phdr_vaddr = base_va + (ehdr.e_phoff - read_file_off);
        }

        if (map_end > out->max_vaddr) {
            out->max_vaddr = map_end;
        }
    }

    if (!phdr_in_load) {
        out->phdr_vaddr = 0U;
    }
    if (out->phdr_vaddr == 0U) {
        out->phdr_vaddr = fallback_phdr_vaddr;
    }

    /* e_entry == 0 is rejected above; MIPS32r2 has a single instruction set. */

    if (!entry_in_load) {
        fprintf(stderr, "mips32rt: %s: entry point 0x%x is not within any PT_LOAD segment\n",
                label, out->entry);
        return -1;
    }

    return 0;
}

/* Phase 5 (lane L5a): measure a PT_INTERP file's PT_LOAD span so the
 * interpreter lands at a verified non-colliding base.  Reads only the ELF
 * and program headers (same admission rules as load_elf32_image, which
 * revalidates everything on the real load); returns the PT_LOAD span
 * length, or -1 when the file is not an admissible MIPS ELF.  Standard
 * MIPS ld.so.1 is ET_DYN with min_vaddr 0, so the picked base applies as
 * the load bias; any other shape still passes through load_elf32_image's
 * own overlap checks unchanged. */
static int interp_measure_span(int fd, uint64_t *out_span)
{
    elf32_ehdr_t ehdr;
    elf32_phdr_t phdrs[64];
    size_t phdr_bytes;
    bool is_be;
    uint64_t lo = UINT64_MAX;
    uint64_t hi = 0ULL;
    uint16_t i;

    if (pread_full(fd, &ehdr, sizeof(ehdr), 0) != 0) {
        return -1;
    }
    if (ehdr.e_ident[0] != 0x7fU || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F' ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS32 ||
        (ehdr.e_ident[EI_DATA] != ELFDATA2LSB &&
         ehdr.e_ident[EI_DATA] != ELFDATA2MSB)) {
        return -1;
    }
    is_be = ehdr.e_ident[EI_DATA] == ELFDATA2MSB;
    if (is_be) {
        ehdr.e_machine  = swap16(ehdr.e_machine);
        ehdr.e_phoff    = swap32(ehdr.e_phoff);
        ehdr.e_phentsize = swap16(ehdr.e_phentsize);
        ehdr.e_phnum    = swap16(ehdr.e_phnum);
    }
    if (ehdr.e_machine != EM_MIPS || ehdr.e_phentsize != sizeof(elf32_phdr_t) ||
        ehdr.e_phnum == 0U || ehdr.e_phnum > 64U) {
        return -1;
    }
    phdr_bytes = (size_t)ehdr.e_phnum * sizeof(elf32_phdr_t);
    if (pread_full(fd, phdrs, phdr_bytes, (off_t)ehdr.e_phoff) != 0) {
        return -1;
    }
    for (i = 0; i < ehdr.e_phnum; i++) {
        uint64_t seg_lo;
        uint64_t seg_hi;
        if (is_be) {
            phdrs[i].p_type   = swap32(phdrs[i].p_type);
            phdrs[i].p_vaddr  = swap32(phdrs[i].p_vaddr);
            phdrs[i].p_memsz  = swap32(phdrs[i].p_memsz);
        }
        if (phdrs[i].p_type != PT_LOAD || phdrs[i].p_memsz == 0U) {
            continue;
        }
        seg_lo = (uint64_t)(phdrs[i].p_vaddr & ~0xFFFU);
        seg_hi = ((uint64_t)phdrs[i].p_vaddr + (uint64_t)phdrs[i].p_memsz +
                  0xFFFULL) & ~0xFFFULL;
        if (seg_hi <= seg_lo) {
            return -1;
        }
        if (seg_lo < lo) {
            lo = seg_lo;
        }
        if (seg_hi > hi) {
            hi = seg_hi;
        }
    }
    if (lo == UINT64_MAX || hi > (uint64_t)MIPS32_TASK_SIZE_TOP) {
        return -1;
    }
    *out_span = hi - lo;
    return 0;
}

/* Phase 5 (lane L5a): first-fit 64 KiB-aligned interpreter base at or above
 * max(brk, 0x3F000000) whose [base, base+span) overlaps no recorded region.
 * Returns 0 when no window fits (caller fails the load). */
static uint32_t interp_pick_base(mips32_ctx_t *ctx, uint64_t span)
{
    uint64_t base = ctx->brk_base > 0x3F000000U ? (uint64_t)ctx->brk_base : 0x3F000000ULL;
    size_t r;

    base = (base + 0xFFFFULL) & ~0xFFFFULL;
    while (base + span <= (uint64_t)MIPS32_TASK_SIZE_TOP) {
        uint32_t lo = (uint32_t)base;
        uint32_t end = (uint32_t)(base + span);
        int clash = 0;
        for (r = 0U; r < ctx->region_count; r++) {
            if (lo < ctx->regions[r].end && end > ctx->regions[r].start) {
                clash = 1;
                break;
            }
        }
        if (!clash) {
            return lo;
        }
        base += 0x10000ULL;
    }
    return 0U;
}

int rt32_elf_load(mips32_ctx_t *ctx, int exec_fd, const char *path, rt32_elf_info_t *out_info)
{
    if (!ctx || !out_info) {
        return -1;
    }

    int fd = exec_fd;
    if (fd < 0) {
        if (!path) {
            return -1;
        }
        fd = rt32_open_guest_ro(ctx, path);
        if (fd < 0) {
            fprintf(stderr, "mips32rt: cannot open '%s': %s\n", path, strerror(errno));
            return -1;
        }
    }

    int rc = load_elf32_image(ctx, fd, 0x00400000U, path ? path : "[guest]", out_info);
    close(fd);
    if (rc != 0) {
        return -1;
    }

    ctx->elf_base  = out_info->load_bias;
    ctx->elf_entry = out_info->entry;
    ctx->brk_base  = mips32_page_up(out_info->max_vaddr);
    ctx->brk_curr  = ctx->brk_base;
    /* SPEC 2.1 software config: bit 0 records BE (mips) vs LE (mipsel). */
    ctx->cp0_config1 = out_info->is_be;
    ctx->nan2008     = (uint8_t)out_info->nan2008;
    ctx->fr_mode     = 0U; /* O32 default; .MIPS.abiflags may raise it in Phase 5 */

    /* Load PT_INTERP if present */
    if (out_info->interp_path[0] != '\0') {
        int ifd = rt32_open_guest_ro(ctx, out_info->interp_path);
        if (ifd < 0) {
            fprintf(stderr, "mips32rt: cannot open interpreter '%s': %s\n",
                    out_info->interp_path, strerror(errno));
            return -1;
        }

        rt32_elf_info_t interp_info;
        uint64_t interp_span = 0ULL;
        uint32_t interp_base;
        int irc;
        /* Size the interpreter before mapping it so the base is verified
         * free; load_elf32_image re-checks every segment on the way in. */
        if (interp_measure_span(ifd, &interp_span) != 0 ||
            (interp_base = interp_pick_base(ctx, interp_span)) == 0U) {
            fprintf(stderr, "mips32rt: no room for interpreter '%s'\n",
                    out_info->interp_path);
            close(ifd);
            return -1;
        }
        irc = load_elf32_image(ctx, ifd, interp_base, out_info->interp_path, &interp_info);
        close(ifd);
        if (irc != 0) {
            return -1;
        }
        out_info->interp_base = interp_info.load_bias;
        ctx->interp_base      = interp_info.load_bias;
        ctx->elf_entry        = interp_info.entry;
        uint32_t interp_end   = mips32_page_up(interp_info.max_vaddr);
        if (ctx->brk_base >= interp_info.load_bias && ctx->brk_base < interp_end) {
            ctx->brk_base = interp_end;
            ctx->brk_curr = ctx->brk_base;
        }
    }

    return 0;
}

/* No kuser-style helper page exists on MIPS O32; the synthetic sigtramp at
 * MIPS32_SIGTRAMP arrives with the Phase 4 signal subsystem. */
