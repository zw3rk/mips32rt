/* E05: LWL/LWR and SWL/SWR unaligned semantics probe (mipsel + mips BE).
 *
 * Exercises single LWL / LWR / SWL / SWR at alignments 0..3 against a
 * known 4-byte pattern, the classic LWL+LWR / SWL+SWR pairs, and plain
 * unaligned LW / SW (fault-or-emulate behavior) under qemu-user.
 *
 * Build (LE): mipsel-linux-gnu-gcc -march=mips32r2 -O1 -o probe-le probe.c
 * Build (BE): mips-linux-gnu-gcc -march=mips32r2 -EB -O1 -o probe-be probe.c
 * Run   (LE): qemu-mipsel probe-le
 * Run   (BE): qemu-mips probe-be
 */
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static sigjmp_buf jbuf;
static volatile int caught_sig;

static void handler(int sig)
{
    caught_sig = sig;
    siglongjmp(jbuf, 1);
}

/* Known pattern bytes at an aligned base. */
static unsigned char area[16] __attribute__((aligned(8)));

#define INIT_RT 0xAABBCCDDu

static uint32_t do_lwl(unsigned char *addr, uint32_t init)
{
    uint32_t rt = init;
    __asm__ volatile("lwl %0, 0(%1)" : "+r"(rt) : "r"(addr) : "memory");
    return rt;
}

static uint32_t do_lwr(unsigned char *addr, uint32_t init)
{
    uint32_t rt = init;
    __asm__ volatile("lwr %0, 0(%1)" : "+r"(rt) : "r"(addr) : "memory");
    return rt;
}

/* Classic unaligned-word load idiom: LWL addr ; LWR addr (same address). */
static uint32_t do_pair_load(unsigned char *addr, uint32_t init)
{
    uint32_t rt = init;
    __asm__ volatile(
        "lwl %0, 0(%1)\n"
        "lwr %0, 0(%1)\n"
        : "+r"(rt)
        : "r"(addr)
        : "memory");
    return rt;
}

static void do_swl(unsigned char *addr, uint32_t v)
{
    __asm__ volatile("swl %0, 0(%1)" : : "r"(v), "r"(addr) : "memory");
}

static void do_swr(unsigned char *addr, uint32_t v)
{
    __asm__ volatile("swr %0, 0(%1)" : : "r"(v), "r"(addr) : "memory");
}

/* Endianness-correct unaligned word load idiom (touches A and A+3):
 * BE: lwl 0(A); lwr 3(A)   LE: lwr 0(A); lwl 3(A). */
static uint32_t do_unaligned_load(unsigned char *addr, uint32_t init)
{
    uint32_t rt = init;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __asm__ volatile(
        "lwr %0, 0(%1)\n"
        "lwl %0, 3(%1)\n"
        : "+r"(rt)
        : "r"(addr)
        : "memory");
#else
    __asm__ volatile(
        "lwl %0, 0(%1)\n"
        "lwr %0, 3(%1)\n"
        : "+r"(rt)
        : "r"(addr)
        : "memory");
#endif
    return rt;
}

/* Endianness-correct unaligned word store idiom. */
static void do_unaligned_store(unsigned char *addr, uint32_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __asm__ volatile(
        "swr %0, 0(%1)\n"
        "swl %0, 3(%1)\n"
        :
        : "r"(v), "r"(addr)
        : "memory");
#else
    __asm__ volatile(
        "swl %0, 0(%1)\n"
        "swr %0, 3(%1)\n"
        :
        : "r"(v), "r"(addr)
        : "memory");
#endif
}

/* Classic unaligned-word store idiom. */
static void do_pair_store(unsigned char *addr, uint32_t v)
{
    __asm__ volatile(
        "swl %0, 0(%1)\n"
        "swr %0, 0(%1)\n"
        :
        : "r"(v), "r"(addr)
        : "memory");
}

static void reset_mem(void)
{
    memset(area, 0x00, sizeof area);
    area[0] = 0x11;
    area[1] = 0x22;
    area[2] = 0x33;
    area[3] = 0x44;
}

static void print_mem(const char *tag, int k)
{
    printf("%s off=%d mem=%02X:%02X:%02X:%02X:%02X:%02X\n", tag, k,
        area[0], area[1], area[2], area[3], area[4], area[5]);
}

int main(void)
{
    int k;
    union { uint32_t w; unsigned char b[4]; } e;
    struct sigaction sa, oldbus, oldsegv;

    e.w = 1;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    printf("ENDIAN=LE\n");
#else
    printf("ENDIAN=BE\n");
#endif
    printf("HOST_BYTE0=%02X (1 means LE landing)\n", e.b[0]);
    printf("INIT_RT=0x%08X MEM_PATTERN=11:22:33:44\n", INIT_RT);

    /* Single LWL at each alignment. */
    for (k = 0; k < 4; k++) {
        uint32_t r;
        reset_mem();
        r = do_lwl(area + k, INIT_RT);
        printf("LWL off=%d init=0x%08X result=0x%08X\n", k, INIT_RT, r);
    }
    /* Single LWR at each alignment. */
    for (k = 0; k < 4; k++) {
        uint32_t r;
        reset_mem();
        r = do_lwr(area + k, INIT_RT);
        printf("LWR off=%d init=0x%08X result=0x%08X\n", k, INIT_RT, r);
    }
    /* Pair LWL+LWR at same address. */
    for (k = 0; k < 4; k++) {
        uint32_t r;
        reset_mem();
        r = do_pair_load(area + k, INIT_RT);
        printf("PAIRLOAD off=%d init=0x%08X result=0x%08X\n", k, INIT_RT, r);
    }
    /* Single SWL at each alignment (zeroed field, store INIT_RT). */
    for (k = 0; k < 4; k++) {
        memset(area, 0x00, sizeof area);
        do_swl(area + k, INIT_RT);
        print_mem("SWL", k);
    }
    /* Single SWR at each alignment. */
    for (k = 0; k < 4; k++) {
        memset(area, 0x00, sizeof area);
        do_swr(area + k, INIT_RT);
        print_mem("SWR", k);
    }
    /* Pair SWL+SWR at same address. */
    for (k = 0; k < 4; k++) {
        memset(area, 0x00, sizeof area);
        do_pair_store(area + k, 0x11223344u);
        print_mem("PAIRSTORE", k);
    }
    /* True unaligned idiom load (sentinel 55:66:77 past pattern). */
    for (k = 0; k < 4; k++) {
        uint32_t r;
        reset_mem();
        area[4] = 0x55;
        area[5] = 0x66;
        area[6] = 0x77;
        r = do_unaligned_load(area + k, INIT_RT);
        printf("ULW off=%d init=0x%08X result=0x%08X\n", k, INIT_RT, r);
    }
    /* True unaligned idiom store. */
    for (k = 0; k < 4; k++) {
        memset(area, 0x00, sizeof area);
        do_unaligned_store(area + k, 0xAABBCCDDu);
        print_mem("USW", k);
    }

    /* Plain unaligned LW / SW: fault (SIGBUS/SIGSEGV/AdEL) or emulate? */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, &oldbus);
    sigaction(SIGSEGV, &sa, &oldsegv);
    for (k = 1; k < 4; k++) {
        uint32_t r = 0xDEADBEEFu;
        unsigned char *p = area + k;
        reset_mem();
        caught_sig = 0;
        if (sigsetjmp(jbuf, 1) == 0) {
            __asm__ volatile("lw %0, 0(%1)" : "=r"(r) : "r"(p) : "memory");
            printf("LW off=%d value=0x%08X signal=none\n", k, r);
        } else {
            printf("LW off=%d value=UNSET signal=%d\n", k, caught_sig);
        }
    }
    for (k = 1; k < 4; k++) {
        unsigned char *p = area + k;
        memset(area, 0x00, sizeof area);
        caught_sig = 0;
        if (sigsetjmp(jbuf, 1) == 0) {
            __asm__ volatile("sw %0, 0(%1)" : : "r"(0xAABBCCDDu), "r"(p) : "memory");
            printf("SW off=%d mem=%02X:%02X:%02X:%02X:%02X:%02X signal=none\n",
                k, area[0], area[1], area[2], area[3], area[4], area[5]);
        } else {
            printf("SW off=%d mem=UNSET signal=%d\n", k, caught_sig);
        }
    }
    sigaction(SIGBUS, &oldbus, NULL);
    sigaction(SIGSEGV, &oldsegv, NULL);

    printf("DONE\n");
    return 0;
}
