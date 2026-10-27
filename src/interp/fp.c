/*
 * src/interp/fp.c — FPU reference interpreter (Phase 3, lane L3a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Software IEEE-754 S/D arithmetic in pure integer math: the host FP
 * environment is never touched (no float/double/fenv), so results are
 * bit-exact and host-independent.  NaN/ABS semantics follow
 * experiments/E03/FINDINGS.md (qemu-mipsel 7.2 ground truth), selected
 * by ctx->nan2008: Legacy quiet bit = fraction MSB clear, 2008 quiet
 * bit = fraction MSB set; sNaN arithmetic input raises Invalid
 * (Cause.V + Flags.V, trap via mips_trap SIGFPE when Enable.V is set,
 * else the operand quieted in-mode with payload preserved).
 *
 * Deliberate E03-over-SPEC point: SPEC 2.2 calls ABS/NEG arithmetic
 * that signals Invalid on sNaN, but qemu 7.2 never signals for
 * ABS.S/ABS.D (both NaN patterns, trap enabled, either NaN mode), so
 * ABS/NEG/MOV are non-arithmetic sign-bit ops that never raise,
 * matching the RC3 oracle.  MFHC1/MTHC1 are FR-agnostic flat high-half
 * moves (qemu emulates them silently in FR=1 too); D/L-format register
 * operands must still be even in FR=0.  All FP state lives in
 * ctx->fpr/ctx->fcsr.
 */

#include <stdint.h>

#include "mips32rt.h"
#include "interp/fp.h"
#include "interp/interp.h"

/* Exception indices: I U O Z V. Flag bit = 1 << (e + 2), enable << 5. */
enum { FP_E_I = 0, FP_E_U = 1, FP_E_O = 2, FP_E_Z = 3, FP_E_V = 4 };

/* Binary format parameters: [0] = S, [1] = D. */
struct fp_fmt { unsigned eb; unsigned mb; int bias; };
static const struct fp_fmt fp_ff[2] = { { 8u, 23u, 127 }, { 11u, 52u, 1023 } };

/* Pending FP exception state for one instruction. */
struct fp_st { mips32_ctx_t *ctx; uint32_t pc; uint32_t cause; uint32_t fl; int trap; };

static void fp_raise(struct fp_st *s, unsigned e)
{
    uint32_t bit = 1u << (e + 2u);
    s->cause |= bit << 10;
    s->fl |= bit;
    if ((s->ctx->fcsr & (bit << 5)) != 0u)
        s->trap = 1;
}

/* Cause (17:12) replaced per-insn, Flags (6:2) accumulate. Trap: Cause
 * sticks, Flags do not (E03: post-trap keeps Cause.V, no Flags.V, no E
 * bit: qemu-mipsel reports 0x10800 for the Invalid trap). */
static int fp_commit(struct fp_st *s)
{
    s->ctx->fcsr &= ~0x3F000u;
    s->ctx->fcsr |= s->cause;
    if (s->trap) {
        mips_trap(s->ctx, 8, s->pc);
        return MIPS_FAULT;
    }
    s->ctx->fcsr |= s->fl;
    return 0;
}

static int fp_write_s(struct fp_st *s, unsigned fd, uint32_t v)
{
    if (fp_commit(s) != 0)
        return MIPS_FAULT;
    s->ctx->fpr[fd] = (s->ctx->fpr[fd] & 0xFFFFFFFF00000000ULL) | v;
    return 0;
}

static int fp_write_d(struct fp_st *s, unsigned fd, uint64_t v)
{
    if (fp_commit(s) != 0)
        return MIPS_FAULT;
    s->ctx->fpr[fd] = v;
    return 0;
}

/* Unpacked value classes. */
enum { FP_ZERO = 0, FP_SUB = 1, FP_NORM = 2, FP_INF = 3, FP_NAN = 4 };

typedef struct {
    int sign; int cls; int qnan; int32_t exp; uint64_t frac; uint64_t raw;
} fpv_t;

static fpv_t fp_unpack(unsigned f, uint64_t w, int nan2008)
{
    const struct fp_fmt *p = &fp_ff[f];
    uint64_t exp = (w >> p->mb) & ((p->eb == 8u) ? 0xFFu : 0x7FFu);
    uint64_t top = (uint64_t)1 << (p->mb - 1u);
    fpv_t v;
    v.sign = (int)((w >> (p->mb + p->eb)) & 1u);
    v.frac = w & ((((uint64_t)1) << p->mb) - 1u);
    v.raw = w;
    v.qnan = 0;
    v.exp = 0;
    if (exp == ((p->eb == 8u) ? 0xFFu : 0x7FFu)) {
        if (v.frac == 0u) { v.cls = FP_INF; return v; }
        v.cls = FP_NAN;
        v.qnan = nan2008 ? ((v.frac & top) != 0u) : ((v.frac & top) == 0u);
    } else if (exp == 0u) {
        if (v.frac == 0u) { v.cls = FP_ZERO; return v; }
        v.cls = FP_SUB;
        v.exp = 1 - p->bias;
    } else {
        v.cls = FP_NORM;
        v.exp = (int32_t)exp - p->bias;
    }
    return v;
}

/* Mode default Invalid-operation quiet NaN (E03 table). */
static uint64_t fp_default_nan(unsigned f, int nan2008)
{
    if (f == 0u)
        return nan2008 ? 0x7FC00000ULL : 0x7FBFFFFFULL;
    return nan2008 ? 0x7FF8000000000000ULL : 0x7FF7FFFFFFFFFFFFULL;
}

/* Impose the mode quiet bit on an sNaN, preserving sign + payload. */
static uint64_t fp_quiet(unsigned f, uint64_t w, int nan2008)
{
    uint64_t top = (uint64_t)1 << (fp_ff[f].mb - 1u);
    return nan2008 ? (w | top) : (w & ~top);
}

/* Full mantissa: hidden leading bit for normals, bare frac otherwise. */
static uint64_t fp_full(unsigned f, const fpv_t *v)
{
    if (v->cls == FP_NORM)
        return (((uint64_t)1) << fp_ff[f].mb) | v->frac;
    return v->frac;
}

/* sNaN: Invalid + Legacy canonical QNaN, 2008 quieted w/ payload. */
static int fp_nan2(struct fp_st *s, unsigned f, const fpv_t *a,
                   const fpv_t *b, uint64_t *out)
{
    const fpv_t *sn = 0;
    if (a->cls != FP_NAN && b->cls != FP_NAN)
        return 0;
    if (a->cls == FP_NAN && a->qnan == 0)
        sn = a;
    else if (b->cls == FP_NAN && b->qnan == 0)
        sn = b;
    if (sn != 0) {
        fp_raise(s, FP_E_V);
        if (s->ctx->nan2008 == 0)
            *out = fp_default_nan(f, 0);
        else
            *out = fp_quiet(f, sn->raw, 1);
    } else {
        *out = (a->cls == FP_NAN) ? a->raw : b->raw;
    }
    return 1;
}

/* 53x53 -> 106-bit product from 27-bit limbs (no __int128). */
static void fp_mul53(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
    uint64_t p0 = (a & 0x7FFFFFFULL) * (b & 0x7FFFFFFULL);
    uint64_t p1 = (a >> 27) * (b & 0x7FFFFFFULL);
    uint64_t p2 = (a & 0x7FFFFFFULL) * (b >> 27);
    uint64_t p3 = (a >> 27) * (b >> 27);
    uint64_t t = p1 + p2, tl = t & 0x7FFFFFFULL, th = t >> 27;
    uint64_t l = p0 + (tl << 27), c = (l < p0) ? 1u : 0u, n;
    n = l + ((th & 0x3FFULL) << 54);
    c += (n < l) ? 1u : 0u;
    l = n + ((p3 & 0x3FFULL) << 54);
    c += (l < n) ? 1u : 0u;
    *hi = (th >> 10) + (p3 >> 10) + c;
    *lo = l;
}

/* Normalize finite nonzero (m, e) so m lies in [2^MB, 2^(MB+1)). */
static void fp_norm(unsigned f, uint64_t *m, int32_t *e)
{
    uint64_t hid = (uint64_t)1 << fp_ff[f].mb;
    while (*m < hid) {
        *m <<= 1;
        (*e)--;
    }
}

/* Swap two (mantissa, exp, sign) triples after subnormal normalization. */
static void fp_swap(uint64_t *m1, int32_t *e1, int *s1,
                    uint64_t *m2, int32_t *e2, int *s2)
{
    uint64_t tm = *m1; int32_t te = *e1; int ts = *s1;
    *m1 = *m2; *e1 = *e2; *s1 = *s2;
    *m2 = tm; *e2 = te; *s2 = ts;
}

/* Pack value = man * 2^(E - MB - 3), man != 0: normalize hidden bit to
 * MB+3 (GRS in bits 2:0), round once per FCSR RM, then overflow
 * (O+I, directed-rounding results when trap-disabled) and tininess
 * (shift to subnormal, U when tiny and inexact).  Tininess is detected
 * before rounding; a result rounding up to the smallest normal is
 * exact-normal (E == emin). */
static uint64_t fp_round_pack(struct fp_st *s, unsigned f, int sign,
                              int32_t E, uint64_t man, int sticky)
{
    const struct fp_fmt *p = &fp_ff[f];
    uint64_t norm = (uint64_t)1 << (p->mb + 3u);
    uint32_t rm = s->ctx->fcsr & 0x3u;
    int32_t emax = p->bias, emin = 1 - p->bias;
    int tiny = 0, any, inc = 0;
    unsigned grs;

    if (man == 0u)
        return ((uint64_t)(sign & 1)) << (p->mb + p->eb);
    while (man >= (norm << 1)) {
        sticky |= (int)(man & 1u);
        man >>= 1;
        E++;
    }
    while (man < norm) {
        man <<= 1;
        E--;
    }
    if (E < emin) {
        int32_t need = emin - E;
        tiny = 1;
        if (need >= 64) {
            sticky |= (man != 0u);
            man = 0u;
        } else {
            sticky |= ((man & ((((uint64_t)1) << need) - 1u)) != 0u);
            man >>= need;
        }
        E = emin;
        if (man == 0u) {
            if (sticky) {
                fp_raise(s, FP_E_U);
                fp_raise(s, FP_E_I);
            }
            return ((uint64_t)(sign & 1)) << (p->mb + p->eb);
        }
    }
    grs = (unsigned)(man & 7u);
    any = (grs | (unsigned)sticky) != 0u;
    if (rm == 0u)
        inc = ((grs > 4u) || (grs == 4u && (sticky || ((man >> 3) & 1u)))) ? 1 : 0;
    else if (rm == 2u)
        inc = (!sign && any) ? 1 : 0;
    else if (rm == 3u)
        inc = (sign && any) ? 1 : 0;
    man = (man >> 3) + (unsigned)inc;
    if (!tiny && man >= (((uint64_t)2) << p->mb)) {
        man >>= 1;
        E++;
    }
    if (any)
        fp_raise(s, FP_E_I);
    if (tiny && any)
        fp_raise(s, FP_E_U);
    if (E > emax) {
        /* Overflow is always inexact (result not representable). */
        uint64_t ebits = (((uint64_t)1 << p->eb) - 1u) << p->mb;
        fp_raise(s, FP_E_O);
        fp_raise(s, FP_E_I);
        if (rm == 1u || (rm == 2u && sign) || (rm == 3u && !sign))
            return (((uint64_t)(sign & 1)) << (p->mb + p->eb)) | ebits |
                   ((((uint64_t)1) << p->mb) - 1u);
        return (((uint64_t)(sign & 1)) << (p->mb + p->eb)) | ebits;
    }
    if (tiny && man < (((uint64_t)1) << p->mb))
        return (((uint64_t)(sign & 1)) << (p->mb + p->eb)) |
               (man & ((((uint64_t)1) << p->mb) - 1u));
    return (((uint64_t)(sign & 1)) << (p->mb + p->eb)) |
           (((uint64_t)(uint32_t)(E + p->bias)) << p->mb) |
           (man & ((((uint64_t)1) << p->mb) - 1u));
}

/* ADD/SUB core (sub flips b; NaN operands pass through by fp_nan2). */
static uint64_t fp_addsub(struct fp_st *s, unsigned f, uint64_t aw,
                          uint64_t bw, int sub)
{
    const struct fp_fmt *p = &fp_ff[f];
    int n8 = s->ctx->nan2008;
    fpv_t a = fp_unpack(f, aw, n8), b = fp_unpack(f, bw, n8);
    uint64_t out, m1, m2, sbit = (uint64_t)1 << (p->mb + p->eb);
    int32_t e1, e2, d;
    int s1, s2, sticky = 0;

    if (fp_nan2(s, f, &a, &b, &out))
        return out;
    if (sub)
        b.sign ^= 1;
    if (a.cls == FP_INF || b.cls == FP_INF) {
        if (a.cls == FP_INF && b.cls == FP_INF && a.sign != b.sign) {
            fp_raise(s, FP_E_V);
            return fp_default_nan(f, n8);
        }
        return ((uint64_t)((a.cls == FP_INF ? a.sign : b.sign) & 1) <<
                (p->mb + p->eb)) | ((((uint64_t)1 << p->eb) - 1u) << p->mb);
    }
    if (a.cls == FP_ZERO && b.cls == FP_ZERO) {
        int z = (a.sign == b.sign) ? a.sign : ((s->ctx->fcsr & 0x3u) == 3u);
        return ((uint64_t)(z & 1)) << (p->mb + p->eb);
    }
    if (a.cls == FP_ZERO) /* SUB already flipped b.sign; rebuild it. */
        return (b.raw & ~sbit) | (((uint64_t)(b.sign & 1)) << (p->mb + p->eb));
    if (b.cls == FP_ZERO)
        return a.raw;
    m1 = fp_full(f, &a);
    e1 = a.exp;
    m2 = fp_full(f, &b);
    e2 = b.exp;
    s1 = a.sign;
    s2 = b.sign;
    if (e1 < e2)
        fp_swap(&m1, &e1, &s1, &m2, &e2, &s2);
    fp_norm(f, &m1, &e1);
    fp_norm(f, &m2, &e2);
    if (e1 < e2)
        fp_swap(&m1, &e1, &s1, &m2, &e2, &s2);
    d = e1 - e2;
    if (d >= 64) {
        sticky |= (m2 != 0u);
        m2 = 0u;
    } else if (d != 0) {
        sticky |= ((m2 & ((((uint64_t)1) << d) - 1u)) != 0u);
        m2 >>= d;
    }
    m1 <<= 3;
    m2 <<= 3;
    if (s1 == s2) {
        m1 += m2;
    } else if (m1 >= m2) {
        m1 -= m2;
    } else {
        m1 = m2 - m1;
        s1 ^= 1;
    }
    if (m1 == 0u) {
        int z = ((s->ctx->fcsr & 0x3u) == 3u);
        return ((uint64_t)(z & 1)) << (p->mb + p->eb);
    }
    return fp_round_pack(s, f, s1, e1, m1, sticky);
}

/* MUL core. */
static uint64_t fp_mul(struct fp_st *s, unsigned f, uint64_t aw, uint64_t bw)
{
    const struct fp_fmt *p = &fp_ff[f];
    int n8 = s->ctx->nan2008;
    fpv_t a = fp_unpack(f, aw, n8), b = fp_unpack(f, bw, n8);
    uint64_t out, m1, m2;
    int32_t e1, e2;
    int sign = (a.sign ^ b.sign) & 1;

    if (fp_nan2(s, f, &a, &b, &out))
        return out;
    if ((a.cls == FP_INF && b.cls == FP_ZERO) ||
        (b.cls == FP_INF && a.cls == FP_ZERO)) {
        fp_raise(s, FP_E_V);
        return fp_default_nan(f, n8);
    }
    if (a.cls == FP_INF || b.cls == FP_INF)
        return (((uint64_t)sign) << (p->mb + p->eb)) |
               ((((uint64_t)1 << p->eb) - 1u) << p->mb);
    if (a.cls == FP_ZERO || b.cls == FP_ZERO)
        return ((uint64_t)sign) << (p->mb + p->eb);
    m1 = fp_full(f, &a);
    e1 = a.exp;
    m2 = fp_full(f, &b);
    e2 = b.exp;
    fp_norm(f, &m1, &e1);
    fp_norm(f, &m2, &e2);
    if (f == 0u) {
        uint64_t pr = m1 * m2;
        int sh = ((pr >> 47) != 0u ? 47 : 46) - (int)p->mb - 3;
        int stk = ((pr & ((((uint64_t)1) << sh) - 1u)) != 0u);
        return fp_round_pack(s, f, sign, e1 + e2 - (int32_t)p->mb + sh + 3,
                             pr >> sh, stk);
    }
    {
        uint64_t hi, lo, man;
        int sh, stk;
        fp_mul53(m1, m2, &hi, &lo);
        sh = ((hi & ((uint64_t)1 << 41)) != 0u ? 105 : 104) - (int)p->mb - 3;
        stk = ((lo & ((((uint64_t)1) << sh) - 1u)) != 0u);
        man = (lo >> sh) | (hi << (64 - sh));
        return fp_round_pack(s, f, sign, e1 + e2 - (int32_t)p->mb + sh + 3,
                             man, stk);
    }
}

/* DIV core: restoring division with K = MB+6 fraction bits; the final
 * remainder decides sticky (further quotient bits exist iff r != 0). */
static uint64_t fp_div(struct fp_st *s, unsigned f, uint64_t aw, uint64_t bw)
{
    const struct fp_fmt *p = &fp_ff[f];
    int n8 = s->ctx->nan2008;
    fpv_t a = fp_unpack(f, aw, n8), b = fp_unpack(f, bw, n8);
    uint64_t out, m1, m2, q = 0u, r = 0u;
    int32_t e1, e2, t;
    unsigned i, n = 2u * p->mb + 7u;
    int sign = (a.sign ^ b.sign) & 1, stk, sh;

    if (fp_nan2(s, f, &a, &b, &out))
        return out;
    if ((a.cls == FP_INF && b.cls == FP_INF) ||
        (a.cls == FP_ZERO && b.cls == FP_ZERO)) {
        fp_raise(s, FP_E_V);
        return fp_default_nan(f, n8);
    }
    if (a.cls == FP_INF || b.cls == FP_ZERO) {
        if (b.cls == FP_ZERO)
            fp_raise(s, FP_E_Z);
        return (((uint64_t)sign) << (p->mb + p->eb)) |
               ((((uint64_t)1 << p->eb) - 1u) << p->mb);
    }
    if (b.cls == FP_INF || a.cls == FP_ZERO)
        return ((uint64_t)sign) << (p->mb + p->eb);
    m1 = fp_full(f, &a);
    e1 = a.exp;
    m2 = fp_full(f, &b);
    e2 = b.exp;
    fp_norm(f, &m1, &e1);
    fp_norm(f, &m2, &e2);
    for (i = 0u; i < n; i++) {
        r = (r << 1) | ((i <= p->mb) ? ((m1 >> (p->mb - i)) & 1u) : 0u);
        if (r >= m2) {
            r -= m2;
            q = (q << 1) | 1u;
        } else {
            q <<= 1;
        }
    }
    stk = (r != 0u);
    t = 63;
    while (t > 0 && ((q >> t) & 1u) == 0u)
        t--;
    sh = t - (int32_t)p->mb - 3;
    stk |= ((q & ((((uint64_t)1) << sh) - 1u)) != 0u);
    return fp_round_pack(s, f, sign, (e1 - e2) + sh - 3, q >> sh, stk);
}

/* Integer square root: MB+4 root bits from radicand m, MSB first. */
static uint64_t fp_isqrt(unsigned f, uint64_t m, int *sticky)
{
    unsigned total = fp_ff[f].mb + 4u, bl = 0u, i, pairs, sh;
    uint64_t q = m, r = 0u, rem = 0u, pair, t;
    while (q != 0u) {
        bl++;
        q >>= 1;
    }
    pairs = (bl + 1u) / 2u;
    for (i = 0u; i < total; i++) {
        pair = 0u;
        if (i < pairs) {
            sh = 2u * (pairs - 1u - i);
            pair = (sh >= 64u) ? 0u : ((m >> sh) & 3u);
        }
        rem = (rem << 2) | pair;
        t = (r << 2) | 1u;
        r <<= 1;
        if (rem >= t) {
            rem -= t;
            r |= 1u;
        }
    }
    *sticky = (rem != 0u);
    return r;
}

/* SQRT core. */
static uint64_t fp_sqrt(struct fp_st *s, unsigned f, uint64_t aw)
{
    int n8 = s->ctx->nan2008;
    fpv_t a = fp_unpack(f, aw, n8);
    uint64_t m, q, r;
    int32_t e, k, extra = 0;
    unsigned bl = 0u;
    int stk;

    if (a.cls == FP_NAN) {
        uint64_t out;
        fpv_t z = a;
        z.cls = FP_ZERO;
        if (fp_nan2(s, f, &a, &z, &out))
            return out;
    }
    if (a.cls == FP_INF) {
        if (a.sign) {
            fp_raise(s, FP_E_V);
            return fp_default_nan(f, n8);
        }
        return a.raw;
    }
    if (a.cls == FP_ZERO)
        return a.raw;
    if (a.sign) {
        fp_raise(s, FP_E_V);
        return fp_default_nan(f, n8);
    }
    m = fp_full(f, &a);
    e = a.exp;
    fp_norm(f, &m, &e);
    k = e - (int32_t)fp_ff[f].mb;
    if ((k & 1) != 0) {
        m <<= 1;
        k--;
    }
    q = m;
    while (q != 0u) {
        bl++;
        q >>= 1;
    }
    extra = (int)(fp_ff[f].mb + 4u) - (int)((bl + 1u) / 2u);
    r = fp_isqrt(f, m, &stk);
    return fp_round_pack(s, f, 0, k / 2 - extra + (int32_t)fp_ff[f].mb + 3,
                         r, stk);
}

/* C.cond comparison. cond bits: bit2 less, bit1 equal, bit0 unordered;
 * bit3 signals Invalid on quiet NaNs too. sNaN always raises Invalid.
 * With the trap disabled an Invalid comparison yields FCC=false. */
static int fp_compare(struct fp_st *s, unsigned f, uint64_t aw, uint64_t bw,
                      unsigned cond, unsigned cc)
{
    int n8 = s->ctx->nan2008;
    fpv_t a = fp_unpack(f, aw, n8), b = fp_unpack(f, bw, n8);
    int less = 0, equal = 0, unord = 0, invalid = 0, res;
    uint32_t mask = fp_fcc_mask(cc);

    if (a.cls == FP_NAN || b.cls == FP_NAN) {
        unord = 1;
        if ((a.cls == FP_NAN && a.qnan == 0) ||
            (b.cls == FP_NAN && b.qnan == 0) || (cond & 8u))
            invalid = 1;
    } else if (a.cls == FP_ZERO && b.cls == FP_ZERO) {
        equal = 1;
    } else if (a.sign != b.sign) {
        less = a.sign;
    } else if (a.cls == FP_INF || b.cls == FP_INF) {
        if (a.cls == b.cls)
            equal = 1;
        else
            less = (a.cls == FP_INF) ? a.sign : !b.sign;
    } else {
        uint64_t ma = fp_full(f, &a), mb = fp_full(f, &b);
        int c = (a.exp != b.exp) ? ((a.exp < b.exp) ? -1 : 1) :
                (ma == mb ? 0 : ((ma < mb) ? -1 : 1));
        if (c == 0)
            equal = 1;
        else
            less = a.sign ? (c > 0) : (c < 0);
    }
    if (invalid) {
        fp_raise(s, FP_E_V);
        res = 0;
    } else if (unord) {
        res = (cond & 1u) != 0u;
    } else {
        res = ((less && (cond & 4u)) || (equal && (cond & 2u))) != 0;
    }
    if (fp_commit(s) != 0)
        return MIPS_FAULT;
    if (res)
        s->ctx->fcsr |= mask;
    else
        s->ctx->fcsr &= ~mask;
    return 0;
}

/* Float -> int (CVT.W/CVT.L, ROUND/TRUNC/CEIL/FLOOR). nbits 32/64;
 * forced_rm < 0 selects FCSR RM; no_inexact suppresses the I flag for
 * the ROUND family. Out-of-range/NaN/Inf raise Invalid with 0x7FFF...
 * Returns 1 on Invalid with *out set, else 0. */
static int fp_to_int(struct fp_st *s, unsigned f, uint64_t w, int nbits,
                     int forced_rm, int no_inexact, uint64_t *out)
{
    int n8 = s->ctx->nan2008;
    fpv_t a = fp_unpack(f, w, n8);
    uint64_t bad = (nbits == 64) ? 0x7FFFFFFFFFFFFFFFULL : 0x7FFFFFFFULL;
    uint64_t m, ip, lim;
    int32_t e, r;
    int neg, rm = (forced_rm < 0) ? (int)(s->ctx->fcsr & 0x3u) : forced_rm;
    int dropped = 0, inc = 0;

    if (a.cls == FP_NAN || a.cls == FP_INF) {
        fp_raise(s, FP_E_V);
        *out = bad;
        return 1;
    }
    if (a.cls == FP_ZERO) {
        *out = 0u;
        return 0;
    }
    neg = a.sign;
    m = fp_full(f, &a);
    e = a.exp;
    fp_norm(f, &m, &e);
    if (e == nbits - 1 && neg && m == ((uint64_t)1 << fp_ff[f].mb)) {
        *out = (uint64_t)1 << (nbits - 1);
        return 0; /* exact INT_MIN/LONG_MIN: no flags. */
    }
    if (e >= nbits - 1) {
        fp_raise(s, FP_E_V);
        *out = bad;
        return 1;
    }
    r = (int32_t)fp_ff[f].mb - e;
    if (r >= 64) {
        ip = 0u;
        dropped = (m != 0u);
    } else if (r > 0) {
        dropped = ((m & ((((uint64_t)1) << r) - 1u)) != 0u);
        ip = m >> r;
    } else {
        ip = m << (-r);
    }
    if (dropped) {
        if (rm == 0 && r > 0 && r < 64) {
            uint64_t lo = m & ((((uint64_t)1) << r) - 1u);
            uint64_t half = (uint64_t)1 << (r - 1);
            inc = (lo > half || (lo == half && (ip & 1u))) ? 1 : 0;
        } else if (rm == 2) {
            inc = !neg;
        } else if (rm == 3) {
            inc = neg;
        }
        ip += (uint64_t)inc;
        if (!no_inexact)
            fp_raise(s, FP_E_I);
    }
    lim = ((uint64_t)1) << (nbits - 1);
    if ((!neg && ip > lim - 1u) || (neg && ip > lim)) {
        fp_raise(s, FP_E_V);
        *out = bad;
        return 1;
    }
    ip &= (nbits == 64) ? ~0ULL : 0xFFFFFFFFULL;
    *out = neg ? (0u - ip) : ip;
    return 0;
}

/* Int -> float (CVT.S/CVT.D from W/L): exact when it fits, else rounded. */
static uint64_t fp_from_int(struct fp_st *s, unsigned f, int neg, uint64_t mag)
{
    const struct fp_fmt *p = &fp_ff[f];
    /* E tracks the true unbiased exponent for a mantissa normalized
     * with the hidden bit at mb+3 (24/55 incl. 3 GRS bits below it). */
    int32_t E = (int32_t)p->mb + 3;
    int sticky = 0;
    if (mag == 0u)
        return 0u;
    while (mag >= ((uint64_t)4 << (p->mb + 2u))) {
        sticky |= (int)(mag & 1u);
        mag >>= 1;
        E++;
    }
    while (mag < ((uint64_t)1 << (p->mb + 3u))) {
        mag <<= 1;
        E--;
    }
    return fp_round_pack(s, f, neg, E, mag, sticky);
}

/* CVT.D.S / CVT.S.D. NaN payloads keep the HIGH bits (low-bit
 * truncation would alias the mode defaults: D legacy default
 * 0x7ff7ffffffffffff must narrow to 0x7fbfffff). A narrowing that
 * empties the payload keeps bit 0 so the result stays a NaN. */
static uint64_t fp_cvt_fmt(struct fp_st *s, unsigned df, uint64_t w)
{
    int n8 = s->ctx->nan2008;
    fpv_t a = fp_unpack(df ^ 1u, w, n8);

    if (a.cls == FP_NAN) {
        uint64_t frac = (df == 1u) ? (a.frac << 29) : (a.frac >> 29);
        uint64_t out;
        if (a.qnan == 0)
            fp_raise(s, FP_E_V);
        if (df == 0u && frac == 0u)
            frac = 1u;
        out = (((uint64_t)(a.sign & 1)) << (fp_ff[df].mb + fp_ff[df].eb)) |
              ((((uint64_t)1 << fp_ff[df].eb) - 1u) << fp_ff[df].mb) | frac;
        return (a.qnan == 0) ? fp_quiet(df, out, n8) : out;
    }
    if (a.cls == FP_INF || a.cls == FP_ZERO) {
        uint64_t m = (a.cls == FP_ZERO) ? 0u :
                     ((((uint64_t)1 << fp_ff[df].eb) - 1u) << fp_ff[df].mb);
        return (((uint64_t)(a.sign & 1)) << (fp_ff[df].mb + fp_ff[df].eb)) | m;
    }
    if (df == 1u) { /* widening: exact (hidden bit 23 -> 55). */
        uint64_t m = fp_full(0u, &a);
        int32_t E = a.exp;
        fp_norm(0u, &m, &E);
        return fp_round_pack(s, df, a.sign, E, m << 32, 0);
    } /* narrowing: hidden + 23 + GRS bits, sticky the rest. */
    {
        uint64_t m = fp_full(1u, &a);
        int32_t E = a.exp;
        int stk;
        fp_norm(1u, &m, &E);
        stk = ((m & ((((uint64_t)1) << 26) - 1u)) != 0u);
        return fp_round_pack(s, df, a.sign, E, m >> 26, stk);
    }
}

/* FR=0 requires even registers for 64-bit (D/L) operands. */
static int fp_even(mips32_ctx_t *ctx, uint32_t pc, unsigned r)
{
    if (ctx->fr_mode == 0u && (r & 1u) != 0u) {
        mips_trap(ctx, 4, pc); /* Reserved: odd 64-bit lane in FR=0. */
        return MIPS_FAULT;
    }
    return 0;
}

/* S/D-format instruction dispatch (rs field 16/17, f = 0/1). */
static int fp_fmt_sd(mips32_ctx_t *ctx, uint32_t pc, const mips_dec_t *d,
                     unsigned f)
{
    unsigned func = d->funct, fs = d->rd, ft = d->rt, fd = d->sa;
    struct fp_st s = { ctx, pc, 0u, 0u, 0 };
    uint64_t v;

    if (func >= 48u) { /* compares: fd holds cc, no even check on it. */
        if (f != 0u && (fp_even(ctx, pc, fs) != 0 || fp_even(ctx, pc, ft) != 0))
            return MIPS_FAULT;
        return fp_compare(&s, f, ctx->fpr[fs], ctx->fpr[ft],
                          func & 15u, d->sa >> 2);
    }
    if (f != 0u && (fp_even(ctx, pc, fs) != 0 ||
        (func <= 3u && fp_even(ctx, pc, ft) != 0) ||
        ((func <= 11u || func == 33u || func == 37u) &&
         fp_even(ctx, pc, fd) != 0)))
        return MIPS_FAULT;
    switch (func) {
    case 0u: v = fp_addsub(&s, f, ctx->fpr[fs], ctx->fpr[ft], 0); break;
    case 1u: v = fp_addsub(&s, f, ctx->fpr[fs], ctx->fpr[ft], 1); break;
    case 2u: v = fp_mul(&s, f, ctx->fpr[fs], ctx->fpr[ft]); break;
    case 3u: v = fp_div(&s, f, ctx->fpr[fs], ctx->fpr[ft]); break;
    case 4u: v = fp_sqrt(&s, f, ctx->fpr[fs]); break;
    case 5u: /* ABS/NEG/MOV: no FCSR update, bypass commit. */
        if (f == 0u) ctx->fpr[fd] = (ctx->fpr[fd] & 0xFFFFFFFF00000000ULL) | ((uint32_t)ctx->fpr[fs] & 0x7FFFFFFFu);
        else ctx->fpr[fd] = ctx->fpr[fs] & 0x7FFFFFFFFFFFFFFFULL;
        return 0;
    case 6u:
        if (f == 0u) ctx->fpr[fd] = (ctx->fpr[fd] & 0xFFFFFFFF00000000ULL) | (uint32_t)ctx->fpr[fs];
        else ctx->fpr[fd] = ctx->fpr[fs];
        return 0;
    case 7u:
        if (f == 0u) ctx->fpr[fd] = (ctx->fpr[fd] & 0xFFFFFFFF00000000ULL) | ((uint32_t)ctx->fpr[fs] ^ 0x80000000u);
        else ctx->fpr[fd] = ctx->fpr[fs] ^ 0x8000000000000000ULL;
        return 0;
    case 8u: case 9u: case 10u: case 11u: /* ROUND/TRUNC/CEIL/FLOOR.L */
        if (fp_to_int(&s, f, ctx->fpr[fs], 64, (int)(func - 8u), 1, &v) != 0)
            v = 0x7FFFFFFFFFFFFFFFULL;
        return fp_write_d(&s, fd, v);
    case 12u: case 13u: case 14u: case 15u: /* ROUND/TRUNC/CEIL/FLOOR.W */
        if (fp_to_int(&s, f, ctx->fpr[fs], 32, (int)(func - 12u), 1, &v) != 0)
            v = 0x7FFFFFFFULL;
        return fp_write_s(&s, fd, (uint32_t)v);
    case 32u:
        if (f == 0u)
            break;
        return fp_write_s(&s, fd, (uint32_t)fp_cvt_fmt(&s, 0u, ctx->fpr[fs]));
    case 33u:
        if (f != 0u)
            break;
        return fp_write_d(&s, fd, fp_cvt_fmt(&s, 1u, ctx->fpr[fs]));
    case 36u:
        if (fp_to_int(&s, f, ctx->fpr[fs], 32, -1, 0, &v) != 0)
            v = 0x7FFFFFFFULL;
        return fp_write_s(&s, fd, (uint32_t)v);
    case 37u:
        if (fp_to_int(&s, f, ctx->fpr[fs], 64, -1, 0, &v) != 0)
            v = 0x7FFFFFFFFFFFFFFFULL;
        return fp_write_d(&s, fd, v);
    default:
        mips_trap(ctx, 4, pc); /* Reserved S/D funct. */
        return MIPS_FAULT;
    }
    /* Arithmetic cases 0..4 break out with v set; shared format write. */
    if (f == 0u)
        return fp_write_s(&s, fd, (uint32_t)v);
    return fp_write_d(&s, fd, v);
}

/* W/L-format (integer source) CVT.S/CVT.D dispatch (rs field 20/21). */
static int fp_fmt_wl(mips32_ctx_t *ctx, uint32_t pc, const mips_dec_t *d,
                     unsigned src64)
{
    unsigned func = d->funct, fs = d->rd, fd = d->sa;
    struct fp_st s = { ctx, pc, 0u, 0u, 0 };
    int64_t v;
    int neg;
    uint64_t mag, r;

    if ((func != 32u && func != 33u) || (ctx->fr_mode == 0u &&
        ((src64 && (fs & 1u)) || (func == 33u && (fd & 1u))))) {
        mips_trap(ctx, 4, pc); /* Reserved W/L funct or FR=0 lane. */
        return MIPS_FAULT;
    }
    v = src64 ? (int64_t)ctx->fpr[fs] : (int64_t)(int32_t)ctx->fpr[fs];
    neg = (v < 0) ? 1 : 0;
    mag = neg ? (0u - (uint64_t)v) : (uint64_t)v;
    r = fp_from_int(&s, func - 32u, neg, mag);
    return (func == 32u) ? fp_write_s(&s, fd, (uint32_t)r) :
                           fp_write_d(&s, fd, r);
}

/* BC1F/BC1T/BC1FL/BC1TL (rs field 8): rt holds cc (bits 20:18), nd
 * (bit 17), tf (bit 16). Likely-not-taken annuls the delay slot with
 * no fetch (SPEC 2.2 page-end rule); otherwise the slot runs once via
 * interp_step with in_delay_slot set, and a slot-internal branch wins. */
static int fp_bc1(mips32_ctx_t *ctx, uint32_t pc, const mips_dec_t *d)
{
    unsigned cc = (d->rt >> 2) & 7u;
    int taken = (((ctx->fcsr & fp_fcc_mask(cc)) != 0) == ((d->rt & 1u) != 0));
    uint32_t target = pc + 4u + (uint32_t)(d->simm * 4);
    mips_dec_t sl;
    uint32_t w;
    int slot_ctrl, rc;

    if (((d->rt >> 1) & 1) != 0 && !taken) {
        ctx->pc = pc + 8u;
        ctx->next_pc = pc + 12u;
        return 2;
    }
    if (mips_fetch(ctx, pc + 4u, &w) != 0) {
        if (ctx->exit_reason == MIPS32_EXIT_NONE)
            mips_fault(ctx, pc + 4u);
        return MIPS_FAULT;
    }
    mips_decode(w, &sl);
    slot_ctrl = interp_is_control(&sl);
    ctx->in_delay_slot = 1;
    ctx->pc = pc + 4u;
    ctx->next_pc = pc + 8u;
    rc = interp_step(ctx);
    if (rc == MIPS_FAULT) {
        ctx->pc = pc;
        ctx->next_pc = pc + 4u;
        return MIPS_FAULT;
    }
    if (rc == 1)
        return 1;
    ctx->in_delay_slot = 0;
    if (slot_ctrl)
        return 2;
    ctx->pc = taken ? target : pc + 8u;
    ctx->next_pc = ctx->pc + 4u;
    return 2;
}

int fp_exec(mips32_ctx_t *ctx, uint32_t pc, const mips_dec_t *d)
{
    if (d->op == 0x13u && ((d->funct & 0x26u) == 0x20u)) {
        unsigned f = d->funct & 1u, fr = d->rs, ft = d->rt, fs = d->rd, fd = d->sa;
        struct fp_st s = { ctx, pc, 0u, 0u, 0 };
        uint64_t v;
        if (f != 0u && (fp_even(ctx, pc, fr) || fp_even(ctx, pc, ft) || fp_even(ctx, pc, fs) || fp_even(ctx, pc, fd)))
            return MIPS_FAULT;
        v = fp_addsub(&s, f, fp_mul(&s, f, ctx->fpr[fs], ctx->fpr[ft]), ctx->fpr[fr], (int)((d->funct >> 3) & 1u));
        if ((d->funct & 0x10u) != 0u && fp_unpack(f, v, ctx->nan2008).cls != FP_NAN)
            v ^= (f == 0u) ? 0x80000000ULL : 0x8000000000000000ULL;
        return (f == 0u) ? fp_write_s(&s, fd, (uint32_t)v) : fp_write_d(&s, fd, v);
    }
    if (d->op != 0x11u) {
        mips_trap(ctx, 4, pc); /* Reserved COP1-adjacent encoding. */
        return MIPS_FAULT;
    }
    switch (d->rs) {
    case 0x08u:
        return fp_bc1(ctx, pc, d);
    case 0x03u: /* MFHC1: high 32 bits, FR-agnostic flat lane (E03). */
        interp_set_reg(ctx, d->rt, (uint32_t)(ctx->fpr[d->rd] >> 32));
        return 0;
    case 0x07u: /* MTHC1: high 32 bits, low half preserved. */
        ctx->fpr[d->rd] = (ctx->fpr[d->rd] & 0xFFFFFFFFULL) |
                          (((uint64_t)ctx->gpr[d->rt]) << 32);
        return 0;
    case 0x10u:
        return fp_fmt_sd(ctx, pc, d, 0u);
    case 0x11u:
        return fp_fmt_sd(ctx, pc, d, 1u);
    case 0x14u:
        return fp_fmt_wl(ctx, pc, d, 0u);
    case 0x15u:
        return fp_fmt_wl(ctx, pc, d, 1u);
    default:
        break;
    }
    /* MFC1/MTC1/CFC1/CTC1 are claimed by fpmove_cop1; DMFC1/DMTC1 have
     * no 64-bit GPRs on MIPS32 and PS is unimplemented: SIGILL. */
    mips_trap(ctx, 4, pc);
    return MIPS_FAULT;
}
