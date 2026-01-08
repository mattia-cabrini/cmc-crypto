#ifndef CMC_CRYPTO_BIGINT_H_INCLUDED
#define CMC_CRYPTO_BIGINT_H_INCLUDED

#include "types.h"

#ifndef BIGINT_MAX
#define BIGINT_MAX 512
#endif

typedef struct bigint_t
{
    byte num[2 * BIGINT_MAX]; /* Big integer represented in base 256 */
    int  overflow;            /* Overflow happened during last op. */
    int  max_exp;    /* Most significant non-zero digit [0, 2*BIGINT_MAX) */
    int  max_digit2; /* Most significant non-zero bit [0,8*2*BIGINT_MAX) */
}* bigint_p;

typedef struct sbigint_t
{
    struct bigint_t N;
    int             sign; /* >0, <0 or ==0 */
}* sbigint_p;

/* In all functins DST and N can overlap, but DST and M cannot, unless
 * differently stated in docs. Parameters that do not overlap with DST will
 * remain constants.
 * */

/* BIGINT INTERFACE */

extern void bigint_init(bigint_p N);
extern void bigint_init_by_int(bigint_p N, int n);
extern void bigint_copy(bigint_p N, bigint_p M);
extern int  bigint_iszero(bigint_p N);
extern int  bigint_iseven(bigint_p N);
extern void bigint_sum(bigint_p DST, bigint_p N, bigint_p M);

/* Overlap is ok in these cases:
 * - no overlap at all;
 * - DST overlaps with N, but not with M;
 * - DST overlaps with M, but not witn N.
 */
extern void bigint_sub(bigint_p DST, bigint_p N, bigint_p M);
extern void bigint_mul(bigint_p DST, bigint_p N, bigint_p M);
extern void bigint_square(bigint_p DST, bigint_p N);

/* M must be != 0 (no check) */
extern void bigint_mod(bigint_p DST, bigint_p N, bigint_p M);
extern void bigint_compl(bigint_p DST, bigint_p N);

/* U.B. if N or M overflew */
extern int bigint_cmp(bigint_p N, bigint_p M);

extern void bigint_setbit(bigint_p N, int weight, int bit);
extern int  bigint_getbit(bigint_p N, int weight);

/* n must be >= 0; otherwise DST would overlfow */
extern void bigint_shiftl(bigint_p DST, bigint_p N, int n);

/* n must be >= 0; otherwise DST would overlfow */
extern void bigint_shiftr(bigint_p DST, bigint_p N, int n);

extern int  bigint_how_many_1bits(bigint_p N);
extern void bigint_set_internal(bigint_p N);

/* M must be != 0 (no check) */
extern void bigint_quotient(bigint_p DST, bigint_p N, bigint_p M);

/* DST (out) -> Greatest common divisor;
 * T   (out) -> t coefficient;
 * N   (in)  -> Operand 1;
 * M   (in)  -> Operand 2.
 * Coefficient S is not coputed.
 *
 * WARNING
 * N and M must be > 0 (no check).
 * */
extern void bigint_eec(bigint_p DST, bigint_p T, bigint_p N, bigint_p M);

extern void bigint_exp_mod(bigint_p DST, bigint_p N, bigint_p E, bigint_p M);

/* SBIGINT INTERFACE */
extern void sbigint_init(sbigint_p N);
extern void sbigint_init_by_int(sbigint_p N, int n);
extern void sbigint_init_by_bigint(sbigint_p N, bigint_p M);
extern void sbigint_copy(sbigint_p N, sbigint_p M);
extern void sbigint_sum(sbigint_p DST, sbigint_p N, sbigint_p M);
extern void sbigint_sub(sbigint_p DST, sbigint_p N, sbigint_p M);
extern void sbigint_mul(sbigint_p DST, sbigint_p N, sbigint_p M);

#endif /* CMC_CRYPTO_BIGINT_H_INCLUDED */
