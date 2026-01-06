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

/* In all functins DST and N can overlap, but DST and M cannot.
 * If DST and N overlap, N is of course modified.
 * M will remain constant.
 * */

extern void bigint_init(bigint_p N);
extern void bigint_init_by_int(bigint_p N, int n);
extern void bigint_sum(bigint_p DST, bigint_p N, bigint_p M);
extern void bigint_sub(bigint_p DST, bigint_p N, bigint_p M);
extern void bigint_mul(bigint_p DST, bigint_p N, bigint_p M);

/* M must be != 0 (no check) */
extern void bigint_mod(bigint_p DST, bigint_p N, bigint_p M);
extern void bigint_compl(bigint_p DST, bigint_p N);

/* U.B. if N or M overflew */
extern int bigint_cmp(bigint_p N, bigint_p M);

extern void bigint_setbit(bigint_p N, int weight, int bit);
extern int  bigint_getbit(bigint_p N, int weight);

/* n must be >= 0; otherwise DST would overlfow */
extern void bigint_shift(bigint_p DST, bigint_p N, int n);

extern int  bigint_how_many_1bits(bigint_p N);
extern void bigint_set_internal(bigint_p N);

/* M must be != 0 (no check) */
extern void bigint_quotient(bigint_p DST, bigint_p N, bigint_p M);

#endif /* CMC_CRYPTO_BIGINT_H_INCLUDED */
