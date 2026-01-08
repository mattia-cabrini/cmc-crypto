#include <string.h>

#include "bigint.h"
#include "error.h"

static int CACHE_1BITS_IN_BYTE[] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};

/* --- HELPERS --- */
int max(int, int);
int max(int a, int b) { return a > b ? a : b; }
/* --- END HELPERS --- */

/* --- BIGINT IMPL --- */

void bigint_init(bigint_p N) { memset(N, 0, sizeof(struct bigint_t)); }

void bigint_init_by_int(bigint_p N, int n)
{
    int i;

    bigint_init(N);

    for (i = 0; i < 4; ++i)
    {
        N->num[i] = (byte)(n % 256);
        n /= 256;
    }

    bigint_set_internal(N);
}

void bigint_copy(bigint_p DST, bigint_p N)
{
    memcpy(DST, N, sizeof(struct bigint_t));
}

int bigint_iszero(bigint_p N)
{
    if (N->max_exp)
        return 0;

    if (N->max_digit2)
        return 0;

    return !N->num[0];
}

int bigint_iseven(bigint_p N) { return !(N->num[0] & 1); }

void bigint_sum(bigint_p DST, bigint_p N, bigint_p M)
{
    int i;
    int dS; /* Result digit */
    int dN; /* Digit of N */
    int dM; /* Digit og N */

    DST->overflow = N->overflow || M->overflow;
    if (DST->overflow)
        return;

    for (i = 0; i < 2 * BIGINT_MAX; ++i)
    {
        dN = N->num[i];
        dM = M->num[i];

        dS = DST->overflow;
        dS = dS + dN + dM;

        if (dS > 255)
        {
            DST->num[i]   = (byte)(dS - 256);
            DST->overflow = 1;
        }
        else
        {
            DST->num[i]   = (byte)dS;
            DST->overflow = 0;
        }
    }

    bigint_set_internal(DST);
}

void bigint_sub(bigint_p DST, bigint_p N, bigint_p M)
{
    struct bigint_t complM;
    struct bigint_t one;

    DST->overflow = N->overflow || M->overflow;
    if (DST->overflow)
        return;

    bigint_compl(&complM, M);           /* complM = ~M */
    bigint_init_by_int(&one, 1);        /* sum = 1 */
    bigint_sum(&complM, &complM, &one); /* compl = ~M + 1 (compl. 2) */
    complM.overflow = 0;                /* Overflow is not an error */

    bigint_sum(DST, N, &complM); /* Subtraction using compl. 2 */
    DST->overflow = 0;           /* Overflow is not an error */
}

void bigint_mul(bigint_p DST, bigint_p N, bigint_p M)
{
    int      hm1N;        /* How many 1-value bits there are in N */
    int      hm1M;        /*                                    M */
    bigint_p tmp = NULL;  /* Used to swap */
    int      i;           /* iterator */
    int      done_shifts; /* Number of shifts already done */

    /* ADDEE */
    struct bigint_t ADDEE;
    struct bigint_t PROD;

    DST->overflow = N->overflow || M->overflow;
    if (DST->overflow)
        return;

    hm1N = bigint_how_many_1bits(N);
    hm1M = bigint_how_many_1bits(M);

    if (hm1N > hm1M)
    {
        tmp = N;
        N   = M;
        M   = tmp;
    }

    /* Now N has got the smallest amount of 1 bits.
     * N will be used to shift M and in order to find addees */

    bigint_init(&PROD);
    bigint_copy(&ADDEE, M);
    done_shifts = 0;

    for (i = 0; i < 8 * 2 * BIGINT_MAX; ++i)
    {
        if (bigint_getbit(N, i) == 0)
            continue;

        /* ADDEE <- M << i
         * Shift M by i; since ADDEE is M shifted by done_shifts, it is
         * sufficiend to shift it by i - done_shifts */
        bigint_shiftl(&ADDEE, &ADDEE, i - done_shifts);
        done_shifts = i;

        /* PROD <- PROD + ADDEE */
        bigint_sum(&PROD, &PROD, &ADDEE);
    }

    bigint_copy(DST, &PROD);
}

void bigint_square(bigint_p DST, bigint_p N)
{
    struct bigint_t M;

    bigint_copy(&M, N);
    bigint_mul(DST, N, &M);
}

void bigint_mod(bigint_p DST, bigint_p N, bigint_p M)
{
    struct bigint_t tmpM;

    DST->overflow = N->overflow || M->overflow;
    if (DST->overflow)
        return;

    bigint_copy(DST, N);

    while (bigint_cmp(DST, M) >= 0)
    {
        /* Increasing M magnitude. */
        /* If DST->max_digit2 is surely grater than or euqal to M->max_digit.
         * Shifting by 0 is not a problem, as M is less than DST. */
        bigint_shiftl(&tmpM, M, max(DST->max_digit2 - M->max_digit2 - 1, 0));

        while (bigint_cmp(DST, &tmpM) >= 0)
            bigint_sub(DST, DST, &tmpM);
    }
}

void bigint_compl(bigint_p DST, bigint_p N)
{
    int i;

    DST->overflow = N->overflow;
    if (DST->overflow)
        return;

    for (i = 0; i < 2 * BIGINT_MAX; ++i)
        DST->num[i] = (byte)~N->num[i];

    bigint_set_internal(DST);
}

int bigint_cmp(bigint_p N, bigint_p M)
{
    int i;
    int diff = 0;

    if (N->overflow || M->overflow)
        return 0;

    for (i = 2 * BIGINT_MAX - 1; i >= 0 && !diff; --i)
        diff = (int)N->num[i] - (int)M->num[i];

    return diff;
}

void bigint_setbit(bigint_p N, int weight, int bit)
{
    byte* p;
    int   byte_index = weight >> 3;
    int   bit_index  = weight & 7;

    if (N->overflow)
        return;

    if (weight >= 8 * 2 * BIGINT_MAX)
    {
        N->overflow = 1;
        return;
    }

    p = &N->num[byte_index];

    if (bit)
        *p = (byte)(*p | (1 << bit_index));
    else
        *p = (byte)(*p & ~(1 << bit_index));

    bigint_set_internal(N);
}

int bigint_getbit(bigint_p N, int weight)
{
    byte* p;
    int   byte_index = weight >> 3;
    int   bit_index  = weight & 7;

    if (N->overflow)
        return 0;

    p = &N->num[byte_index];

    return *p & (1 << bit_index);
}

void bigint_shiftl(bigint_p DST, bigint_p N, int n)
{
    int i;

    DST->overflow = N->overflow || n < 0;
    if (DST->overflow)
        return;

    bigint_copy(DST, N);

    if (n == 0)
        return;

    for (i = 8 * 2 * BIGINT_MAX - 1; i >= n; --i)
        bigint_setbit(DST, i, bigint_getbit(N, i - n));

    for (i = 0; i < n && i < 8 * 2 * BIGINT_MAX; ++i)
        bigint_setbit(DST, i, 0);

    bigint_set_internal(DST);
}

void bigint_shiftr(bigint_p DST, bigint_p N, int n)
{
    int i;

    DST->overflow = N->overflow || n < 0;
    if (DST->overflow)
        return;

    bigint_copy(DST, N);

    if (n == 0)
        return;

    for (i = 0; i < 8 * 2 * BIGINT_MAX - n; ++i)
        bigint_setbit(DST, i, bigint_getbit(N, i + n));

    for (i = 8 * 2 * BIGINT_MAX - n; i < 2 * 8 * BIGINT_MAX; ++i)
        bigint_setbit(DST, i, 0);

    bigint_set_internal(DST);
}

int bigint_how_many_1bits(bigint_p N)
{
    int i;
    int counter = 0;

    if (N->overflow)
        return -1;

    for (i = 0; i < 2 * BIGINT_MAX; ++i)
        counter += CACHE_1BITS_IN_BYTE[N->num[i]];

    return counter;
}

void bigint_set_internal(bigint_p N)
{
    int i;

    if (N->overflow)
        return;

    N->max_exp = 0;
    for (i = 2 * BIGINT_MAX - 1; i >= 0 && !N->max_exp; --i)
        if (N->num[i])
            N->max_exp = i;

    N->max_digit2 = 0;
    for (i = 7; i >= 0 && !N->max_digit2; --i)
        if (bigint_getbit(N, 8 * N->max_exp + i))
            N->max_digit2 = 8 * N->max_exp + i;
}

void bigint_quotient(bigint_p DST, bigint_p N, bigint_p M)
{
    struct bigint_t tmpM;
    struct bigint_t tmpMod;
    struct bigint_t w;

    DST->overflow = N->overflow || M->overflow;
    if (DST->overflow)
        return;

    bigint_copy(&tmpMod, N);
    bigint_init(DST);

    while (bigint_cmp(&tmpMod, M) >= 0)
    {
        /* Increasing M magnitude, see bigint_mod */
        bigint_init_by_int(&w, 1);
        bigint_shiftl(&tmpM, M, max(tmpMod.max_digit2 - M->max_digit2 - 1, 0));
        bigint_shiftl(&w, &w, max(tmpMod.max_digit2 - M->max_digit2 - 1, 0));

        while (bigint_cmp(&tmpMod, &tmpM) >= 0)
        {
            bigint_sub(&tmpMod, &tmpMod, &tmpM);
            bigint_sum(DST, DST, &w);
        }
    }
}

void bigint_eec(bigint_p DST, bigint_p T, bigint_p N, bigint_p M)
{
    struct bigint_t  r0;
    struct bigint_t  r1;
    struct sbigint_t q;
    struct sbigint_t t0; /* t coefficient t0, T will be t1 */
    struct sbigint_t t1;
    struct sbigint_t t2;
    struct sbigint_t TMP;
    int              flagNgtM; /* Flag that tells if N > M */

    /* r0 is the greatest number */
    flagNgtM = bigint_cmp(N, M) > 0;
    if (flagNgtM)
    {
        bigint_copy(&r0, N);
        bigint_copy(&r1, M);
    }
    else
    {
        bigint_copy(&r0, M);
        bigint_copy(&r1, N);
    }

    sbigint_init_by_int(&t0, 0);
    sbigint_init_by_int(&t1, 1);
    sbigint_init_by_int(&q, 1); /* Init.ed as 1, for it will always be >0 */

    while (!bigint_iszero(&r1))
    {
        bigint_quotient(&q.N, &r0, &r1);

        /* Computing reminder rem = r0 - q * r1 */
        bigint_mul(&TMP.N, &q.N, &r1);
        bigint_sub(DST, &r0, &TMP.N);
        bigint_copy(&r0, &r1);
        bigint_copy(&r1, DST);

        /* Computing t coefficient t[i+1] = t[i-1] - q * t[i] */
        sbigint_mul(&TMP, &q, &t1); /* q * t[i] */

        sbigint_sub(&t2, &t0, &TMP); /* t[i-1] - q * t[i] */

        sbigint_copy(&t0, &t1);
        sbigint_copy(&t1, &t2);
    }

    /* Normalize t0, that at this point may be <0 */
    while (t0.sign < 0)
    {
        sbigint_init_by_bigint(&t1, flagNgtM ? N : M);
        sbigint_sum(&t0, &t0, &t1);
    }

    bigint_copy(T, &t0.N);
    bigint_copy(DST, &r0);
}

void bigint_exp_mod(bigint_p DST, bigint_p N, bigint_p E, bigint_p M)
{
    struct bigint_t base;
    struct bigint_t e;
    struct bigint_t one;

    bigint_copy(&base, N);
    bigint_copy(&e, E);
    bigint_init_by_int(DST, 1);
    bigint_init_by_int(&one, 1);

    while (!bigint_iszero(&e))
    {
        if (bigint_iseven(&e))
        {
            bigint_square(&base, &base);
            bigint_shiftr(&e, &e, 1);
            bigint_mod(&base, &base, M);
        }
        else
        {
            bigint_mul(DST, DST, &base);
            bigint_mod(DST, DST, M);
            bigint_sub(&e, &e, &one);
        }
    }
}

/* --- SBIGING IMPL */
void sbigint_init(sbigint_p N)
{
    bigint_init(&N->N);
    N->sign = 0;
}

void sbigint_init_by_int(sbigint_p N, int n)
{
    bigint_init_by_int(&N->N, n);
    N->sign = n;
}

void sbigint_init_by_bigint(sbigint_p N, bigint_p M)
{
    bigint_copy(&N->N, M);
    N->sign = 1;
}

void sbigint_copy(sbigint_p N, sbigint_p M)
{
    memcpy(N, M, sizeof(struct sbigint_t));
}

void sbigint_sum(sbigint_p DST, sbigint_p N, sbigint_p M)
{
    M->sign *= -1;
    sbigint_sub(DST, N, M);
    M->sign *= -1;
}

void sbigint_sub(sbigint_p DST, sbigint_p N, sbigint_p M)
{
    int flagNgtM;
    int flagSignN;   /* true: >0, false: <0, U.B. ==0 */
    int flagSignM;   /* true: >0, false: <0, U.B. ==0 */
    int flagSignOUT; /* true: >0, false: <0, U.B. ==0 */
    int noOp = 0;

    if (M->sign == 0)
    {
        sbigint_copy(DST, N);
        return;
    }

    if (N->sign == 0)
    {
        sbigint_copy(DST, M);
        DST->sign *= -1;
        return;
    }

    /* Now surely N and M are not 0 */

    /*
     * |N| > |M|   signN   signM   signOUT   Calc.        E.G.      = OUT     #
     * true        + (8)   + (3)   +         |N| - |M|    8 -   3  = +(8-3)   1
     * true        + (8)   - (3)   +         |N| + |M|    8 - (-3) = +(8+3)   2
     * true        - (8)   + (3)   -         |N| - |M|   -8 +   3  = -(8-3)   1
     * true        - (8)   - (3)   -         |N| + |M|   -8 - (-3) = -(8+3)   2
     * false       + (3)   + (8)   -         |M| - |N|    3 -   8  = -(8-3)   3
     * false       + (3)   - (8)   +         |N| + |M|    3 - (-8) = +(8+3)   2
     * false       - (3)   + (8)   -         |M| - |N|   -3 -   8  = -(8-3)   3
     * false       - (3)   - (8)   +         |M| - |N|   -3 - (-8) = +(8-3)   3
     */

    /* State */
    flagNgtM  = bigint_cmp(&N->N, &M->N) > 0;
    flagSignN = N->sign > 0;
    flagSignM = M->sign > 0;

    /* Out */

    /* flagSignOUT = flagNgtM  &&  flagSignN && flagSignM  +   << Fact 1
     *               flagNgtM  &&  flagSignN && !flagSignM +   << Fact 1
     *               !flagNgtM &&  flagSignN && !flagSignM +   << Fact 2
     *               !flagNgtM && !flagSignN && !flagSignM     << Fact 2
     *
     *             =  flagNgtM && flagSignN +                  << Fact 1
     *               !flagNgtM && !flagSignM                   << Fact 2
     *
     *             = flagNgtM && flagSignN + !(flagNgtM + flagSignM)
     */
    flagSignOUT = (flagNgtM && flagSignN) || !(flagNgtM || flagSignM);

    /* #1: flagNgtM &&  flagSignN && flagSignM +
     *     flagNgtM && !flagSignN && flagSignM
     *
     *   : flagNgtM && flagSignM
     */
    if (flagNgtM && flagSignM)
        noOp = 1;

    /*
     * #2:  flagNgtM &&  flagSignN && !flagSignM +   << Fact 1
     *      flagNgtM && !flagSignN && !flagSignM +   << Fact 2
     *     !flagNgtM &&  flagSignN && !flagSignM
     *
     *   :   flagNgtM && !flagSignM +
     *      !flagNgtM &&  flagSignN && !flagSignM
     */
    if ((flagNgtM && !flagSignM) || (!flagNgtM && flagSignN && !flagSignM))
        noOp = 2;

    if (!noOp)
        noOp = 3;

    /* Computing */
    DST->sign = flagSignOUT ? 1 : -1;

    switch (noOp)
    {
    case 1:
        bigint_sub(&DST->N, &N->N, &M->N);
        break;
    case 2:
        bigint_sum(&DST->N, &N->N, &M->N);
        break;
    case 3:
        bigint_sub(&DST->N, &M->N, &N->N);
        break;
    default:
        EXIT(FATAL_LOGIC, "sbigint_sub", "noOp undefined");
    }
}

void sbigint_mul(sbigint_p DST, sbigint_p N, sbigint_p M)
{
    DST->sign = N->sign * M->sign;
    bigint_mul(&DST->N, &N->N, &M->N);
}
