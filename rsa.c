#include <string.h>

#include "error.h"
#include "random.h"
#include "rsa.h"

typedef struct rsa_keygen_t
{
    struct bigint_t  p;
    struct bigint_t  q;
    struct bigint_t  phi_n;
    struct rsa_key_t K;
}* rsa_keygen_p;

const char* RSA_ERR[] = {
    "rsa: unsupported key bit length",
    "rsa: key too long: bit length exceed BIGINT_MAX",
    "rsa: not implemented, yet",
    "rsa: could not import `n`, bigint_import failed",
    "rsa: could not import exponent, bigint_import failed",
    "rsa: pub-priv join failed: bit lengths not compatible",
    "rsa: pub-priv join failed: `n` not consistent",
};

char RSA_ERR_MESSAGE[2048] = {0};

static void rsa_key_init(rsa_key_p FK);

/* Get a prime with maximum length of byte_length */
static void rsa_get_prime(bigint_p N, int byte_length);

/* Select public and private exponents */
static void rsa_select_exp(rsa_keygen_p keygen);

/* Checl primality using an implementation of Miller-Rabin primality check */
static int miller_rabin_is_likely_prime(bigint_p N, int u, bigint_p R);

/* Euler's Phi function on n = p * q.
 *
 * RETURN
 * PHI(n) = PHI(p * q)
 */
static void rsa_phi(bigint_p DST, bigint_p p, bigint_p q);

/* Dump a single n-exp pair */
static void rsa_n_exp_dump(FILE* fp, bigint_p n, bigint_p e, int bit_length);

/* Import a single n-exp pair
 *
 * OUTPUT
 * - K->bit_length <- set to the bit length read from fp;
 * - K->n          <- set to `n` read from fp;
 * - E             <- set to the exponent read from fp.
 *
 * RETURN
 * RSA ERROR ENUM
 */
static int rsa_n_exp_import(FILE* fp, rsa_key_p K, bigint_p E);

/* Checks and join a public and a private key.
 *
 * The join process consists of copying into DST all key parts.
 *
 * The check process consists of:
 * - Verifying bit length equality;
 * - Verifying `n` equality.
 *
 * RETURN
 * RSA ERROR ENUM
 */
static int rsa_key_import_join(rsa_key_p DST, rsa_key_p pub, rsa_key_p priv);

/* IMPL */

/* STATIC */
static void rsa_key_init(rsa_key_p FK)
{
    memset(FK, 0, sizeof(struct rsa_key_t));
}

static void rsa_get_prime(bigint_p N, int byte_length)
{
    int             u;
    struct bigint_t twoU; /* 2^u */
    struct bigint_t one;  /* one */
    struct bigint_t R;

    if (byte_length <= 1)
    {
        N->overflow = 1;
        return;
    }

    bigint_init_by_int(&one, 1);

    do
    {
        /* Choosing u in (0, byte_length / 2] */
        random_get_buffer((char*)&u, sizeof(u));
        u %= byte_length / 2;
        if (u < 0)
            u += byte_length / 2;
        ++u;

        /* 2^u */
        bigint_copy(&twoU, &one);
        bigint_shiftl(&twoU, &twoU, u);

        bigint_init_rand(&R, (size_t)byte_length);
        bigint_or(&R, &R, &one);

        bigint_mul(N, &R, &twoU); /* N = 2^u * R */
        bigint_sum(N, N, &one);   /* N = N + 1 */
    } while (!miller_rabin_is_likely_prime(N, u, &R));
}

static void rsa_select_exp(rsa_keygen_p keygen)
{
    struct bigint_t GCD;

    bigint_init_by_int(&GCD, 2);

    while (!bigint_eq_byte(&GCD, 1))
    {
        do
        {
            bigint_init_rand(&keygen->K.e, (size_t)(keygen->K.n.max_exp + 1));
        } while (bigint_cmp(&keygen->phi_n, &keygen->K.e) < 0);

        bigint_eec(&GCD, &keygen->K.d, &keygen->K.e, &keygen->phi_n);
    }
}

static int miller_rabin_is_likely_prime(bigint_p N, int u, bigint_p R)
{
    int             s;
    int             i;
    struct bigint_t A;
    struct bigint_t nm1; /* nm1 = N - 1 */
    struct bigint_t Z;

    bigint_sub_int(&nm1, N, 1);

    for (s = 0; s < PRIMALITY_S; ++s)
    {
        do
        {
            bigint_init_rand(&A, (size_t)nm1.max_exp);
        } while (bigint_cmp(&nm1, &A) <= 0 || bigint_eq_byte(&A, 0) ||
                 bigint_eq_byte(&A, 1));

        bigint_exp_mod(&Z, &A, R, N);

        if (bigint_eq_byte(&Z, 1) || bigint_cmp(&Z, &nm1) == 0)
            continue; /* Likely prime, maybe a lie... */

        if (!bigint_eq_byte(&Z, 1))
            for (i = 1; i < u; ++i)
            {
                bigint_square(&Z, &Z);
                bigint_mod(&Z, &Z, N);

                if (bigint_eq_byte(&Z, 1))
                    return 0;

                if (bigint_cmp(&Z, &nm1) == 0)
                    break;
            }

        if (bigint_cmp(&Z, &nm1) != 0)
            return 0;
    }

    return 1;
}

static void rsa_phi(bigint_p DST, bigint_p p, bigint_p q)
{
    struct bigint_t one;
    struct bigint_t pm1;
    struct bigint_t qm1;

    bigint_init_by_int(&one, 1);
    bigint_sub(&pm1, p, &one);
    bigint_sub(&qm1, q, &one);

    bigint_mul(DST, &pm1, &qm1);
}

static void rsa_n_exp_dump(FILE* fp, bigint_p n, bigint_p e, int bit_length)
{
    char dumped[BIGINT_DUMP_SIZE];

    fprintf(fp, "%d ", bit_length);

    bigint_tostring(dumped, n, 16);
    fprintf(fp, "%s ", &dumped[BIGINT_DUMP_SIZE - bit_length / 4 - 1]);

    bigint_tostring(dumped, e, 16);
    fprintf(fp, "%s ", &dumped[BIGINT_DUMP_SIZE - bit_length / 4 - 1]);
}

static int rsa_n_exp_import(FILE* fp, rsa_key_p K, bigint_p E)
{
    char dumped[BIGINT_DUMP_SIZE];
    int  res;

    fscanf(fp, "%d", &K->bit_length);
    res = rsa_key_bit_length_supported(K->bit_length);
    if (res != RSA_OK)
        return res;

    fscanf(fp, "%s", dumped);           /* n */
    res = bigint_import(&K->n, dumped); /* res <- true or false */
    if (!res)
        return RSA_ERR_N_IMPORT_FAILED;

    fscanf(fp, "%s", dumped);       /* exp */
    res = bigint_import(E, dumped); /* res <- true or false */
    if (!res)
        return RSA_ERR_EXP_IMPORT_FAILED;

    return RSA_OK;
}

static int rsa_key_import_join(rsa_key_p DST, rsa_key_p pub, rsa_key_p priv)
{
    if (pub->bit_length != priv->bit_length)
        return RSA_ERR_IMPORT_JOIN_FAILED_BIT_LENGTH;

    if (bigint_cmp(&pub->n, &priv->n))
        return RSA_ERR_IMPORT_JOIN_FAILED_N;

    bigint_copy(&DST->n, &pub->n);
    bigint_copy(&DST->e, &pub->e);
    bigint_copy(&DST->d, &pub->d);
    DST->bit_length = pub->bit_length;

    return RSA_OK;
}

/* EXTERN */
int rsa_key_bit_length_supported(int bit_length)
{
    if (bit_length > 8 * BIGINT_MAX)
        return RSA_ERR_OVERFLOW_SIZE;

    switch (bit_length)
    {
#ifdef DEBUG
    case 64:
#endif
    case 1 * 1024:
    case 2 * 1024:
    case 3 * 1024:
    case 4 * 1024:
    case 8 * 1024:
        return RSA_OK;
        break;
    }

    return RSA_ERR_UNSUPPORTED_SIZE;
}

int rsa_key_generate(rsa_key_p FK, int bit_length)
{
    int                 err;
    struct rsa_keygen_t keygen;

    err = rsa_key_bit_length_supported(bit_length);
    RETERR(err);

    rsa_get_prime(&keygen.p, (bit_length / 2) / 8);
    rsa_get_prime(&keygen.q, (bit_length / 2) / 8);

    bigint_mul(&keygen.K.n, &keygen.p, &keygen.q);
    rsa_phi(&keygen.phi_n, &keygen.p, &keygen.q);
    rsa_select_exp(&keygen);

    keygen.K.bit_length = bit_length;
    rsa_key_copy(FK, &keygen.K);

    return RSA_OK;
}

void rsa_key_copy(rsa_key_p DST, rsa_key_p SRC)
{
    memcpy(DST, SRC, sizeof(struct rsa_key_t));
}

int rsa_key_import(rsa_key_p FK, FILE* pub, FILE* priv)
{
    struct rsa_key_t pubK;
    struct rsa_key_t privK;
    int              res = RSA_OK;

    rsa_key_init(FK);

    if (pub != NULL)
    {
        if (priv == NULL)
            /* Full - public only */
            res = rsa_n_exp_import(pub, FK, &FK->e);
        else
            /* Partial - public part here */
            res = rsa_n_exp_import(pub, &pubK, &pubK.e);
    }

    if (res == RSA_OK && priv != NULL)
    {
        if (pub == NULL)
            /* Full - private only */
            res = rsa_n_exp_import(priv, FK, &FK->d);
        else
            /* Partial - private here */
            res = rsa_n_exp_import(priv, &privK, &privK.d);
    }

    /* Join is done only if both the private and public keys are read */
    if (res == RSA_OK && pub != NULL && priv != NULL)
        res = rsa_key_import_join(FK, &pubK, &privK);

    return res;
}

void rsa_key_dump(rsa_key_p FK, FILE* pub, FILE* priv)
{
    if (pub != NULL)
        rsa_n_exp_dump(pub, &FK->n, &FK->e, FK->bit_length);
    if (priv != NULL)
        rsa_n_exp_dump(priv, &FK->n, &FK->d, FK->bit_length);
}

int rsa_key_ispub(rsa_key_p K) { return !bigint_iszero(&K->e); }

int rsa_key_ispriv(rsa_key_p K) { return !bigint_iszero(&K->d); }

const char* rsa_err(int err)
{
    if (err < 0)
        return NULL;

    switch (err)
    {
    case RSA_ERR_CUSTOM:
        return RSA_ERR_MESSAGE;
    case RSA_OK:
    case __rsa_err_sentinel:
        return NULL;
    default:
        return RSA_ERR[err - 1];
    }
}

void rsa_encrypt(bigint_p DST, bigint_p B, rsa_key_p K)
{
    bigint_exp_mod(DST, B, &K->e, &K->n);
}

void rsa_decrypt(bigint_p DST, bigint_p B, rsa_key_p K)
{
    bigint_exp_mod(DST, B, &K->d, &K->n);
}

void rsa_sign(bigint_p DST, bigint_p B, rsa_key_p K)
{
    bigint_exp_mod(DST, B, &K->d, &K->n);
}

void rsa_decrypt_signed(bigint_p DST, bigint_p B, rsa_key_p K)
{
    bigint_exp_mod(DST, B, &K->e, &K->n);
}
