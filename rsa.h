#ifndef CMC_CRYPTO_RSA_INCLUDED
#define CMC_CRYPTO_RSA_INCLUDED

#include <stdio.h>

#include "bigint.h"

#ifndef PRIMALITY_S
#define PRIMALITY_S 10
#endif

/* RSA ERROR ENUM */
enum
{
    RSA_OK = 0,
    RSA_ERR_UNSUPPORTED_SIZE,
    RSA_ERR_OVERFLOW_SIZE,
    RSA_NIY,
    RSA_ERR_N_IMPORT_FAILED,
    RSA_ERR_EXP_IMPORT_FAILED,
    RSA_ERR_IMPORT_JOIN_FAILED_BIT_LENGTH,
    RSA_ERR_IMPORT_JOIN_FAILED_N,
    RSA_ERR_IMPORT_JOIN_FAILED_MOD,

    __rsa_err_sentinel,
    RSA_ERR_CUSTOM
};

typedef struct rsa_key_t
{
    struct bigint_t n; /* p * q */
    struct bigint_t e; /* public exponent */
    struct bigint_t d; /* private exponent */
    int             bit_length;
}* rsa_key_p;

/* Key generation is limited by the value of BIGINT_MAX and in any case to the
 * following bit lengths:
 * - 64 (if compiled with debug symbols);
 * - 1024;
 * - 2048;
 * - 3072;
 * - 4096;
 * - 8192.
 *
 * RETURN
 * RSA ERROR ENUM
 */
extern int  rsa_key_generate(rsa_key_p FK, int bit_length);
extern void rsa_key_copy(rsa_key_p DST, rsa_key_p SRC);

/* pub != NULL -> Public key is imported into it
 * priv != NULL -> Private key is imported into it
 *
 * The function might also be called with bot parameter NULL; It would simply do
 * nothing at all.
 *
 * RETURN
 * RSA ERROR ENUM
 */
extern int rsa_key_import(rsa_key_p FK, FILE* pub, FILE* priv);

/* pub != NULL -> Public key is dumped into it
 * priv != NULL -> Private key is dumped into it
 *
 * The function might also be called with bot parameter NULL; It would simply do
 * nothing at all.
 */
extern void rsa_key_dump(rsa_key_p FK, FILE* pub, FILE* priv);

extern int rsa_key_ispub(rsa_key_p K);
extern int rsa_key_ispriv(rsa_key_p K);

/* RETURN
 * RSA ERROR ENUM
 */
extern int rsa_key_bit_length_supported(int size);

/* Do not free */
extern const char* rsa_err(int code);

#endif /* CMC_CRYPTO_RSA_INCLUDED */
