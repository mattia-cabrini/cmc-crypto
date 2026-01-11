#ifndef CMC_CRYPTO_AES_INCLUDED
#define CMC_CRYPTO_AES_INCLUDED

#include "block_cipher.h"

enum
{
    AES_ERR_NONE = 0,
    AES_ERR_PKCS_OUT_CHAR_OOB,
    AES_ERR_PKCS_INVALID_PADDING,
    AES_ERR_MODE_NOT_SUPPORTED,

    __aes_err_sentinel,
    AES_ERR_CUSTOM
};

/*
 * IV: NULL or 16 bytes long
 * Pad Mode is only used in ECB and CBC modes.
 */
extern int aes_encrypt(
    char*          plain,
    char*          enc,
    unsigned char* key,
    int            plainN,
    int            encN,
    int            keyN,
    char*          IV,
    int            pad_mode,
    int            block_mode
);

/*
 * IV: NULL or 16 bytes long
 * Pad Mode is only used in ECB and CBC modes.
 *
 * WARNING:
 * Padding is not removed.
 */
extern int aes_decrypt(
    char*          plain,
    char*          enc,
    unsigned char* key,
    int            plainN,
    int            encN,
    int            keyN,
    char*          IV,
    int            pad_mode,
    int            block_mode
);

/* DO NOT FREE */
extern const char* aes_err(int code);

#endif /* CMC_CRYPTO_AES_INCLUDED */
