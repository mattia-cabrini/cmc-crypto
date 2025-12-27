#ifndef CMC_CRYPTO_AES
#define CMC_CRYPTO_AES

enum
{
    AES_ERR_NONE = 0,
    AES_ERR_PKCS_OUT_CHAR_OOB,
    AES_ERR_PKCS_INVALID_PADDING,
    AES_ERR_MODE_NOT_SUPPORTED,

    __aes_err_sentinel,
    AES_ERR_CUSTOM
};

enum
{
    AES_PAD_NONE,
    AES_PAD_PKCS7
};

enum
{
    AES_MODE_ECB,
    AES_MODE_CBC
};

/*
 * IV: NULL or 16 bytes long
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

#endif /* CMC_CRYPTO_AES */
