#ifndef CMC_CRYPTO_AES
#define CMC_CRYPTO_AES

enum
{
    AES_ERR_NONE = 0,
    AES_ERR_PKCS_OUT_CHAR_OOB,

    __aes_err_sentinel
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

extern void aes_encrypt(
    char*          plain,
    char*          enc,
    unsigned char* key,
    int            plainN,
    int            encN,
    int            keyN,
    int            pad_mode,
    int            block_mode
);

extern int aes_decrypt(
    char*          plain,
    char*          enc,
    unsigned char* key,
    int            plainN,
    int            encN,
    int            keyN,
    int            pad_mode,
    int            block_mode
);

extern const char* aes_err(int code);

#endif /* CMC_CRYPTO_AES */
