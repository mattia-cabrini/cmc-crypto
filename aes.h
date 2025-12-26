#ifndef CMC_CRYPTO_AES
#define CMC_CRYPTO_AES

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

#endif /* CMC_CRYPTO_AES */
