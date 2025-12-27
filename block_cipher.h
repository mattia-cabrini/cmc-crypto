#ifndef CMC_CRYPTO_BLOCK_CIPHER_INCLUDED
#define CMC_CRYPTO_BLOCK_CIPHER_INCLUDED

/* Paddin Modes */
enum
{
    PAD_NONE,
    PAD_PKCS7
};

/* Block Cipher Mode */
enum
{
    MODE_ECB,
    MODE_CBC,
    MODE_OFB,
    MODE_CFB,
    /* CTR and GCM are not implemented, as it would be a style excercise.
       Furthermore, a real world use case of CTR would require a system to be
       designed in order to produce a sequence of keys in a desirable manner. An
       elegant - but sub-optimal - library implementation would maybe take as
       input a function that returns a new key at each call. Shuch a design
       would be functional, but would also teach me nothing new about
       cryptography. */

    __aes_mode_invalid
};

#endif /* CMC_CRYPTO_BLOCK_CIPHER_INCLUDED */
