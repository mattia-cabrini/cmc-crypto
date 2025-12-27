#include <stdint.h>

#include "aes.h"
#include "error.h"
#include <string.h>

#define AES_BLOCK_SIZE 16

typedef unsigned char byte;

typedef struct aes_block_t
{
    byte data[AES_BLOCK_SIZE];
}* aes_block_p;

struct polynom_red_cache_item_t
{
    byte p;
    byte set;
};

typedef uint32_t word;

typedef struct aes_keys_t
{
    /* 0: pre
     * 1: after round 1
     * 2: after round 2
     * ...
     * R: after round R
     * */
    struct aes_block_t subkeys[15];

    /* How many subkeys are there, number of rounds + 1 */
    int N;
}* aes_keys_p;

typedef struct ofb_iterator_t
{
    struct aes_block_t subkey;
    struct aes_keys_t  KEY;
    int                n;
}* ofb_iterator_p;

static struct polynom_red_cache_item_t polynom_red_cache[256][256] = {0};

static char aes_err_custom[1024];
const char* AES_ERR_COLLECTION[] = {
    "",
    "padding character is out of bound for PKCS#7",
    "padding is not compliant to PKCS#7",
    "mode not supported"
};

/*
static const byte POLYNOM_INV[]                                    = {
    0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0,
    0xb0, 0xe1, 0xe5, 0xc7, 0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f,
    0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2, 0x3a, 0x6e, 0x5a, 0xf1,
    0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0x0a, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2,
    0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f,
    0x77, 0xbb, 0x59, 0x19, 0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69,
    0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x09, 0xed, 0x5c, 0x05, 0xca,
    0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17,
    0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91, 0xdf,
    0x33, 0x93, 0x21, 0x3b, 0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c,
    0xb6, 0x70, 0xd0, 0x06, 0xa1, 0xfa, 0x81, 0x82, 0x83, 0x7e, 0x7f, 0x80,
    0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x02, 0xb9, 0xa4,
    0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88,
    0xf9, 0xdc, 0x89, 0x9a, 0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48,
    0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62, 0x0c, 0xe0, 0x1f, 0xef,
    0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57,
    0x0b, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0x0f, 0xa9, 0x27, 0x53, 0x04,
    0x1b, 0xfc, 0xac, 0xe6, 0x7a, 0x07, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea,
    0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b, 0xb1, 0x0d, 0xd6, 0xeb,
    0xc6, 0x0e, 0xcf, 0xad, 0x08, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3,
    0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0,
    0xcd, 0x1a, 0x41, 0x1c
};
*/

static const byte S_BOX[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

static const byte S_BOX_INV[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d
};

static const byte MIX_COL_MATRIX[] = {
    0x02,
    0x03,
    0x01,
    0x01,
    0x01,
    0x02,
    0x03,
    0x01,
    0x01,
    0x01,
    0x02,
    0x03,
    0x03,
    0x01,
    0x01,
    0x02
};

static const byte INV_MIX_COL_MATRIX[] = {
    0x0E,
    0x0B,
    0x0D,
    0x09,
    0x09,
    0x0E,
    0x0B,
    0x0D,
    0x0D,
    0x09,
    0x0E,
    0x0B,
    0x0B,
    0x0D,
    0x09,
    0x0E
};

/* --- Utility Functions */

/* Return a byte with only the n-th bit set to the same value as `b` */
static byte byte_or(byte b, int n);

/* Return `1` if the n-th bit is set, `0` otherwise */
static byte byte_is_set(byte b, int n);

/* Set the n-th bit of `b` to the value of `state`, that must be `1` or `0` and
 * return it */
static byte byte_set(byte b, int state, int n);

/* --- Polynomial Operations */

/* Return the sum of `p` and `q`, treated as polynomials in GF(2^8) */
static byte polynom_sum(byte p, byte q);

/* Return the reduction of the 2-bytes `P`.
 * Reduction in modulo x^8 + x^4 + x^3 + x + 1 */
static byte polynom_red(byte* P);

/* Return the scalar product between `P` and `Q`, reduced.
 * `P` and `Q` are two vector of polynomials and have size `D`. */
static byte polynom_scalar_prod(const byte* P, const byte* Q, int D);

/* Return the multiplication `p` × `q`, reduced */
static byte polynom_mul(byte p, byte q);

/* Shift a 2-bytes polynomial by `n` to the left (multiplication against 2^n) */
static void polynom_shift(byte* DST, byte* SRC, int n);

/* --- AES Block */

/* `dst`: destination block;
 * `src`: source block;
 * `BOX`: S-Box to use
 *
 * This function can perform both the byte substitution and its inverse
 * algorithm. In fact, both algorithms consist of a simple byte-to-byte mapping
 * defined by a byte array. What algorithm is performed depends on the `BOX`
 * passed as parameter.
 *
 * S_BOX -> byte substitusion;
 * S_BIX_INV -> S_BOX^-1.
 *
 * `dst` and `src` must be different */
static void
aes_block_byte_substitution(aes_block_p dst, aes_block_p src, const byte* BOX);

/* `dst` and `src` must be different */
static void aes_block_shift_rows(aes_block_p dst, aes_block_p src);
static void aes_block_shift_rows_inv(aes_block_p dst, aes_block_p src);

/* `dst`: destination block;
 * `src`: source block;
 * `M`: mix matrix.
 *
 * This function can perform both the MixColumn and InvMixColumn algorithm. In
 * fact, both of them are merely a matrix-vector multiplication, hence the two
 * of them can be selected by passing the appropriate mix matrix as parameter.
 *
 * `dst` and `src` must be different */
static void
aes_block_mix_columns(aes_block_p dst, aes_block_p src, const byte* M);

/* `last_r` tells if it is the last round.
 * `dst` and `src` must be different. */
static void aes_block_diffusion(aes_block_p dst, aes_block_p src, int last_r);

/* `last_r` tells if it is the last round and refers to the last *encryption*
 * round, that happens to be the first one in decryption.
 *
 * `dst` and `src` must be different. */
static void
aes_block_diffusion_inv(aes_block_p dst, aes_block_p src, int last_r);

static void
aes_block_key_addition(aes_block_p dst, aes_block_p src, aes_block_p key);

/* `dst` and `src` must be different */
static void aes_block_round_n(
    aes_block_p dst, aes_block_p src, aes_keys_p keys, int round_no
);

/* `round_n` refers to the *encryption* round number, hence in goes backward in
 * decryption.
 *
 * `dst` and `src` must be different */
static void aes_block_round_n_inv(
    aes_block_p dst, aes_block_p src, aes_keys_p keys, int round_no
);

static void aes_block_encrypt(aes_block_p dst, aes_block_p src, aes_keys_p KEY);
static void aes_block_decrypt(aes_block_p dst, aes_block_p src, aes_keys_p KEY);

static void aes_block_copy(aes_block_p dst, aes_block_p src);

/* --- AES Keys */

static word aes_keys_schedule_h(word w);
static word aes_keys_schedule_g(word w, unsigned int i);

static word aes_keys_schedule_g(word w, unsigned int i);

static void aes_keys_schedule_tr(aes_keys_p KEY, word* W, unsigned int wN);

static void aes_keys_schedule_128(aes_keys_p KEY, byte* extern_key);
static void aes_keys_schedule_192(aes_keys_p KEY, byte* extern_key);
static void aes_keys_schedule_256(aes_keys_p KEY, byte* extern_key);

/* Initialize `KEY` with `extern_key`: `extern_key` is the AES encryption key
 * and `DIM` is its value expressed in bytes. */
static void aes_keys_init(aes_keys_p KEY, byte* extern_key, int DIM);

static void aes_keys_copy(aes_keys_p dst, aes_keys_p src);

/* --- OFB Iterator */
static void ofb_it_init(ofb_iterator_p it, aes_keys_p KEY, aes_block_p IV);
static byte ofb_it_next(ofb_iterator_p it);

/* --- AES MODES */

/*
 * U.B. if:
 * - encN < plainN;
 * - encN < 0;
 *   plainN < 0;
 */
static int aes_encrypt_ecb_cbc(
    char*       plain,
    char*       enc,
    int         plainN,
    int         encN,
    aes_keys_p  KEY,
    aes_block_p IV,
    int         pad_mode,
    int         block_mode
);

/*
 * U.B. if:
 * - plainB < encN;
 *   plainN < 0;
 *   encN < 0;
 */
static int aes_decrypt_ecb_cbc(
    char*       plain,
    char*       enc,
    int         encN,
    aes_keys_p  KEY,
    aes_block_p IV,
    int         pad_mode,
    int         block_mode
);

/*
 * U.B. if:
 * - sizeof(dst) < sizeof(src);
 * - N < 0;
 */
static int
aes_XXcrypt_ofb(char* dst, char* src, int N, aes_keys_p KEY, aes_block_p IV);

/* --- IMPL */

static byte byte_or(byte b, int n) { return (byte)(b & (1 << n)); }

static byte byte_is_set(byte b, int n) { return byte_or(b, n) ? 1 : 0; }

static byte polynom_sum(byte p, byte q) { return p ^ q; }

static byte byte_set(byte b, int state, int n)
{
    if (state)
    {
        state <<= n;
        return (byte)(b | state);
    }

    state = ~(1 << n);
    return (byte)(b & state);
}

static byte polynom_mul(byte p, byte q)
{
    int  current_exp;
    int  iP;
    int  iQ;
    byte tmp_1;
    byte tmp_2;
    byte RES[2];

    RES[0] = RES[1] = 0;

    for (current_exp = 0; current_exp <= 7 + 7; ++current_exp)
    {
        if (current_exp > 7)
            iP = 1;
        else
            iP = 0;

        for (; iP < 8; ++iP)
        {
            /* iP + iQ = current_exp, as they are the indexes of the
             * coefficients to multiply */
            iQ = current_exp - iP;

            if (iQ < 0 || iQ > 7)
                continue;

            /* Evaluating coefficients multiplication */
            tmp_1 = byte_is_set(p, iP) & byte_is_set(q, iQ);

            /* Evaluatin sum with previous multiplied coefficients for the
             * same expontet */
            if (current_exp > 7)
                tmp_2 = byte_is_set(RES[1], current_exp - 8);
            else
                tmp_2 = byte_is_set(RES[0], current_exp);

            if (current_exp > 7)
                RES[1] = byte_set(RES[1], tmp_1 ^ tmp_2, current_exp - 8);
            else
                RES[0] = byte_set(RES[0], tmp_1 ^ tmp_2, current_exp);
        }
    }

    return polynom_red(RES);
}

static void polynom_shift(byte* DST, byte* SRC, int n)
{
    uint32_t x;

    x = SRC[1];
    x <<= 8;
    x |= SRC[0];

    x <<= n;

    DST[1] = (byte)(x >> 8);
    DST[0] = (byte)(x & 0xFF);
}

static byte polynom_red(byte* P)
{
    int i = 0;

    byte PP[2];
    byte PRIME[2] = {0x1B, 0x01};
    byte SUBTRAHEND[2];

    struct polynom_red_cache_item_t* cached;

    cached = &polynom_red_cache[P[1]][P[0]];

    PP[0]  = P[0];
    PP[1]  = P[1];

    if (cached->set)
        return cached->p;

    while (PP[1]) /* PP[1] != 0 is equivalent to not reduced */
    {
        for (i = 7; i >= 0; --i)
        {
            /* Bit not set: not to be reduced */
            if (byte_or(PP[1], i) == 0)
                continue;

            polynom_shift(SUBTRAHEND, PRIME, i);

            PP[1] = polynom_sum(PP[1], SUBTRAHEND[1]);
            PP[0] = polynom_sum(PP[0], SUBTRAHEND[0]);
        }
    }

    cached->p   = PP[0];
    cached->set = 1;

    return cached->p;
}

static byte polynom_scalar_prod(const byte* P, const byte* Q, int D)
{
    byte res = 0x00;
    int  i;

    if (D <= 0)
        EXIT(FATAL_LOGIC, "polynom_scalar_prod", "D <= 0");

    for (i = 0; i < D; ++i)
        res = polynom_sum(res, polynom_mul(P[i], Q[i]));

    return res;
}

static void
aes_block_byte_substitution(aes_block_p dst, aes_block_p src, const byte* BOX)
{
    int i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
        dst->data[i] = BOX[src->data[i]];
}

static void aes_block_shift_rows(aes_block_p dst, aes_block_p src)
{
    dst->data[0]  = src->data[0];
    dst->data[1]  = src->data[5];
    dst->data[2]  = src->data[10];
    dst->data[3]  = src->data[15];
    dst->data[4]  = src->data[4];
    dst->data[5]  = src->data[9];
    dst->data[6]  = src->data[14];
    dst->data[7]  = src->data[3];
    dst->data[8]  = src->data[8];
    dst->data[9]  = src->data[13];
    dst->data[10] = src->data[2];
    dst->data[11] = src->data[7];
    dst->data[12] = src->data[12];
    dst->data[13] = src->data[1];
    dst->data[14] = src->data[6];
    dst->data[15] = src->data[11];
}

static void aes_block_shift_rows_inv(aes_block_p dst, aes_block_p src)
{
    dst->data[0]  = src->data[0];
    dst->data[5]  = src->data[1];
    dst->data[10] = src->data[2];
    dst->data[15] = src->data[3];
    dst->data[4]  = src->data[4];
    dst->data[9]  = src->data[5];
    dst->data[14] = src->data[6];
    dst->data[3]  = src->data[7];
    dst->data[8]  = src->data[8];
    dst->data[13] = src->data[9];
    dst->data[2]  = src->data[10];
    dst->data[7]  = src->data[11];
    dst->data[12] = src->data[12];
    dst->data[1]  = src->data[13];
    dst->data[6]  = src->data[14];
    dst->data[11] = src->data[15];
}

static void
aes_block_mix_columns(aes_block_p dst, aes_block_p src, const byte* M)
{
    const byte* matrix_row;
    const byte* state_column;
    int         i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        state_column = &src->data[i & ~3];
        matrix_row   = &M[(i & 3) * 4];
        dst->data[i] = polynom_scalar_prod(matrix_row, state_column, 4);
    }
}

static void aes_block_diffusion(aes_block_p dst, aes_block_p src, int last_r)
{
    struct aes_block_t shifted;

    aes_block_shift_rows(&shifted, src);

    if (!last_r)
        aes_block_mix_columns(dst, &shifted, MIX_COL_MATRIX);
    else
        aes_block_copy(dst, &shifted);
}

static void
aes_block_diffusion_inv(aes_block_p dst, aes_block_p src, int last_r)
{
    struct aes_block_t shifted;

    if (!last_r)
        aes_block_mix_columns(&shifted, src, INV_MIX_COL_MATRIX);
    else
        aes_block_copy(&shifted, src);

    aes_block_shift_rows_inv(dst, &shifted);
}

static void
aes_block_key_addition(aes_block_p dst, aes_block_p src, aes_block_p key)
{
    int i;

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
        dst->data[i] = src->data[i] ^ key->data[i];
}

static void aes_block_round_n(
    aes_block_p dst, aes_block_p src, aes_keys_p keys, int round_no
)
{
    struct aes_block_t tmp_sub, tmp_diff;

    if (round_no < 1 || round_no > keys->N - 1)
        EXIT(FATAL_LOGIC, "aes_block_round_n", "round_no out of bound");

    aes_block_byte_substitution(&tmp_sub, src, S_BOX);
    aes_block_diffusion(&tmp_diff, &tmp_sub, round_no == keys->N - 1);

    aes_block_key_addition(dst, &tmp_diff, &keys->subkeys[round_no]);
}

static void aes_block_round_n_inv(
    aes_block_p dst, aes_block_p src, aes_keys_p keys, int round_no
)
{
    struct aes_block_t tmp_diff;

    if (round_no < 1 || round_no > keys->N - 1)
        EXIT(FATAL_LOGIC, "aes_block_round_n", "round_no out of bound");

    aes_block_key_addition(dst, src, &keys->subkeys[round_no]);

    aes_block_diffusion_inv(&tmp_diff, dst, round_no == keys->N - 1);
    aes_block_byte_substitution(dst, &tmp_diff, S_BOX_INV);
}

static void aes_keys_init(aes_keys_p KEY, byte* extern_key, int DIM)
{
    switch (DIM)
    {
    case 32:
        KEY->N = 15;
        aes_keys_schedule_256(KEY, extern_key);
        break;
    case 24:
        KEY->N = 13;
        aes_keys_schedule_192(KEY, extern_key);
        break;
    case 16:
        KEY->N = 11;
        aes_keys_schedule_128(KEY, extern_key);
        break;
    default:
        EXIT(
            FATAL_LOGIC,
            "aes_keys_init",
            "incorrect key size (the only allowed key lengths are 16B (128), "
            "24B (192) and 32B (256)"
        );
    }
}

static void aes_keys_copy(aes_keys_p dst, aes_keys_p src)
{
    memcpy(dst, src, sizeof(*dst));
}

static word aes_keys_schedule_h(word w)
{
    byte* vTOw = (byte*)&w;

    vTOw[0]    = S_BOX[vTOw[0]];
    vTOw[1]    = S_BOX[vTOw[1]];
    vTOw[2]    = S_BOX[vTOw[2]];
    vTOw[3]    = S_BOX[vTOw[3]];

    return w;
}

static word aes_keys_schedule_g(word w, unsigned int i)
{
    byte* vTOw = (byte*)&w;
    word  res;
    byte* shifted = (byte*)&res;
    byte  RC[2]   = {1, 0};
    byte  RCi;

    shifted[0] = S_BOX[vTOw[1]];
    shifted[1] = S_BOX[vTOw[2]];
    shifted[2] = S_BOX[vTOw[3]];
    shifted[3] = S_BOX[vTOw[0]];

    if (i)
        polynom_shift(RC, RC, (int)(i - 1));
    RCi = polynom_red(RC);

    shifted[0] ^= RCi;

    return res;
}

static void aes_keys_schedule_tr(aes_keys_p KEY, word* W, unsigned int wN)
{
    unsigned int i;
    unsigned int j;

    unsigned int IT = KEY->N == 11 ? 10 : 8;
    unsigned int SZ = KEY->N == 11 ? 4 : 6;

    switch (KEY->N)
    {
    case 11:
        IT = 10;
        SZ = 4;
        break;
    case 13:
        IT = 8;
        SZ = 6;
        break;
    case 15:
        IT = 7;
        SZ = 8;
        break;
    default:
        EXIT(FATAL_LOGIC, "aes_keys_schedule_tr", "round number out of domain");
    }

    for (i = 1; i <= IT; ++i)
    {
        W[SZ * i] = W[SZ * (i - 1)] ^ aes_keys_schedule_g(W[SZ * i - 1], i);

        for (j = 1; j <= SZ - 1 && SZ * i + j < wN; ++j)
        {
            if (KEY->N == 15 && j == 4)
                W[SZ * i + j] = aes_keys_schedule_h(W[SZ * i + j - 1]) ^
                                W[SZ * (i - 1) + j];
            else
                W[SZ * i + j] = W[SZ * i + j - 1] ^ W[SZ * (i - 1) + j];
        }
    }
}

static void aes_keys_schedule_128(aes_keys_p KEY, byte* extern_key)
{
    const int N     = 16;
    int       i     = 0;
    word      W[44] = {0};

    memcpy(W, extern_key, (size_t)N);
    memcpy(&KEY->subkeys[0], extern_key, sizeof(KEY->subkeys[0]));

    aes_keys_schedule_tr(KEY, W, 44);

    for (i = 1; i < KEY->N; ++i)
        memcpy(&KEY->subkeys[i], &W[i * 4], sizeof(KEY->subkeys[0]));
}

static void aes_keys_schedule_192(aes_keys_p KEY, byte* extern_key)
{
    const int N     = 24;
    int       i     = 0;
    word      W[52] = {0};

    memcpy(W, extern_key, (size_t)N);
    memcpy(&KEY->subkeys[0], extern_key, sizeof(KEY->subkeys[0]));

    aes_keys_schedule_tr(KEY, W, 52);

    for (i = 1; i < KEY->N; ++i)
        memcpy(&KEY->subkeys[i], &W[i * 4], sizeof(KEY->subkeys[0]));
}

static void aes_keys_schedule_256(aes_keys_p KEY, byte* extern_key)
{
    const int N     = 32;
    int       i     = 0;
    word      W[60] = {0};

    memcpy(W, extern_key, (size_t)N);
    memcpy(&KEY->subkeys[0], extern_key, sizeof(KEY->subkeys[0]));

    aes_keys_schedule_tr(KEY, W, 60);

    for (i = 1; i < KEY->N; ++i)
        memcpy(&KEY->subkeys[i], &W[i * 4], sizeof(KEY->subkeys[0]));
}

static void aes_block_encrypt(aes_block_p dst, aes_block_p src, aes_keys_p KEY)
{
    struct aes_block_t block[2];
    int                i;

    aes_block_key_addition(&block[1], src, &KEY->subkeys[0]);

    for (i = 0; i < KEY->N - 1; ++i)
        /* Ping-Pong 1-0, 0-1, 1-0, 0-1, ... */
        aes_block_round_n(&block[i & 1], &block[1 - (i & 1)], KEY, i + 1);

    aes_block_copy(dst, &block[(i - 1) & 1]);
}

static void aes_block_decrypt(aes_block_p dst, aes_block_p src, aes_keys_p KEY)
{
    struct aes_block_t block[2];
    int                i;

    int iDst = 0;

    aes_block_copy(block + iDst, src);
    memset(block + (1 - iDst), 0, sizeof(struct aes_block_t));

    for (i = KEY->N - 1; i > 0; --i)
    {
        iDst = 1 - iDst;
        aes_block_round_n_inv(block + iDst, block + (1 - iDst), KEY, i);
    }

    iDst = 1 - iDst;
    aes_block_key_addition(block + iDst, block + (1 - iDst), &KEY->subkeys[0]);

    aes_block_copy(dst, block + iDst);
}

static void aes_block_copy(aes_block_p dst, aes_block_p src)
{
    memcpy(dst, src, sizeof(*dst));
}

static int aes_encrypt_ecb_cbc(
    char*       plain,
    char*       enc,
    int         plainN,
    int         encN,
    aes_keys_p  KEY,
    aes_block_p IV,
    int         pad_mode,
    int         block_mode
)
{
    struct aes_block_t src;
    struct aes_block_t dst;
    struct aes_block_t iv;

    int  iPlain;
    byte pad_byte = 0x00;

    if (block_mode != AES_MODE_ECB && block_mode != AES_MODE_CBC)
        /* Exit, for function is internal to the TU, and hence should receive
         * this parameter correctly */
        EXIT(
            FATAL_LOGIC,
            "aes_encrypt_ecb_cbc",
            "mode different from ECB or CBC are not supported"
        );

    if (block_mode == AES_MODE_CBC)
        aes_block_copy(&iv, IV);

    switch (pad_mode)
    {
    case AES_PAD_NONE:
        if (plainN % 16 != 0)
        {
            sprintf(
                aes_err_custom,
                "padding mode is NONE but plaintext size is (%d)",
                plainN
            );
            return AES_ERR_CUSTOM;
        }
        break;
    case AES_PAD_PKCS7:
        if (encN < plainN + (plainN % 16 == 0 ? 16 : 16 - (plainN % 16)))
        {
            sprintf(
                aes_err_custom,
                "enc has size %d and plaintext has size %d: wrong for PKCS#7",
                encN,
                plainN
            );
            return AES_ERR_CUSTOM;
        }
        break;
    default:
        sprintf(aes_err_custom, "padding mode not supported");
        return AES_ERR_CUSTOM;
    }

    for (iPlain = 0; iPlain < plainN; iPlain += AES_BLOCK_SIZE)
    {
        /* Last block -> handling padding */
        if (iPlain + AES_BLOCK_SIZE >= plainN)
            pad_byte = (byte)(AES_BLOCK_SIZE - (plainN - iPlain));

        memcpy(src.data, &plain[iPlain], (size_t)(AES_BLOCK_SIZE - pad_byte));

        if (pad_byte > 0)
            memset(src.data + (AES_BLOCK_SIZE - pad_byte), pad_byte, pad_byte);

        if (block_mode == AES_MODE_CBC)
            aes_block_key_addition(&src, &src, &iv);

        aes_block_encrypt(&dst, &src, KEY);

        memcpy(&enc[iPlain], dst.data, sizeof(src.data));

        if (block_mode == AES_MODE_CBC)
            aes_block_copy(&iv, &dst);
    }

    switch (pad_mode)
    {
    case AES_PAD_PKCS7:
        if (pad_byte != 0)
            break;

        memset(src.data, 0x10, AES_BLOCK_SIZE);

        if (block_mode == AES_MODE_CBC)
            aes_block_key_addition(&src, &src, &iv);

        aes_block_encrypt(&dst, &src, KEY);
        memcpy(&enc[iPlain], dst.data, sizeof(src.data));

        break;
    }

    return AES_ERR_NONE;
}

static int
aes_XXcrypt_ofb(char* dst, char* src, int N, aes_keys_p KEY, aes_block_p IV)
{
    struct ofb_iterator_t it;

    int i;

    ofb_it_init(&it, KEY, IV);

    for (i = 0; i < N; ++i)
        dst[i] = (char)(src[i] ^ ofb_it_next(&it));

    return 0;
}

int aes_encrypt(
    char*          plain,
    char*          enc,
    unsigned char* key,
    int            plainN,
    int            encN,
    int            keyN,
    char*          IV,
    int            pad_mode,
    int            block_mode
)
{
    struct aes_keys_t  KEY;
    struct aes_block_t oIV;

    if (encN < plainN || plainN < 0 || encN < 0)
    {
        sprintf(
            aes_err_custom,
            "enc has size %d and plaintext has size %d: incompatible or wrong",
            encN,
            plainN
        );
        return AES_ERR_CUSTOM;
    }

    aes_keys_init(&KEY, key, keyN);

    if (IV != NULL)
        memcpy(oIV.data, IV, 16);
    else
        memset(oIV.data, 0, 16);

    switch (block_mode)
    {
    case AES_MODE_ECB:
    case AES_MODE_CBC:
        return aes_encrypt_ecb_cbc(
            plain, enc, plainN, encN, &KEY, &oIV, pad_mode, block_mode
        );
    case AES_MODE_OFB:
        return aes_XXcrypt_ofb(enc, plain, plainN, &KEY, &oIV);
    default:
        return AES_ERR_MODE_NOT_SUPPORTED;
    }

    /* Exit, for it should be unreachable */
    EXIT(FATAL_LOGIC, "aes_encrypt", "### no statement ###");
}

static int aes_decrypt_ecb_cbc(
    char*       plain,
    char*       enc,
    int         encN,
    aes_keys_p  KEY,
    aes_block_p IV,
    int         pad_mode,
    int         block_mode
)
{
    struct aes_block_t src;
    struct aes_block_t dst;
    struct aes_block_t iv;

    int  iEnc;
    byte pad_byte = 0x00;

    if (block_mode != AES_MODE_ECB && block_mode != AES_MODE_CBC)
        /* Exit, for function is internal to the TU, and hence should receive
         * this parameter correctly */
        EXIT(
            FATAL_LOGIC,
            "aes_decrypt_ecb_cbc",
            "mode different from ECB and CBC are not supported"
        );

    if (encN % 16 != 0 || encN == 0)
    {
        sprintf(
            aes_err_custom, "enc has size %d, that is not multiple of 16", encN
        );
        return AES_ERR_CUSTOM;
    }

    if (block_mode == AES_MODE_CBC)
        aes_block_copy(&iv, IV);

    for (iEnc = 0; iEnc < encN; iEnc += AES_BLOCK_SIZE)
    {
        memcpy(src.data, &enc[iEnc], AES_BLOCK_SIZE);

        aes_block_decrypt(&dst, &src, KEY);

        if (block_mode == AES_MODE_CBC)
        {
            aes_block_key_addition(&dst, &dst, &iv);
            aes_block_copy(&iv, &src);
        }

        memcpy(&plain[iEnc], dst.data, sizeof(src.data));
    }

    switch (pad_mode)
    {
    case AES_PAD_PKCS7:
        pad_byte = (byte)plain[encN - 1];

        if (pad_byte < 0x01 || pad_byte > 0x10)
            return AES_ERR_PKCS_OUT_CHAR_OOB;

        for (iEnc = encN - 1; iEnc >= 0 && encN - iEnc <= pad_byte; --iEnc)
            if (plain[iEnc] != pad_byte)
                return AES_ERR_PKCS_INVALID_PADDING;

        memset(plain + (encN - pad_byte), 0, pad_byte);
        break;
    }

    return 0;
}

int aes_decrypt(
    char*          plain,
    char*          enc,
    unsigned char* key,
    int            plainN,
    int            encN,
    int            keyN,
    char*          IV,
    int            pad_mode,
    int            block_mode
)
{
    struct aes_keys_t  KEY;
    struct aes_block_t iv;

    if (plainN < encN || plainN < 0 || encN < 0)
    {
        sprintf(
            aes_err_custom,
            "enc has size %d and plaintext has size %d: incompatible or wrong",
            encN,
            plainN
        );
        EXIT(FATAL_LOGIC, "aes_decrypt", aes_err_custom);
    }

    if (IV != NULL)
        memcpy(iv.data, IV, 16);
    else
        memset(iv.data, 0, 16);

    aes_keys_init(&KEY, key, keyN);

    switch (block_mode)
    {
    case AES_MODE_ECB:
    case AES_MODE_CBC:
        return aes_decrypt_ecb_cbc(
            plain, enc, encN, &KEY, &iv, pad_mode, block_mode
        );
    case AES_MODE_OFB:
        return aes_XXcrypt_ofb(plain, enc, encN, &KEY, &iv);
    default:
        return AES_ERR_MODE_NOT_SUPPORTED;
    }

    return 0;
}

const char* aes_err(int code)
{
    if (code == AES_ERR_CUSTOM)
        return aes_err_custom;

    if (code <= 0 || code >= __aes_err_sentinel)
        return NULL;

    return AES_ERR_COLLECTION[code];
}

static void ofb_it_init(ofb_iterator_p it, aes_keys_p KEY, aes_block_p IV)
{
    aes_block_copy(&it->subkey, IV);
    aes_keys_copy(&it->KEY, KEY);
    it->n = AES_BLOCK_SIZE;
}

static byte ofb_it_next(ofb_iterator_p it)
{
    struct aes_block_t tmp;

    if (it->n == AES_BLOCK_SIZE)
    {
        it->n = 0;
        aes_block_encrypt(&tmp, &it->subkey, &it->KEY);
        aes_block_copy(&it->subkey, &tmp);
    }

    it->n += 1;
    return it->subkey.data[it->n - 1];
}
