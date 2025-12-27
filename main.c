#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "error.h"

enum
{
    CLI_OP       = 1,
    CLI_CIPHER   = 2,
    CLI_PATH_KEY = 3,
    CLI_PATH_IN  = 4,
    CLI_PATH_OUT = 5,
    CLI_PATH_IV  = 6
};

void exit_usage(void);

void aes_router(int argc, char** argv);

/* Read all file content and put it in a buffer.
 * The buffer is returned and ownership is transfered to the caller.
 * The buffer size if stored into *r. */
char* read_all_content(const char* path, int* r);

/* Write a buffer to a file, panic in case of failure.
 */
void write_all_content(const char* buf, const char* path, int r, int pad_mode);

/*
 * argc = 3:
 * - [0]
 * - [1] operation (encrypt, decrypt)
 * - [2] algo-variant-padding. E.g.:
 *   - AES-ECB
 *   - AES-CBC
 *   - AES-ECB-PKCS#7
 *   - AES-OFB
 *   [3] key file;
 * - [4] path in;
 * - [5] path out;
 * - [ ] cipher-specific options.
 * */
int main(int argc, char** argv)
{
    (void)argv;

    if (argc <= 5)
        exit_usage();

    switch (argv[CLI_OP][0])
    {
    case 'e':
    case 'd':
        break;
    case '\0':
        printf("no operation provided!\n\n");
        exit_usage();
        break;
    case 's':
        printf("signing is not supported, yet\n\n");
        exit_usage();
        break;
    default:
        exit_usage();
    }

    if (strncmp("AES", argv[CLI_CIPHER], 3) != 0)
    {
        printf("cipher %s is not supported (, yet?)\n\n", argv[CLI_CIPHER]);
        exit_usage();
    }

    aes_router(argc, argv);

    return 0;
}

void exit_usage(void)
{
    printf("Usage: cmc-crypto <operation> <cipher> <key path> <input path> "
           "<output path> [cipher options...]\n");

    printf("\nOperations: (the program only checks the first char)\n");
    printf("\te, encrypt\n");
    printf("\td, decrypt\n");

    printf("\nAvailable ciphers, and specific options:\n");

    printf("\tAES-ECB[-PKCS#7]\n");
    printf("\tAES-CBC[-PKCS#7] <iv path>\n");
    printf("\tAES-OFB          <iv path>\n");

    printf("\nExamples:\n");

    printf("\tcmc-crypto encrypt AES-ECB key.bin foo.txt bar.bin\n");
    printf("\tcmc-crypto e AES-ECB-PKCS#7 key.bin foo.txt bar.bin\n");
    printf("\tcmc-crypto d AES-OFB key.bin bar.bin foo.txt iv.bin\n");

    exit(FATAL_GENERIC);
}

void aes_router(int argc, char** argv)
{
    int block_mode = __aes_mode_invalid;
    int pad_mode   = AES_PAD_NONE;
    int aes_ret_code;

    char* in_text = NULL;
    int   in_text_N;

    char* out_text = NULL;
    int   out_text_N;

    unsigned char* key = NULL;
    int            key_N;

    char* iv = NULL;
    int iv_N = 0; /* Before reading IV, tell if IV should be read; After reading
                     IV, tell its length*/

    if (strcmp(argv[CLI_CIPHER], "AES-ECB") == 0)
    {
        block_mode = AES_MODE_ECB;
    }
    else if (strcmp(argv[CLI_CIPHER], "AES-ECB-PKCS#7") == 0)
    {
        block_mode = AES_MODE_ECB;
        pad_mode   = AES_PAD_PKCS7;
    }
    else if (strcmp(argv[CLI_CIPHER], "AES-CBC") == 0)
    {
        if (argc < 7)
        {
            printf("no IV provided\n");
            exit_usage();
        }

        iv_N       = 1;
        block_mode = AES_MODE_CBC;
    }
    else if (strcmp(argv[CLI_CIPHER], "AES-CBC-PKCS#7") == 0)
    {
        if (argc < 7)
        {
            printf("no IV provided\n");
            exit_usage();
        }

        iv_N       = 1;
        block_mode = AES_MODE_CBC;
        pad_mode   = AES_PAD_PKCS7;
    }
    else if (strcmp(argv[CLI_CIPHER], "AES-OFB") == 0)
    {
        if (argc < 7)
        {
            printf("no IV provided\n");
            exit_usage();
        }

        iv_N       = 1;
        block_mode = AES_MODE_OFB;
    }

    if (block_mode == __aes_mode_invalid)
    {
        printf("invalid cipher: %s\n", argv[CLI_CIPHER]);
        exit_usage();
    }

    if (iv_N)
    {
        iv = read_all_content(argv[CLI_PATH_IV], &iv_N);
        if (iv_N != 16)
        {
            free(iv);
            printf("IV size must be 16 (found %d)\n", iv_N);
            exit(FATAL_GENERIC);
        }
    }

    in_text = read_all_content(argv[CLI_PATH_IN], &in_text_N);

    if (pad_mode == AES_PAD_NONE || argv[CLI_OP][0] == 'd')
    {
        out_text_N = in_text_N;
    }
    else
    {
        out_text_N = in_text_N + 16;
        out_text_N -= in_text_N % 16;
    }

    out_text = malloc((size_t)out_text_N);
    EXIT_EALLOC(out_text);

#ifdef DEBUG
    printf("in_text_N = %d, out_text_N = %d\n", in_text_N, out_text_N);
#endif

    key = (unsigned char*)read_all_content(argv[CLI_PATH_KEY], &key_N);

    if (argv[CLI_OP][0] == 'e')
        aes_ret_code = aes_encrypt(
            in_text,
            out_text,
            key,
            in_text_N,
            out_text_N,
            key_N,
            iv,
            pad_mode,
            block_mode
        );
    else if (argv[CLI_OP][0] == 'd')
        aes_ret_code = aes_decrypt(
            out_text,
            in_text,
            key,
            out_text_N,
            in_text_N,
            key_N,
            iv,
            pad_mode,
            block_mode
        );
    else
        aes_ret_code = 0;

    if (aes_ret_code == 0)
        write_all_content(
            out_text,
            argv[CLI_PATH_OUT],
            out_text_N,
            argv[CLI_OP][0] == 'e' ? AES_PAD_NONE : pad_mode
        );
    else
        printf("AES failed: %s\n", aes_err(aes_ret_code));

    if (iv != NULL)
        free(iv);

    if (in_text != NULL)
        free(in_text);

    if (out_text != NULL)
        free(out_text);

    if (key != NULL)
        free(key);
}

char* read_all_content(const char* path, int* r)
{
    const size_t N   = 1024;
    size_t       sz  = N;
    char*        buf = NULL;
    FILE*        fp  = fopen(path, "rb");

    if (fp == NULL)
    {
        printf("%s", strerror(errno));
        exit(errno);
    }

    for (*r = 0; !feof(fp);)
    {
        if (buf == NULL)
        {
            buf = malloc(sz);
        }
        else
        {
            sz  = sz * 2;
            buf = realloc(buf, sz);
        }

        if (buf == NULL)
        {
            printf("%s", strerror(errno));
            fclose(fp);
            exit(errno);
        }

        *r += (int)fread(buf + *r, 1, sz - (size_t)*r, fp);
    }

    fclose(fp);
    return buf;
}

void write_all_content(const char* buf, const char* path, int r, int pad_mode)
{
    int   wb;
    FILE* fp;

    if (r == 0)
        return;

    if (pad_mode == AES_PAD_PKCS7)
    {
        if ((unsigned char)buf[r - 1] > r)
            EXIT(FATAL_GENERIC, "write_all_content", "pad is incorrect");

        printf("padding of %d", buf[r - 1]);
        r -= (unsigned char)buf[r - 1];
    }

    fp = fopen(path, "wb");

    if (fp == NULL)
    {
        printf("%s", strerror(errno));
        exit(errno);
    }

    wb = (int)fwrite(buf, 1, (size_t)r, fp);

    if (wb != r)
    {
        printf("%s", strerror(errno));
        fclose(fp);
        exit(errno);
    }

    fclose(fp);
}
