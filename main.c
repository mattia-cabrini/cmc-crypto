#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "error.h"
#include "io.h"

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

/*
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
    int pad_mode   = PAD_NONE;
    int aes_ret_code;

    struct io_buffer_t input_text;
    struct io_buffer_t output_text;
    struct io_buffer_t key;
    struct io_buffer_t iv; /* Before reading IV, tell if IV should be read;
                              After reading IV, tell its length*/

    io_buffer_alloc(&iv, 0);

    if (strcmp(argv[CLI_CIPHER], "AES-ECB") == 0)
    {
        block_mode = MODE_ECB;
    }
    else if (strcmp(argv[CLI_CIPHER], "AES-ECB-PKCS#7") == 0)
    {
        block_mode = MODE_ECB;
        pad_mode   = PAD_PKCS7;
    }
    else if (strcmp(argv[CLI_CIPHER], "AES-CBC") == 0)
    {
        if (argc < 7)
        {
            printf("no IV provided\n");
            exit_usage();
        }

        iv.N       = 1;
        block_mode = MODE_CBC;
    }
    else if (strcmp(argv[CLI_CIPHER], "AES-CBC-PKCS#7") == 0)
    {
        if (argc < 7)
        {
            printf("no IV provided\n");
            exit_usage();
        }

        iv.N       = 1;
        block_mode = MODE_CBC;
        pad_mode   = PAD_PKCS7;
    }
    else if (strcmp(argv[CLI_CIPHER], "AES-OFB") == 0)
    {
        if (argc < 7)
        {
            printf("no IV provided\n");
            exit_usage();
        }

        iv.N       = 1;
        block_mode = MODE_OFB;
    }

    if (block_mode == __aes_mode_invalid)
    {
        printf("invalid cipher: %s\n", argv[CLI_CIPHER]);
        exit_usage();
    }

    if (iv.N)
    {
        io_read_all_content(&iv, argv[CLI_PATH_IV]);
        if (iv.N != 16)
        {
            io_buffer_free(&iv);
            printf("IV size must be 16 (found %d)\n", iv.N);
            exit(FATAL_GENERIC);
        }
    }

    io_read_all_content(&input_text, argv[CLI_PATH_IN]);

    if (pad_mode == PAD_NONE || argv[CLI_OP][0] == 'd')
    {
        output_text.N = input_text.N;
    }
    else
    {
        output_text.N = input_text.N + 16;
        output_text.N -= input_text.N % 16;
    }

    io_buffer_alloc(&output_text, output_text.N);

#ifdef DEBUG
    printf(
        "input_text.N = %d, output_text.N = %d\n", input_text.N, output_text.N
    );
#endif

    io_read_all_content(&key, argv[CLI_PATH_KEY]);

    if (argv[CLI_OP][0] == 'e')
        aes_ret_code = aes_encrypt(
            input_text.buf,
            output_text.buf,
            (unsigned char*)key.buf,
            input_text.N,
            output_text.N,
            key.N,
            iv.buf,
            pad_mode,
            block_mode
        );
    else if (argv[CLI_OP][0] == 'd')
        aes_ret_code = aes_decrypt(
            output_text.buf,
            input_text.buf,
            (unsigned char*)key.buf,
            output_text.N,
            input_text.N,
            key.N,
            iv.buf,
            pad_mode,
            block_mode
        );
    else
        aes_ret_code = 0;

    if (aes_ret_code == 0)
        io_write_all_content(
            &output_text,
            argv[CLI_PATH_OUT],
            argv[CLI_OP][0] == 'e' ? PAD_NONE : pad_mode
        );
    else
        printf("AES failed: %s\n", aes_err(aes_ret_code));

    io_buffer_free(&input_text);
    io_buffer_free(&output_text);
    io_buffer_free(&key);
    io_buffer_free(&iv);
}
