#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block_cipher.h"
#include "error.h"
#include "io.h"

void io_read_all_content(io_buffer_p B, const char* path)
{
    FILE* fp;

    fp = fopen(path, "rb");

    if (fp == NULL)
    {
        printf(
            "io_read_all_content: could not open %s; %s\n",
            path,
            strerror(errno)
        );
        exit(errno);
        return;
    }

    B->N = fseek(fp, 0, SEEK_END);

    if (B->N == -1)
    {
        B->N = errno;
        printf("io_read_all_content: seek failed; %s\n", strerror(B->N));
        fclose(fp);
        exit(B->N);
        return;
    }

    B->N = (int)ftell(fp);
    if (B->N == -1)
    {
        B->N = errno;
        printf("io_read_all_content: tell failed; %s\n", strerror(B->N));
        fclose(fp);
        exit(B->N);
        return;
    }

    B->buf = malloc((size_t)B->N);
    if (B->buf == NULL)
    {
        B->N = errno;
        printf("io_read_all_content: malloc failed; %s\n", strerror(B->N));
        fclose(fp);
        exit(B->N);
        return;
    }

    if (fseek(fp, 0, SEEK_SET) == -1)
    {
        B->N = errno;
        printf("io_read_all_content: seek failed; %s\n", strerror(B->N));
        fclose(fp);
        exit(B->N);
        return;
    }

    if (fread(B->buf, 1, (size_t)B->N, fp) != (size_t)B->N)
    {
        B->N = errno;
        printf("io_read_all_content: read failed; %s\n", strerror(B->N));
        fclose(fp);
        exit(B->N);
        return;
    }

    fclose(fp);

#ifdef DEBIG
    printf("io_read_all_content: read %d from %s\n", B->N, path);
#endif

    return;
}

void io_write_all_content(io_buffer_p B, const char* path, int pad_mode)
{
    int   wb;
    FILE* fp;

    int to_print = B->N;

    if (to_print == 0)
        return;

    if (pad_mode == PAD_PKCS7)
    {
        if ((unsigned char)B->buf[to_print - 1] > to_print)
            EXIT(FATAL_GENERIC, "io_write_all_content", "pad is incorrect");

#ifdef DEBUG
        printf("padding of %d", B->buf[to_print - 1]);
#endif

        to_print -= (unsigned char)B->buf[to_print - 1];
    }

    fp = fopen(path, "wb");

    if (fp == NULL)
    {
        printf("%s", strerror(errno));
        exit(errno);
    }

    wb = (int)fwrite(B->buf, 1, (size_t)to_print, fp);

    if (wb != to_print)
    {
        to_print = errno;
        printf("io_write_all_content: %s", strerror(to_print));
        fclose(fp);
        exit(to_print);
    }

    fclose(fp);
}

void io_buffer_alloc(io_buffer_p B, int N)
{
    B->N = N;

    if (B->N == 0)
    {
        B->buf = NULL;
        return;
    }

    B->buf = malloc((size_t)B->N);
    if (B->buf == NULL)
    {
        B->N = errno;
        printf("io_buffer_alloc: %s", strerror(B->N));
        exit(B->N);
        return;
    }
}

void io_buffer_free(io_buffer_p B)
{
    if (B->buf == NULL)
        return;

    free(B->buf);
    B->buf = NULL;
    B->N   = 0;
}
