#ifndef CMC_CRYPTO_IO_INCLUDED
#define CMC_CRYPTO_IO_INCLUDED

typedef struct io_buffer_t
{
    char* buf;
    int   N;
}* io_buffer_p;

/* Read all file content and put it in a buffer. */
void io_read_all_content(io_buffer_p B, const char* path);

/* Write a buffer to a file, panic in case of failure. */
void io_write_all_content(io_buffer_p B, const char* path, int pad_mode);

void io_buffer_alloc(io_buffer_p B, int N);
void io_buffer_free(io_buffer_p B);

#endif /* CMC_CRYPTO_IO_INCLUDED */
