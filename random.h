#ifndef CMC_CRYPTO_RANDOM
#define CMC_CRYPTO_RANDOM

#include <stddef.h>

#ifndef RANDOM_BUFFER_SIZE
#define RANDOM_BUFFER_SIZE 1024
#endif

/** Thread UNSAFE */
extern void random_get_buffer(char* buf, size_t size);

#endif /* CMC_CRYPTO_RANDOM */
