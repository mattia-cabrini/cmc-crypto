#ifndef CMC_CRYPTO_ERROR_H_INCLUDED
#define CMC_CRYPTO_ERROR_H_INCLUDED

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define OK 0
#define FATAL_GENERIC 1
#define FATAL_LOGIC 2
#define NIY 3

#define EXIT(code, context, str)                                               \
    {                                                                          \
        fprintf(stderr, "%s: %s\n", (context), (str));                         \
        exit((code));                                                          \
    }

#define EXIT_EALLOC(ptr)                                                       \
    {                                                                          \
        if ((ptr) == NULL)                                                     \
        {                                                                      \
            printf("%s\n", strerror(errno));                                   \
            exit(1);                                                           \
        }                                                                      \
    }

#define NN(n) __attribute__((nonnull(n)))

#endif /* CMC_CRYPTO_ERROR_H_INCLUDED */
