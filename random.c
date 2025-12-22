#include "random.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * THREAD UNSAFE
 */

int  fd = -1;
int  cur;
char random_buffer[RANDOM_BUFFER_SIZE];

static void random_open(void);
static void random_load(void);

void random_get_buffer(char* buf, size_t size)
{
    size_t i;

    if (buf == NULL)
        return;

    if (fd == -1)
    {
        random_open();
    }

    for (i = 0; i < size;)
    {
        for (; cur < RANDOM_BUFFER_SIZE && i < size; ++i)
        {
            buf[i] = random_buffer[cur];
            ++cur;
        }

        if (i < size)
            random_load();
    }
}

static void random_open(void)
{
    int errno_hold;

    if (fd != -1)
        return;

    fd = open("/dev/urandom", O_RDONLY, 0444);
    if (fd == -1)
    {
        errno_hold = errno;
        fprintf(
            stderr, "random_open: %d - %s", errno_hold, strerror(errno_hold)
        );
        exit(errno_hold);
    }

    cur = RANDOM_BUFFER_SIZE;
}

static void random_load(void)
{
    int errno_hold;

    if (read(fd, random_buffer, RANDOM_BUFFER_SIZE) != RANDOM_BUFFER_SIZE)
    {
        errno_hold = errno;
        fprintf(
            stderr, "random_load: %d - %s", errno_hold, strerror(errno_hold)
        );
        exit(errno_hold);
    }

    cur = 0;
}
