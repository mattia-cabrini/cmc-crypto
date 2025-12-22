#include <stdio.h>

#include "random.h"

int main(int argc, char** argv)
{
    int V[10];
    int i;

    (void)argc;
    (void)argv;

    random_get_buffer((char*)V, sizeof(V));
    for (i = 0; i < 10; ++i)
        printf("%d\n", V[i]);

    return 0;
}
