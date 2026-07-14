#ifndef TEST_H
#define TEST_H


#include <stdio.h>


#define TEST_ASSERT(expression)                                           \
    do {                                                                  \
        if (!(expression)) {                                              \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__,           \
                #expression);                                             \
            return 1;                                                     \
        }                                                                 \
    } while (0)


#endif /* TEST_H */
