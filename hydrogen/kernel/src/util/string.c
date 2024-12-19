#include <stddef.h>

int strcmp(const char *s1, const char *s2) {
    size_t i = 0;

    for (;;) {
        unsigned char c1 = s1[i];
        unsigned char c2 = s2[i];

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
        if (c1 == 0) return 0;

        i += 1;
    }
}
