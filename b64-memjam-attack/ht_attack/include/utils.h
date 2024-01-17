#ifndef __UTILS_H
#define __UTILS_H

#include <stdint.h>

#define ASSERT(cond)                                                    \
    do {                                                                \
        if (!(cond))                                                    \
        {                                                               \
            perror("[" __FILE__ "] assertion '" #cond "' failed");      \
            abort();                                                    \
        }                                                               \
    } while(0)


uintptr_t getPhysAddr(void *addr);

unsigned int getSetIndexBits(uintptr_t addr, unsigned int setIndexBits,
        unsigned int lineIndexBits);

#endif
