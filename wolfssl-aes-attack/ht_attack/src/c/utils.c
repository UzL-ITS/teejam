#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>

#include "utils.h"

uintptr_t getPhysAddr(void *addr) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    assert(fd >= 0);
    uint8_t tmp = *((uint8_t*) addr);
    assert(tmp >= 0);

    uintptr_t virtual_addr = (uintptr_t) addr;
    uintptr_t value = 0;
    uintptr_t offset = (virtual_addr / getpagesize()) * sizeof(value);
    if (pread(fd, &value, sizeof(value), offset) == -1) {
        fprintf(stderr,
                "[cpu_getPhysAddr] ERROR while reading pagemap file.\n");
        value = 0;
    }
    close(fd);
    if ((value << 12) <= 0) {
        fprintf(stderr,
                "[cpu_getPhysAddr] WARNING: You must be root to access the pagemap file!\n");
    }
    return (value << 12) | ((size_t) addr & 0xFFFULL);
}

unsigned int getSetIndexBits(uintptr_t addr, unsigned int setIndexBits,
        unsigned int lineIndexBits) {

    unsigned setMask = ((1 << setIndexBits) - 1) << lineIndexBits;
    return (addr & setMask) >> lineIndexBits;
}
