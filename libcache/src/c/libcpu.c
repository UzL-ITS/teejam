//** Includes **//
#include <fcntl.h> /* For O_* constants */
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h> /* For shm_* functions */
#include <sys/stat.h> /* For mode constants */

#include "libcpu.h"

int _cpu_getPhysicalCores() {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) {
        return 0;
    }
    char *line = NULL;

    int cores[256] = { 0 };
    size_t len = 0;
    while (getline(&line, &len, f) != -1) {
        if (strncmp(line, "core id", 7) == 0) {
            int id = 0;
            sscanf(strrchr(line, ':') + 1, "%d", &id);
            if (id >= 0 && id < 256) {
                cores[id]++;
            }
        }
    }
    free(line);
    fclose(f);

    int phys_cores = 0;
    int i;
    for (i = 0; i < 256; i++) {
        if (cores[i]) {
            phys_cores++;
        }
    }
    return phys_cores;
}

cache_info_t _cpu_getCacheInfo(cache_name_t name) {
    cache_info_t info;
    int leaf = 4, subleaf = 0, eax = 0, ebx = 0, ecx = 0, edx = 0;
    switch (name) {
    case L1D:
        subleaf = 0;
        info.slices = 1;
        break;
    case L1I:
        subleaf = 1;
        info.slices = 1;
        break;
    case L2:
        subleaf = 2;
        info.slices = 1;
        break;
    case L3:
        subleaf = 3;
        // info.slices = _cpu_getPhysicalCores() * 2;
        info.slices = 8;
        break;
    }
    __cpuid_count(leaf, subleaf, eax, ebx, ecx, edx);
    info.linesize = ((ebx >> 0) & 0xFFF) + 1;
    info.linesize_log = _bit_scan_reverse(info.linesize);
    info.partitions = ((ebx >> 12) & 0x3FF) + 1;
    info.ways = ((ebx >> 22) & 0x3FF) + 1;
    info.sets = (((ecx >> 0) & 0xFFFFFFFF) + 1) / info.slices;
    info.sets_log = _bit_scan_reverse(info.sets);
    info.size = info.linesize * info.sets * info.slices * info.ways;
    return info;
}

uint64_t _cpu_getL1Threshold() {
    return 10;
}

uint64_t _cpu_getL2Threshold() {
    return 25;
}

uint64_t _cpu_getL3Threshold() {
    return 100;
}

cache_t* cpu_cacheInit(cache_name_t name) {
    cache_info_t info = _cpu_getCacheInfo(name);
    cache_t *cache = calloc(1, sizeof(cache_t));
    cache->name = name;
    cache->info = info;
    cache->ev_sets = calloc(info.sets, sizeof(ev_set_t*));
    int i;
    for (i = 0; i < info.sets; ++i) {
        cache->ev_sets[i] = calloc(info.slices, sizeof(ev_set_t));
    }
    switch (name) {
    case L1D:
    case L1I:
        cache->threshold = _cpu_getL1Threshold();
        break;
    case L2:
        cache->threshold = _cpu_getL2Threshold();
        break;
    case L3:
        cache->threshold = _cpu_getL3Threshold();
    }
    return cache;
}

void cpu_fillEvSet(volatile void **start, volatile void **startReverse,
        volatile void **probeTime, addr_list_t *eviction_set) {

    if (eviction_set->length > 0) {

        if (probeTime != 0) {
            // setting storage location for probing time
            *probeTime = ((uintptr_t*) eviction_set->first->addr) + 7;
        }

        // forward
        *start = (uintptr_t*) eviction_set->first->addr;
        volatile uintptr_t *p = *start;

        for (addr_list_entry_t *e = eviction_set->first; e->next != NULL;
                e = e->next) {

            *p = e->next->addr;
            p = (uintptr_t*) *p;
        }
        *p = 0;

        // backward
        if (startReverse != 0) {
            *startReverse = ((uintptr_t*) eviction_set->last->addr) + 1;
            volatile uintptr_t *pReverse = *startReverse;

            for (addr_list_entry_t *e = eviction_set->last; e->prev != NULL; e =
                    e->prev) {

                *pReverse = e->prev->addr + sizeof(uintptr_t);
                pReverse = (uintptr_t*) *pReverse;
            }
            *pReverse = 0;
        }
    } else {
        *start = 0;
        if (startReverse != 0) {
            *startReverse = 0;
        }
        if (probeTime != 0) {
            *probeTime = 0;
        }
    }
}

void cpu_fillEvSetRandomized(volatile void **start,
        volatile void **startReverse, volatile void **probeTime,
        addr_list_t *eviction_set) {

    if (eviction_set->length > 0) {

        if (probeTime != 0) {
            // setting storage location for probing time
            *probeTime = ((uintptr_t*) eviction_set->first->addr) + 7;
        }

        // Randomizing list
        uintptr_t *addresses = (uintptr_t*) calloc(eviction_set->length,
                sizeof(uintptr_t));
        uint64_t seed = cpu_rdtsc();
        srandom((unsigned int) seed);

        int i = 0;
        for (addr_list_entry_t *e = eviction_set->first; e != 0; e = e->next) {
            unsigned int index = random() % eviction_set->length;
            if (addresses[index] == 0) {
                addresses[index] = e->addr;
            } else {
                while (addresses[i] != 0) {
                    i++;
                }
                addresses[i] = e->addr;
            }
        }

        // forward
        *start = (uintptr_t*) addresses[0];
        volatile uintptr_t *p = *start;

        for (int j = 1; j < eviction_set->length; j++) {
            *p = addresses[j];
            p = (uintptr_t*) *p;
        }
        *p = 0;

        //backward
        if (startReverse != 0) {
            *startReverse = ((uintptr_t*) addresses[eviction_set->length - 1])
                    + 1;
            volatile uintptr_t *pReverse = *startReverse;

            for (int j = eviction_set->length - 2; j >= 0; j--) {
                *pReverse = addresses[j] + sizeof(uintptr_t);
                pReverse = (uintptr_t*) *pReverse;
            }
            *pReverse = 0;
        }

        free(addresses);
    } else {
        *start = 0;
        if (startReverse != 0) {
            *startReverse = 0;
        }
        if (probeTime != 0) {
            *probeTime = 0;
        }
    }
}

void cpu_cacheFillEvSetRandomize(cache_t *cache, addr_list_t *eviction_set,
        int index, int slice) {

    if (index < cache->info.sets && slice < cache->info.slices) {
        cache->ev_sets[index][slice].index = index;
        cache->ev_sets[index][slice].slice = slice;

        cpu_fillEvSetRandomized(&(cache->ev_sets[index][slice].start),
                &(cache->ev_sets[index][slice].startReverse),
                &(cache->ev_sets[index][slice].probeTimeForward), eviction_set);
    }
}

void cpu_cacheFillEvSet(cache_t *cache, addr_list_t *eviction_set, int index,
        int slice) {

    if (index < cache->info.sets && slice < cache->info.slices) {
        cache->ev_sets[index][slice].index = index;
        cache->ev_sets[index][slice].slice = slice;

        cpu_fillEvSet(&(cache->ev_sets[index][slice].start),
                &(cache->ev_sets[index][slice].startReverse),
                &(cache->ev_sets[index][slice].probeTimeForward), eviction_set);
    }
}

void cpu_cacheFree(cache_t *cache) {
    int i;
    for (i = 0; i < cache->info.sets; ++i) {
        free(cache->ev_sets[i]);
    }
    free(cache->ev_sets);
    free(cache);
}

uint64_t cpu_getCacheSet(uint64_t paddr, cache_t *cache) {
    uint64_t mask = ((uint64_t) 1
            << (cache->info.sets_log + cache->info.linesize_log)) - 1;
    return (paddr & mask) >> 6;
}

uintptr_t cpu_getPhysAddr(void *addr) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    assert(fd >= 0);
    cpu_maccess((uintptr_t) addr);
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

void* cpu_createSharedMemory(const char *name, size_t size) {
    int fd;
    if ((fd = shm_open(name, O_RDWR | O_CREAT, 0660)) == -1) {
        fprintf(stderr, "[cpu_crShMem] ERROR: shm_open() failed!\n");
        return (void*) -1;
    }
    if (ftruncate(fd, size) == -1) {
        fprintf(stderr, "[cpu_crShMem] ERROR: ftruncate() failed!\n");
        return (void*) -1;
    }
    void *ptr;
    int flags = MAP_SHARED;
    int protection = PROT_READ | PROT_WRITE;
    if ((ptr = mmap(NULL, size, protection, flags, fd, 0)) == MAP_FAILED) {
        fprintf(stderr, "[cpu_crShMem] ERROR: mmap() failed!\n");
        return (void*) -1;
    }
    return ptr;
}

void cpu_removeSharedMemory(const char *name, void *addr, size_t size) {
    if (munmap(addr, size) == -1) {
        fprintf(stderr, "[cpu_rmShMem] ERROR: munmap failed!\n");
    }
    if (shm_unlink(name) == -1) {
        fprintf(stderr, "[cpu_rmShMem] ERROR: shm_unlink() failed!\n");
    }
}

void* cpu_attachSharedMemory(const char *name, size_t size) {
    int fd;
    if ((fd = shm_open(name, O_RDWR, 0)) == -1) {
        fprintf(stderr, "[cpu_attShMem] ERROR: shm_open() failed!\n");
        return (void*) -1;
    }
    void *ptr;
    int flags = MAP_SHARED;
    int protection = PROT_READ | PROT_WRITE;
    if ((ptr = mmap(NULL, size, protection, flags, fd, 0)) == MAP_FAILED) {
        fprintf(stderr, "[cpu_attShMem] ERROR: mmap failed!\n");
        return (void*) -1;
    }
    return ptr;
}

void cpu_detachSharedMemory(void *ptr, size_t size) {
    if (munmap(ptr, size) == -1) {
        fprintf(stderr, "[cpu_detShMem] ERROR: munmap failed!\n");
    }
}
