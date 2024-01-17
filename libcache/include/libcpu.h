#ifndef LIBCPU_H__
#define LIBCPU_H__

#include <stdint.h>
#include <stdlib.h>
#include <immintrin.h> // _mm_?fence(), _mm_clflush()
#include <x86intrin.h> // _rdtsc*()
#include <cpuid.h>     // __cpuid_count()

#include <list.h>

//** Type definitions **//
struct ev_set_s {
    uint8_t used;
    uint32_t index;
    uint32_t slice;
    uint32_t num_addrs;
    volatile void *start; // Pointer chasing start
    volatile void *probeTimeForward;
    volatile void *startReverse;
    volatile void **addrs; // Array with addresses
};
typedef struct ev_set_s ev_set_t;

enum cache_name_e {
    L1I, L1D, L2, L3
};
typedef enum cache_name_e cache_name_t;

struct cache_info_s {
    uint32_t linesize_log;
    uint32_t linesize;
    uint32_t sets_log;
    uint32_t sets;
    uint32_t slices;
    uint32_t partitions;
    uint32_t ways;
    uint64_t size;
};
typedef struct cache_info_s cache_info_t;

struct cache_s {
    cache_name_t name;
    uint64_t threshold;
    cache_info_t info;
    ev_set_t **ev_sets;
};
typedef struct cache_s cache_t;

//** Intrinsic function macro wrapper **//
/* Insert lfence insturction */
#define cpu_lfence() _mm_lfence()
/* Insert sfence instruction */
#define cpu_sfence() _mm_sfence()
/* Insert mfence instruction */
#define cpu_mfence() _mm_mfence()
/* Read TSC register */
#define cpu_rdtsc() _rdtsc()
/* Fenced TSC register read */
#define cpu_rdtscp() __rdtscp()
/* Mfenced TSC register read */
#define cpu_mfence_rdtsc() ({uint64_t _val;cpu_mfence();_val=cpu_rdtsc();_val; })
/* Flush a given address */
#define cpu_clflush(_addr) _mm_clflush(_addr)

//** Assembler function declarations **//
/* Busy wait for num_iter cycles */
extern void cpu_warm_up(uint64_t num_iter);
/* Flush a given address */
//extern void cpu_clflush (void *addr);
/* Mfenced TSC register read */
//extern uint64_t cpu_rdtsc (void);
/* Fenced TSC register read */
//extern uint64_t cpu_rdtscp (void);
/* Access a given address */
extern void cpu_maccess(uintptr_t addr);
/* Time memory access to the given address */
extern uint64_t cpu_maccess_time(uintptr_t addr);
/* Access linked eviction set list for length addresses */
extern void cpu_prime_pointer_chasing_n(volatile void *ptr, size_t length);
/* Access linked eviction set list until NULL address */
extern void cpu_prime_pointer_chasing(volatile void *ptr);
/* Access eviction set addresses in array */
extern void cpu_prime_array(volatile void **array_ptr, size_t length);
/* Access and time linked eviction set list for length addresses */
extern uint64_t cpu_probe_pointer_chasing_n(volatile void *ptr, size_t length);
/* Access and time linked eviction set list until NULL address */
extern uint64_t cpu_probe_pointer_chasing(volatile void *ptr);
extern void cpu_probe_pointer_chasing_store(volatile void *ptr,
        volatile void *store_target);
/* Access and time eviction set addresses in array */
extern uint64_t cpu_probe_array(volatile void **array_ptr, size_t length);

//** C function declarations **//
/* Initialize a cache_t structure for a given cache name */
cache_t* cpu_cacheInit(cache_name_t name);
/* Fill an eviction set structure using the results from libscan */
void cpu_cacheFillEvSet(cache_t *cache, addr_list_t *eviction_set, int index,
        int slice);
void cpu_cacheFillEvSetRandomize(cache_t *cache, addr_list_t *eviction_set,
        int index, int slice);
void cpu_fillEvSet(volatile void **start, volatile void **startReverse,
        volatile void **probeTime, addr_list_t *eviction_set);
void cpu_fillEvSetRandomized(volatile void **start,
        volatile void **startReverse, volatile void **probeTime,
        addr_list_t *eviction_set);
/* Free a cache_t structure */
void cpu_cacheFree(cache_t *cache);
/* Get the cache set a physical address is mapped to in the given cache */
uint64_t cpu_getCacheSet(uint64_t paddr, cache_t *cache);
/* REQUIRES ROOT: Get the physical address for a virtual address */
uint64_t cpu_getPhysAddr(void *addr);
/* Create a shared memory region of a given size (name has to start with '/') */
void* cpu_createSharedMemory(const char *name, size_t size);
/* Remove a shared memory region */
void cpu_removeSharedMemory(const char *name, void *addr, size_t size);
/* Attach to a shared memory region */
void* cpu_attachSharedMemory(const char *name, size_t size);
/* Detach from a shared memory region */
void cpu_detachSharedMemory(void *ptr, size_t size);

#endif
