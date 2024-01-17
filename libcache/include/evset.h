#ifndef EVSET_H__
#define EVSET_H__

#include <list.h>
#include <libcpu.h>

#include <unistd.h>

typedef enum EvSetSearchResult {
    OK, CONFLICT_SET_INCOMPLETE, UNABLE_TO_SPLIT_TO_EVICTION_SETS, ERROR
} EvSetSearchResult_t;

typedef enum EvSetValidationResult {
    VALID, FOUND_SET_IS_NO_EVSET, FOUND_SETS_ARE_NO_EVSETS
} EvSetValidationResult_t;

unsigned int getSetIndexBits(uintptr_t addr, unsigned int setIndexBits,
        unsigned int lineIndexBits);

void* initSharedMemory(size_t shmSizeInBytes);

void freeSharedMemory(void *addr, size_t shmSizeInBytes);

EvSetSearchResult_t findEvictionSetsLlc(unsigned int setIndexBits,
        cache_t *cache, addr_list_t *testCandidates, void *shm_ptr,
        size_t shm_size);

/*Assumes that the cache object was already filled with the eviction sets
 * for addresse's set index using findEvitionSetsLlc()
 *
 * @return slice index or -1 for error
 * */
int getEvictionSetForAddress(uintptr_t addr, cache_t *cache,
        unsigned int setIndex);

EvSetValidationResult_t validateEvictionSetLlc(uintptr_t testCandidate,
        cache_t *cache, unsigned int setIndex, unsigned int slice);
EvSetValidationResult_t validateEvictionSetsLlcForAllSlices(
        addr_list_t *testCandidates, cache_t *cache, unsigned int setIndex);

#endif
