#include <libcpu.h>
#include <evset.h>

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

/*
 * Target buffer
 */
uint8_t target[128] __attribute__((aligned(64)));

/*
 * Victim function variables
 */
uint8_t temp = 0; // Used so compiler won’t optimize out victim_function()
int idx = 0;

/*
 * Victim function for the eviction set determination
 */
void victim_function(void) {
    temp &= target[idx];
}

int main(int argc, char **argv) {
    cache_t *cache = cpu_cacheInit(L3);
    size_t shmSize = cache->info.size * 24;
    void *shm_ptr = (void*) malloc(shmSize * sizeof(uint8_t)); // initSharedMemory(shmSize);
    uint8_t *cur = (uint8_t*) shm_ptr;
    for (size_t i = 0; i < shmSize; i++) {
        *(cur + i) = 0;
    }

    uintptr_t addr = (uintptr_t) target;
    uintptr_t phyAddr = cpu_getPhysAddr((uintptr_t*) addr);

    addr_list_t testCandidates;
    initAddrList(&testCandidates);

    cpu_warm_up(1000000);

    unsigned int phySetIndex = getSetIndexBits(phyAddr, cache->info.sets_log,
            cache->info.linesize_log);

    EvSetSearchResult_t evSetFindingResult;
    for (int i = 0; i < 1024; i++) {
        evSetFindingResult = findEvictionSetsLlc(i, cache,
                &testCandidates, shm_ptr, shmSize);
    }

    if (evSetFindingResult != OK) {
        fprintf(stdout, "\n\nError finding eviction sets. Code: %d\n",
                evSetFindingResult);
    } else {
        if (validateEvictionSetsLlcForAllSlices(&testCandidates, cache,
                phySetIndex) == VALID) {
            fprintf(stdout, "\n\nValidation: Eviction Sets found :-)\n");
            fprintf(stdout, "\n\nDetermine eviction set for virt address 0x%lx "
                    "(phys: 0x%lx, set index: 0x%x)\n", addr, phyAddr,
                    phySetIndex);
            int sliceIndex = getEvictionSetForAddress(addr, cache, phySetIndex);

            if (sliceIndex >= 0) {
                fprintf(stdout, "Set for slice %d evicts target address.\n\n",
                        sliceIndex);

                // Prime and probe forward
                cpu_prime_pointer_chasing(
                        cache->ev_sets[phySetIndex][sliceIndex].start);
                cpu_maccess(addr);
                uint64_t probingTime = cpu_probe_pointer_chasing(
                        cache->ev_sets[phySetIndex][sliceIndex].start);

                fprintf(stdout, "\n\nPrime and Probe:\n\nProbing time: %lu\n\n",
                        probingTime);

                // Prime and probe with reverse pointer chasing during probing
                cpu_prime_pointer_chasing(
                        cache->ev_sets[phySetIndex][sliceIndex].start);
                cpu_maccess(addr);
                probingTime = cpu_probe_pointer_chasing(
                        cache->ev_sets[phySetIndex][sliceIndex].startReverse);

                fprintf(stdout, "\n\nPrime and Probe (Reverse):\n\n"
                        "Probing time: %lu\n\n", probingTime);
            } else {
                fprintf(stdout, "Unexpected error, no slice evicts "
                        "target address!");
            }
        } else {
            fprintf(stdout,
                    "\n\nValidation: Determined sets for address 0x%lx and "
                            "cache index 0x%x are no eviction sets :-(\n", addr,
                    getSetIndexBits(addr, cache->info.sets_log,
                            cache->info.linesize_log));
        }
    }

    freeAddrListEntries(&testCandidates);
    cpu_cacheFree(cache);
    // freeSharedMemory(shm_ptr, shmSize);
    free(shm_ptr);
}

