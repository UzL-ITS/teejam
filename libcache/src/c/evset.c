#include <evset.h>

#include <stdio.h>

const char *shm_name = "eviction_set_finding";

unsigned int getSetIndexBits(uintptr_t addr, unsigned int setIndexBits,
        unsigned int lineIndexBits) {

    unsigned setMask = ((1 << setIndexBits) - 1) << lineIndexBits;
    return (addr & setMask) >> lineIndexBits;
}

uint64_t getTagBits(uintptr_t addr, unsigned int setIndexBits,
        unsigned int lineIndexBits) {

    uint64_t tagMask = 0xffffffffffffffff
            ^ ((1 << (setIndexBits + lineIndexBits)) - 1);
    return (addr & tagMask) >> (lineIndexBits + setIndexBits);
}

void* initSharedMemory(size_t shmSizeInByte) {
    void *shmPtr = cpu_createSharedMemory(shm_name, shmSizeInByte);
    return shmPtr;
}

void freeSharedMemory(void *addr, size_t shmSizeInByte) {
    cpu_removeSharedMemory(shm_name, addr, shmSizeInByte);
}

void printCacheInfo(cache_t *cache) {
    fprintf(stdout, "\nCache Info:\n"
            "Ways: %u\t\tSlices: %u\t\tSize: %lu\n"
            "Sets: %u\t\tSets log: %u\t\tLine size: %u"
            "\t\tLine Size log: %u\n\n", cache->info.ways, cache->info.slices,
            cache->info.size, cache->info.sets, cache->info.sets_log,
            cache->info.linesize, cache->info.linesize_log);
}

void printAddressSet(addr_list_t *addresses, const char *title, cache_t *cache) {
    fprintf(stdout, "\n%s", title);
    fprintf(stdout, "\nSize of set: %u\n\n", addresses->length);

    addr_list_entry_t *elem = addresses->first;
    int j = 0;
    while (elem) {
        j++;
        uintptr_t phyAddr = cpu_getPhysAddr((uintptr_t*) elem->addr);
        fprintf(stdout,
                "[#%2d] Virt: 0x%lx\t\tPhys: 0x%lx\t\tSet index: 0x%x\t\t"
                        "Tag bits: 0x%lx\n", j, elem->addr, phyAddr,
                getSetIndexBits(phyAddr, cache->info.sets_log,
                        cache->info.linesize_log),
                getTagBits(phyAddr, cache->info.sets_log,
                        cache->info.linesize_log));
        elem = elem->next;
    }
}

void printEvictionSets(addr_list_t *evSets, cache_t *cache) {
    fprintf(stdout, "\n\nEviction Sets:\n");
    for (int k = 0; k < cache->info.slices; k++) {
        char strBuf[16];
        snprintf(strBuf, 16, "Eviction Set %d", k);
        printAddressSet(&(evSets[k]), strBuf, cache);
    }
}

int probeEvicted(uintptr_t candidate, volatile void *evSet1, uint64_t threshold) {
    uint64_t accessTime = 0;

    cpu_maccess(candidate);

    if (evSet1 == 0) {
        return 0;
    } else {
        do {
            cpu_prime_pointer_chasing(evSet1);
            cpu_prime_pointer_chasing(evSet1);
            cpu_prime_pointer_chasing(evSet1);
            cpu_prime_pointer_chasing(evSet1);
            accessTime = cpu_maccess_time(candidate);
        } while (accessTime > 350);
        // fprintf(stdout, "Access time (0x%lx): %lu (%lu)\n", candidate,
        //          accessTime, threshold);
        return accessTime > threshold ? 1 : 0;
    }
}

void buildCandidateSet(unsigned int setIndexBits, addr_list_t *evSetCandidates,
        cache_t *cache, void *shm_ptr, size_t shmSizeInByte) {

    uint8_t *cur = (uint8_t*) shm_ptr;
    unsigned desiredCandidateCount = cache->info.ways * cache->info.slices * 32;

    for (size_t i = 0;
            i < (shmSizeInByte - cache->info.linesize)
                    && evSetCandidates->length < desiredCandidateCount; i +=
                    cache->info.linesize) {
        uintptr_t phyAddr = cpu_getPhysAddr(cur + i);
        // fprintf(stdout, "Checking virt: %p with phy: 0x%lx\n", cur + i, phyAddr);
        if (getSetIndexBits(phyAddr, cache->info.sets_log,
                cache->info.linesize_log) == setIndexBits) {
            insert_end(evSetCandidates, (uintptr_t) (cur + i));
        }
    }
}

EvSetSearchResult_t determineConflictSet(addr_list_t *evSetCandidates,
        addr_list_t *conflictSet, cache_t *cache) {
    volatile void *conflictSetChase1;

    // fprintf(stdout, "\n\nMeasurements:\n");
    for (addr_list_entry_t *e = evSetCandidates->first; e != 0; e = e->next) {
        cpu_fillEvSetRandomized(&conflictSetChase1, 0, 0, conflictSet);
        if (!probeEvicted(e->addr, conflictSetChase1, cache->threshold)) {
            insert_end(conflictSet, e->addr);
        }
    }

    if (conflictSet->length != cache->info.slices * cache->info.ways) {
        return CONFLICT_SET_INCOMPLETE;
    } else {
        return OK;
    }
}

void removeSet1FromSet2(addr_list_t *set1, addr_list_t *set2) {

    for (addr_list_entry_t *e = set1->first; e != 0; e = e->next) {
        addr_list_entry_t *entryToRemove = find_by_address_member(set2,
                e->addr);
        remove_middle(set2, entryToRemove);
    }
}

int checkCorrectSizeOfAllEvictionSets(cache_t *cache, addr_list_t *evSets) {
    int nbCorrectlySizedEvSets = 0;
    for (int s = 0; s < cache->info.slices; s++) {
        if (evSets[s].length == cache->info.ways) {
            nbCorrectlySizedEvSets++;
        }
    }

    return nbCorrectlySizedEvSets == cache->info.slices ? 1 : 0;
}

int probeEvictedWithRandomizedPointerChasing(addr_list_t *evSet,
        uintptr_t targetAddress, cache_t *cache) {

    volatile void *pointerChaseSet;

    cpu_fillEvSetRandomized(&pointerChaseSet, 0, 0, evSet);
    return probeEvicted(targetAddress, pointerChaseSet, cache->threshold);
}

int findNewEvSetFromConflictSetForCandidate(uintptr_t candidate,
        addr_list_t *conflictSet, addr_list_t *evSet, cache_t *cache) {

    int retries = 1;
    int currentEvSetFound = 0;

    for (int r = 0; (r < retries) && !currentEvSetFound; r++) {

        for (addr_list_entry_t *ecs = conflictSet->first; ecs != 0;
                ecs = ecs->next) {

            addr_list_t reducedConflictSet;
            initAddrList(&reducedConflictSet);

            deepCopyList(conflictSet, &reducedConflictSet);
            remove_middle(&reducedConflictSet,
                    find_by_address_member(&reducedConflictSet, ecs->addr));

            int test = !probeEvictedWithRandomizedPointerChasing(
                    &reducedConflictSet, candidate, cache);

            if (test) {

                // fprintf(stdout, "Candidate was not evicted, "
                //        "adding address 0x%lx to Eviction Set\n", ecs->addr);

                insert_end(evSet, ecs->addr);
            }

            freeAddrListEntries(&reducedConflictSet);
        }

        if (evSet->length == cache->info.ways) {
            currentEvSetFound = 1;
        } else {
            freeAddrListEntries(evSet);
        }
    }

    return currentEvSetFound;
}

EvSetSearchResult_t determineEvictionSets(addr_list_t *evSets,
        addr_list_t *evSetCandidates, addr_list_t *conflictSet,
        addr_list_t *testCandidates, cache_t *cache) {

    // fprintf(stdout, "\n\nBuilding eviction sets.\n");

    int retries = 100;
    int evSetsFound = 0;

    for (int r = 0; (r < retries) && !evSetsFound; r++) {
        // fprintf(stdout, "Retry %d\n", r);

        int activeSlice = 0;
        addr_list_t retryConflictSet;
        initAddrList(&retryConflictSet);
        deepCopyList(conflictSet, &retryConflictSet);

        for (addr_list_entry_t *e = evSetCandidates->first;
                e != 0 && retryConflictSet.length > 0
                        && activeSlice < cache->info.slices; e = e->next) {

            int test = probeEvictedWithRandomizedPointerChasing(
                    &retryConflictSet, e->addr, cache);

            if (test) {
                // fprintf(stdout, "Filling slice %d\n", activeSlice);

                int currentEvSetFound = findNewEvSetFromConflictSetForCandidate(
                        e->addr, &retryConflictSet, &(evSets[activeSlice]),
                        cache);

                if (currentEvSetFound
                        && probeEvictedWithRandomizedPointerChasing(
                                &(evSets[activeSlice]), e->addr, cache)) {
                    // fprintf(stdout, "Removing %d entries from conflict set.\n",
                    //        evSets[activeSlice].length);

                    removeSet1FromSet2(&(evSets[activeSlice]),
                            &retryConflictSet);

                    insert_end(testCandidates, e->addr);
                    activeSlice++;
                }
            }
        }
        freeAddrListEntries(&retryConflictSet);

        evSetsFound = checkCorrectSizeOfAllEvictionSets(cache, evSets);
        if (evSetsFound != 1) {
            for (int k = 0; k < cache->info.slices; k++) {
                freeAddrListEntries(&(evSets[k]));
            }
        }
    }

    if (evSetsFound != 1) {
        return UNABLE_TO_SPLIT_TO_EVICTION_SETS;
    } else {
        return OK;
    }
}

EvSetSearchResult_t findEvictionSetsLlc(unsigned int setIndexBits,
        cache_t *cache, addr_list_t *testCandidates, void *shm_ptr,
        size_t shmSizeInByte) {

    printCacheInfo(cache);

    // Build candidate set

    addr_list_t evSetCandidates;
    initAddrList(&evSetCandidates);

    buildCandidateSet(setIndexBits, &evSetCandidates, cache, shm_ptr,
            shmSizeInByte);

    // printAddressSet(&evSetCandidates, "Candidate Set", cache);

    // Build conflict set

    addr_list_t conflictSet;
    initAddrList(&conflictSet);

    EvSetSearchResult_t conflictSetResult = determineConflictSet(
            &evSetCandidates, &conflictSet, cache);
    if (conflictSetResult != OK) {
        freeAddrListEntries(&evSetCandidates);
        freeAddrListEntries(&conflictSet);

        return conflictSetResult;
    }

    // printAddressSet(&conflictSet, "Conflict Set for all slices", cache);

    // Build eviction sets

    addr_list_t evSets[cache->info.slices];
    for (int k = 0; k < cache->info.slices; k++) {
        initAddrList(&(evSets[k]));
    }

    removeSet1FromSet2(&conflictSet, &evSetCandidates);

    EvSetSearchResult_t evSetsFound = determineEvictionSets(evSets,
            &evSetCandidates, &conflictSet, testCandidates, cache);

    if (evSetsFound == OK) {
        for (int k = 0; k < cache->info.slices; k++) {
            if (evSets[k].length > 0) {
                cpu_cacheFillEvSetRandomize(cache, &(evSets[k]), setIndexBits,
                        k);
            }
        }

        printEvictionSets(evSets, cache);
    }

    for (int k = 0; k < cache->info.slices; k++) {
        freeAddrListEntries(&(evSets[k]));
    }

    freeAddrListEntries(&evSetCandidates);
    freeAddrListEntries(&conflictSet);

    return evSetsFound;
}

int getEvictionSetForAddress(uintptr_t virtAddr, cache_t *cache,
        unsigned int setIndex) {

    if (cache->ev_sets[setIndex][0].start == 0) {
        return -1;
    }

    int sliceIndex = -1;
    for (int s = 0; s < cache->info.slices; s++) {
        if (probeEvicted(virtAddr, cache->ev_sets[setIndex][s].start,
                cache->threshold)) {
            sliceIndex = s;
            break;
        }
    }

    return sliceIndex;
}

EvSetValidationResult_t validateEvictionSetLlc(uintptr_t testCandidate,
        cache_t *cache, unsigned int setIndex, unsigned int slice) {

    if (probeEvicted(testCandidate, cache->ev_sets[setIndex][slice].start,
            cache->threshold)) {
        return VALID;
    } else {
        return FOUND_SET_IS_NO_EVSET;
    }
}

EvSetValidationResult_t validateEvictionSetsLlcForAllSlices(
        addr_list_t *testCandidates, cache_t *cache, unsigned int setIndex) {

    EvSetValidationResult_t validationResult = VALID;

    fprintf(stdout, "\n\nValidation:\n");

    addr_list_entry_t *testCandidate = testCandidates->first;
    for (int i = 0; i < cache->info.slices && testCandidate != 0; i++) {

        if (validateEvictionSetLlc(testCandidate->addr, cache, setIndex, i)
                != VALID) {
            fprintf(stdout, "Set for slice %d is invalid!\n", i);
            validationResult = FOUND_SETS_ARE_NO_EVSETS;
            continue;
        }

        fprintf(stdout, "Set for slice %d is valid.\n", i);

        testCandidate = testCandidate->next;
    }

    return validationResult;
}

