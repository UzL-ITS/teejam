#include "encl_t.h"
#include "mem_read.h"

#define TEST_MEM_SIZE (12288)

unsigned char test_mem1[TEST_MEM_SIZE] = { 0 };

void* get_stub_adrs(void) {
    return test_access_for_4k_attack;
}

void* get_test_mem1_addr(void) {
    return &(test_mem1[0]);
}

int get_test_access_pos_1_for_4k_attack(unsigned int attack_offset) {
    int cur = 0;
    unsigned int offset_mask = 0xFFF;

    attack_offset = attack_offset & offset_mask;

    while(cur < TEST_MEM_SIZE &&
            (((unsigned int) (((unsigned long int) &(test_mem1[cur])) & offset_mask)) != attack_offset)) {
        cur++;
    }

    return cur;
}


void test_access_for_4k_attack(int pos1, int pos2) {
    for (int i = 0; i < 100; ++i) {
        mem_read((uintptr_t) (test_mem1 + pos1), (uintptr_t) (test_mem1 + pos2));
    }
}
