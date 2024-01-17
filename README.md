# TeeJam

In TeeJam, we revisit and carefully analyze the 4k-aliasing effect.
By combining 4k-aliasing with a high temporal resolution possible when single-stepping an SGX enclave, we construct a very precise, yet widely applicable attack with sub-cache-line leakage resolution.
To demonstrate the significance of our findings, we apply the new attack primitive to break a hardened AES T-Table implementation that features constant cache line access patterns.
The attack is up to three orders of magnitude more efficient than previous sub-cache-line attacks on AES in SGX.

Furthermore, we improve upon our previous work which showed partial exploitability of very faint leakages in a utility function loading base64-encoded RSA keys.
We build an end-to-end attack exploiting the faint leakage that can recover 4096-bit keys in minutes on a laptop.
Finally, we extend the key recovery algorithm to also work for RSA keys following the standard that uses Carmichael’s totient
function, while previous attacks were restricted to RSA keys using Euler’s totient function.

This repository contains all code for the microarchitectural attacks and the reconstruction of the AES key.
The RSA key reconstruction code for the attack on the base64 decoding can be found in [this](https://github.com/UzL-ITS/rsa-key-recovery) repo.

## Prerequisites

### System configuration

For SGX-Step to work properly a few kernel command line parameters have to be set. We went with the following line:

```GRUB_CMDLINE_LINUX_DEFAULT="nox2apic iomem=relaxed no_timer_check nmi_watchdog=0  clearcpuid=514 pti=off rcuupdate.rcu_cpu_stall_suppress=1 msr.allow_writes=on vdso=0 intel_idle.max_cstate=1 processor.max_cstate=1 apparmor=0 isolcpus=0,1,4,5 nosmap nosmep```

Isolating two cores for victim and attacker is sufficient.

Additionally we disabled
  * Intel TurboBoost
  * SpeedStep

in the BIOS.

Then we set the CPU frequency and load the SGX-Step kernel module. For these steps we prepared the script `local_setup.sh`. Additionally it the script disables some prefetchers that can be configured via MSR. Please adapt the script to the number of cores of your processor.


### Build and configure sgx-step

* Patch SGX-Step:
    * to enable proper stepping on your processor, set `#define SGX_STEP_TIMER_INTERVAL 53` in `sgx-step/libsgxstep/config.h` to a value suitable for your CPU by following the instructions in the comment in `config.h` or in the SGX-Step documentation. The value obtained from the benchmark usually has to be increased a bit to still work in the TeeJam hyperthreading scenario.
    * to avoid SGX-step debug messages disable the `#define LIBSGXSTEP_DEBUG` in `sgx-step/libsgxstep/config.h` and move the debug print in line 168 in `sgx-step/libsgxstep/enclave.c` into the following `#if LIBSGXSTEP_DEBUG` precompiler condition
* Build the patched SGX SDK from SGX-Step (and driver if not already installed)
    * Follow the SGX-Step instructions. The build and install script might require a few modifications for local install. We usually installed the compiled SGX SDK in the project root. In the following we will assume that it is installed to the project root in the folder `local-sgx-sdk`
* Before building and running the applications please `source local-sgx-sdk/environment` and run the `local_setup.sh` script.

## Usage

Remark 1: For each experiment / attack the attacking core must be adapted to be the hyperthread of the victim core (`ATTACKER_CPU` in `ht_attack/src/c/main.c`)
Remark 2: Adjust the step_time_min / max thresholds in the analysis scripts to match the measurements on your platform to filter outliers
Remark 3: Configuring the correct timer value for SGX-Step sometimes proofs tricky, especially with an attack continously spamming the hyperthread with memory writes. If one of the examples blows gets stuck in the first iteration, just restarting the attack usually helps (if the timeout is otherwise correctly configured)

### The basic experiment

The basic experiment will access two addresses alternatingly and concurrently run another thread which causes a 4k-aliasing conflict to one of the addresses. The resulting log file can be plotted to visualize the introduced delay. The first parameter to the executable sets the log file's name and the second allows to change the analyzed page offset.

* `cd` to `basic-experiment`
* `cd` to `ht_attack` and `make clean all` the program which will cause the conflicts from the hyperthread
* Go back to the parent folder and build the basic-experiment with `SGX_SDK=/home/its/dev/projects/teejam_github/local-sgx-sdk make clean all` ...
* ... and run it with `sudo LD_LIBRARY_PATH=../sgx-step/sdk/intel-sdk/linux-sgx/psw/urts/linux/ ./basic_experiment`
* (Install python and all required dependencies (TODO: explicitely list dependencies or provide requirements file))
* Run `python3 parser/parse_4k_test_erip.py "Basic Experiment" 100 log.out` for plotting the result with 100 bins
* `parser/sweep_parser.py` can be used to analyze a sweep over an address range of one page (to be created with `sweep.sh`, this will take some time and might require restarts; for the sweep you should also adapt the `max_meas` count in `main.c`)

### Attack on base64 decoding

* `cd` to `b64-memjam-attack`
* `cd` to `ht_attack` and `make clean all` the program which will cause the conflicts from the hyperthread
* Go back to the parent folder and build the b64-decoding attack binary
* Build with `SGX_SDK=/home/its/dev/projects/teejam_github/sgxsdk make clean all`
* Check the function and table offsets defined in the beginning of `main.c`. Please follow the comments to read them from the `encl.so` file. If the output of objdump differs from the addresses specified in `main.c`, please update these.
* Build again
* Run with `sudo LD_LIBRARY_PATH=../sgx-step/sdk/intel-sdk/linux-sgx/psw/urts/linux/ ./b64-attack`
* Offset into the base64 lookup table and the filename can be changed per position parameter 1 and 2 respectively. Please note, the analysis script derives the offset from
    the filename, using chars 4 to 8.
* Analyse a single offset with `python3 parser/parse_memjam_multi_iteration.py --inputFile log-0x68.out`, it might be necessary to adjust the decision threshold computation for your plattform. Different CPU generations will produce more or less noise and smaller or stronger delays.
* The resulting classification can be used for the key reconstruction. Please refer to https://github.com/UzL-ITS/rsa-key-recovery
* Use the `analyse_memjam.py` script to analyse and merge the results of a full sweep into the offsets of the lookup-table
* The script `classification_heat_map.py` can be used to plot a graphical representation of which base64 symbols could be extracted from the recorded traces. It does require a reference file for validation (`print_expected_ossl_b64_decode_string.py`)

### Attack on cache-line protected AES T-Table encryption

* `cd` to `wolfssl-aes-attack`
* First, build wolfssl by calling `build_wolfss_sgx.sh` in the Enclave folder
* Go back to the parent folder and build the wolfssl aes attack binary
* Build with `SGX_SDK=/home/its/dev/projects/teejam_github/sgxsdk make clean all`
* Check the function and table offsets defined in the beginning of `main.c`. Please follow the comments to read them from the `encl.so` file. If the output of objdump differs from the addresses specified in `main.c`, please update these.
* Build again
* Run with `sudo LD_LIBRARY_PATH=../sgx-step/sdk/intel-sdk/linux-sgx/psw/urts/linux/ ./wolfssl-aes-attack` (the number of observed encryption runs must be changed in the code of the main function). By default it is set to 30,000 and the analysis script is configured correspondingly. By default the attacker attacks the offset 0x140 in each T-Table and forwarding the pointer to the next T-Table is handled by a simple state machine in the attacker code.
* For analysis and reconstruction use the script `python3 parser/aes_dta_analysis.py --logFile log.out --cipherTextFile key_log.out --attackedOffset 0x140 --rkFile ground_truth_round_keys_last_round` (if you chose to attack another of offset, please change the script parameter correspondingly). The round key ground truth file is used only for highlighting terminal output and the plots. It is not used for the recovery itself.

## Our paper

When citing our work, please use the following data:

```
@article{tches_SieckZBCEY24,
  author       = {Florian Sieck and
                  Zhiyuan Zhang and
                  Sebastian Berndt and
                  Chitchanok Chuengsatiansup and
                  Thomas Eisenbarth and
                  Yuval Yarom},
  title        = {TeeJam: Sub-Cache-Line Leakages Strike Back},
  journal      = {{IACR} Trans. Cryptogr. Hardw. Embed. Syst.},
  volume       = {2024},
  number       = {1},
  pages        = {457--500},
  year         = {2024},
  url          = {https://doi.org/10.46586/tches.v2024.i1.457-500},
  doi          = {10.46586/TCHES.V2024.I1.457-500},
}
```

