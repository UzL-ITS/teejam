import argparse
import statistics
import json
import sys
import matplotlib.pyplot as plt
import r2pipe
import os
import re


# step_time_min = 12000
# step_time_max = 15500

def load_file(file_name):
    with open(file_name, 'r') as f:
        log = json.load(f)
    return log


def get_mem_read_disasm():
    r = r2pipe.open('./Enclave/encl.so')
    r.cmd('aaa')
    mem_read_disasm = r.cmdj('pdfj @loc.mem_read')

    return mem_read_disasm


def analyze_log(log, page_offset, results):
    stepping_times_attack = []
    stepping_times_benign = []

    erip = 0

    mem_read_disasm = get_mem_read_disasm()
    mem_read_ops = mem_read_disasm['ops']
    max_ops_offset = mem_read_ops[-1]['offset']
    ops_counter = 0
    reset_ops_counter = 0

    print('Read ops: ' + str(len(mem_read_ops)))

    for run in log['runs']:
        run_keys = []
        for key in run.keys():
            run_keys.append(key)
        
        stop_run = False
        for meas in run[run_keys[0]]['measurements']:
            if stop_run:
                break
            # Seems that radare takes the beginning of the instruction and erip from sgx the end
            erip = meas['erip'] - 2  # in case the mov uses 3 bytes this has to be 3

            if meas['atm1'] == 1 and meas['ic'] > 10 and erip <= max_ops_offset:

                while mem_read_ops[ops_counter]['offset'] != erip and not stop_run:
                    ops_counter += 1
                    if ops_counter >= len(mem_read_ops):
                        if reset_ops_counter == 1:
                            print('Reset twice, unexpected behavior! Skipping the rest of this run.')
                            stop_run = True
                        ops_counter = 0
                        reset_ops_counter = 1
                # print(ops_counter)
                reset_ops_counter = 0
                op_esil = mem_read_ops[ops_counter]['esil']

                if str(op_esil).startswith('rdi'):
                    stepping_times_attack.append(meas['st'])
                elif str(op_esil).startswith('rsi'):
                    stepping_times_benign.append(meas['st'])

    if len(stepping_times_attack) > 2 and len(stepping_times_benign) > 2:
        uncleaned_mean_attack = statistics.mean(stepping_times_attack)
        uncleaned_stdev_attack = statistics.stdev(stepping_times_attack)
        step_time_min_attack = uncleaned_mean_attack - 6 * uncleaned_stdev_attack
        step_time_max_attack = uncleaned_mean_attack + 6 * uncleaned_stdev_attack

        uncleaned_mean_benign = statistics.mean(stepping_times_benign)
        uncleaned_stdev_benign = statistics.stdev(stepping_times_benign)
        step_time_min_benign = uncleaned_mean_benign - 6 * uncleaned_stdev_benign
        step_time_max_benign = uncleaned_mean_benign + 6 * uncleaned_stdev_benign

        stepping_times_attack_cleaned = [i for i in stepping_times_attack if
                                 (step_time_min_attack < i < step_time_max_attack)]
        stepping_times_benign_cleaned = [i for i in stepping_times_benign if
                                 (step_time_min_benign < i < step_time_max_benign)]

        avg_stepping_time_attack = statistics.mean(stepping_times_attack_cleaned)
        stdev_stepping_time_attack = statistics.stdev(stepping_times_attack_cleaned)
        avg_stepping_time_benign = statistics.mean(stepping_times_benign_cleaned)
        stdev_stepping_time_benign = statistics.stdev(stepping_times_benign_cleaned)

        # print('Access count attack (' + filename + '): ' + str(len(stepping_times_attack)))
        # print('Average stepping time attack (' + filename + '): ' + str(avg_stepping_time_attack))
        # print('Access count benign (' + filename + '): ' + str(len(stepping_times_benign)))
        # print('Average stepping time benign (' + filename + '): ' + str(avg_stepping_time_benign))

        results[page_offset] = {
            'attacked': {
                'nb_measurements': len(stepping_times_attack),
                'mean': avg_stepping_time_attack,
                'stdev': stdev_stepping_time_attack
            },
            'benign': {
                'nb_measurements': len(stepping_times_benign),
                'mean': avg_stepping_time_benign,
                'stdev': stdev_stepping_time_benign
            }
        }
    else:
        print('Warning: Minimum number of measurements for offset ' + str(
            page_offset) + " not achieved.")


def plot_heat_map(results):
    timing_differences = []
    for i in range(0, 64, 1):
        timing_diffs_cache_line_i = []
        for j in range(0, 64, 4):
            offset = hex(i * 64 + j)
            if offset in results.keys():
                if results[offset]['attacked']['mean'] < 20000 and results[offset]['attacked']['stdev'] < 300 and results[offset]['benign']['mean'] < 20000 and results[offset]['benign']['stdev'] < 300: 
                    print("Adding offset " + offset + ". Measurements: " + json.dumps(results[offset]))
                    timing_diffs_cache_line_i.append(results[offset]['attacked']['mean'] - results[offset]['benign']['mean'])
                else:
                    timing_diffs_cache_line_i.append(0)
            else:
                timing_diffs_cache_line_i.append(0)

        timing_differences.append(timing_diffs_cache_line_i)

    plt.imshow(timing_differences, cmap='inferno', interpolation='none', aspect='auto')
    plt.title("Analysis of the TeeJam Effect for all offsets within a page")
    plt.xlabel("Offsets within a cache line (4-byte steps)")
    plt.ylabel("'Cache Line' / '64 byte page rows'")
    plt.show()


def main(input_src, data_origin):
    results = {}
    
    if data_origin == "raw":
        for f in os.listdir(in_folder):
            log_file_name = os.path.join(in_folder, f)
            if os.path.isfile(log_file_name) and f.endswith(".log"):
                page_offset = re.match('be_offset_(0x[a-f0-9]+)\\.log', f).group(1)
                print(page_offset + ": ")
                log = load_file(log_file_name)
                analyze_log(log, page_offset, results)

        with open('basic_experiment_sweep_results', 'w') as f:
            json.dump(results, f, indent=2)
    elif data_origin == "preprocessed":
        with open('basic_experiment_sweep_results', 'r') as f:
            results = json.load(f)
    else:
        print("Invalid data origin.")

    plot_heat_map(results)


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Parsing arguments for memjam results parser')
    arg_parser.add_argument('--inputSrc', type=str, required=True, help="Input folder name")
    arg_parser.add_argument('--dataOrigin', type=str, required=True, help="Use preprocessed data from file or raw data from a folder")
    args = arg_parser.parse_args()

    main(args.inputSrc, args.dataOrigin)
