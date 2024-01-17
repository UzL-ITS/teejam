import argparse
import statistics
import matplotlib.pyplot as plt
import ijson
import json
import re
import heapq

from wolfssl_aes_ttable import Te


class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


min_step_time = 13000 
max_step_time = 18000

# Usually this should be 640 (the number of accesses to the T-Table during round key derivation).
# However, there seem to be some unrelated accesses to the pages holding the T-Table and access routines.
# This might change with a different memory layout (e.g. different compiler version)
wolfssl_expected_ttable_accesses_offset = 640 + 20
expected_ttable_access_count_wolfssl_aes_target = 2560 + wolfssl_expected_ttable_accesses_offset
expected_ttable_access_count = expected_ttable_access_count_wolfssl_aes_target

last_round_ttable_index_map = [2, 2, 2, 2, 3, 3, 3, 3, 0, 0, 0, 0, 1, 1, 1, 1]
last_round_mask_index_map = [3, 3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0]


def is_valid_measurement(meas):
    return meas['attable'] == 1 and (meas['agt_m'] == 1 or meas['axt_m'] == 1) and meas['ic'] > 1


def parse_log_file(log_file):
    global expected_ttable_access_count

    measurements_filtered_correct_length = {}

    run_nb = 0
    traces_with_invalid_length = 0

    with open(log_file, 'r') as json_f:
        for run in ijson.items(json_f, 'runs.item'):
            measurements = run['run' + str(run_nb)]['measurements']
            measurements_filtered = []
            for meas in measurements:
                if is_valid_measurement(meas):
                    measurements_filtered.append(meas['st'])
            
            if len(measurements_filtered) == expected_ttable_access_count:
                measurements_filtered_correct_length[str(int(run_nb))] = \
                    measurements_filtered[wolfssl_expected_ttable_accesses_offset:]
            else:
                traces_with_invalid_length += 1
            
            print("Read run nb: " + str(run_nb) + ", Traces with invalid lenght: " + str(
                traces_with_invalid_length) + "\r", end="")

            run_nb += 1

    print("Read run nb: " + str(run_nb) + ", Traces with invalid lenght: " + str(traces_with_invalid_length))

    return measurements_filtered_correct_length


def filter_mapped_measurements_by_range(mapped_measurements):
    const_filtered_mapped_measurements = {
        'attacked': [],
        'benign': []
    }

    filtered_mapped_measurements = {
        'attacked': [],
        'benign': []
    }

    const_filtered_mapped_measurements['attacked'] = [i for i in mapped_measurements['attacked'] if
                                                      (min_step_time < i < max_step_time)]
    const_filtered_mapped_measurements['benign'] = [i for i in mapped_measurements['benign'] if
                                                    (min_step_time < i < max_step_time)]

    return const_filtered_mapped_measurements


def plot_mapped_measurements(mapped_measurements, stats, hist_bins):
    avg_label_inc = 0

    mean_attacked = stats['attacked']['mean']
    stdev_attacked = stats['attacked']['stdev']
    mean_benign = stats['benign']['mean']
    stdev_benign = stats['benign']['stdev']

    plt.hist(mean_attacked, bins=hist_bins, alpha=0.5, label='attack')
    plt.axvline(statistics.mean(mapped_measurements['attacked']), color='k', linestyle='dashed',
                linewidth=1)
    min_ylim, max_ylim = plt.ylim()
    plt.text(mean_attacked * 1.0001, max_ylim * 0.01 + max_ylim * avg_label_inc,
             'Mean: {:.2f}\nStdev: {:.2f}'.format(mean_attacked, stdev_attacked))
    avg_label_inc += 0.1

    plt.hist(mapped_measurements['benign'], bins=hist_bins, alpha=0.5, label='benign')
    plt.axvline(mean_benign, color='k', linestyle='dashed', linewidth=1)
    min_ylim, max_ylim = plt.ylim()
    plt.text(mean_benign * 1.0001, max_ylim * 0.01 + max_ylim * avg_label_inc,
             'Mean: {:.2f}\nStdev: {:.2f}'.format(mean_benign, stdev_benign))
    avg_label_inc += 0.1

    plt.legend(loc='upper right')
    plt.yscale('log')
    plt.show()
    # plt.savefig(dpi=600, format="pdf")


def compute_stats(mapped_measurements):
    return {
        'attacked': {
            'mean': statistics.mean(mapped_measurements['attacked']),
            'median': statistics.median(mapped_measurements['attacked']),
            # Remove stdev for single measurement (nist)
            'stdev': statistics.stdev(mapped_measurements['attacked'])
        },
        'benign': {
            'mean': statistics.mean(mapped_measurements['benign']),
            'median': statistics.median(mapped_measurements['benign']),
            # Remove stdev for single measurement (nist)
            'stdev': statistics.stdev(mapped_measurements['benign'])
        }
    }


def reverse_endianess(cipher_text_array):
    # This function does nothing, endianess reversing not necessary

    # cipher_text_array_re = [None] * len(cipher_text_array)
    # for i in range(0, len(cipher_text_array), 4):
    #     cipher_text_array_re[i + 0] = cipher_text_array[i + 3]
    #     cipher_text_array_re[i + 1] = cipher_text_array[i + 2]
    #     cipher_text_array_re[i + 2] = cipher_text_array[i + 1]
    #     cipher_text_array_re[i + 3] = cipher_text_array[i + 0]

    # return cipher_text_array_re
    return cipher_text_array


def read_cipher_texts(cipher_text_file):
    cipher_texts = {}
    with open(cipher_text_file, 'r') as ctf:
        ctf_content = ctf.read()
        matches = re.findall("Run (\\d+)\\nPlain: ([\\s0-9a-fx]+)\\nCipher: ([\\s0-9a-fx]+)", ctf_content)
        for m in matches:
            run = m[0]
            cipher_texts[run] = reverse_endianess([int(c, 16) for c in str(m[2]).strip().split(" ")])

    return cipher_texts


def get_loopindex(ttable_access, mode="wolfssl"):
    # The compiler does some weird stuff when compiling the enclave and switches index 1 and 3 ...
    if mode == "wolfssl":
        ttable_access_mod = ttable_access % 4
        if ttable_access_mod == 1:
            return 3
        elif ttable_access_mod == 3:
            return 1
        else:
            return ttable_access_mod
    else:
        return ttable_access % 4


def map_measurements_according_to_expected_key_byte(expected_key_byte, cipher_text_byte, ttable,
                                                    last_round_mask_index, ttable_access,
                                                    attacked_offset, measurements, mapped_measurements):
    expected_ttable_output_byte = expected_key_byte ^ cipher_text_byte
    expected_ttable_index = -1

    for i in range(0, len(Te[str(ttable)])):
        candidate_byte = (Te[str(ttable)][i] & (0xFF << (8 * last_round_mask_index))) >> (8 * last_round_mask_index)
        if candidate_byte == expected_ttable_output_byte:
            expected_ttable_index = i
            break

    if expected_ttable_index == -1:
        print('Error could not resolve t-table entry.')
        exit(-1)

    attacked_index_base = int((attacked_offset % 0x40) / 4)
    attacked_indexes = [int(attacked_index_base + c) for c in range(0, 256, 16)]

    base_last_round_index = 2304
    step_index = base_last_round_index \
                 + ((ttable_access // 4) * 64) \
                 + (get_loopindex(ttable_access, "wolfssl")) \
                 + (4 * (attacked_offset // 0x40))

    if expected_ttable_index in attacked_indexes:
        mapped_measurements['attacked'].append(measurements[step_index])
    else:
        mapped_measurements['benign'].append(measurements[step_index])


def get_cipher_text_byte(run, ttable_access, cipher_texts):
    ttable_access_to_cipher_text_map = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    return cipher_texts[str(run)][ttable_access_to_cipher_text_map[ttable_access]]


def load_preprocessed_measurements(log_file):
    with open(log_file + ".preprocessed", 'r') as lf:
        measurement_runs = json.load(lf)

    return measurement_runs


def store_preprocessed_measurements(measurement_runs, log_file):
    with open(log_file + ".preprocessed", 'w') as plf:
        json.dump(measurement_runs, plf)


def read_ground_trouth_round_key_last_round(round_key_file):
    rk = {}
    rk_pattern = re.compile('r\\[(\\d)]: (0x[a-f0-9]{8})')
    with open(round_key_file, 'r') as rkf:
        while line := rkf.readline():
            m = rk_pattern.search(line.strip())
            if m is not None:
                rk[str(m.group(1))] = int(m.group(2), 16)

    return rk


def plot_all_key_bytes_in_different_graphs(meas_series):
    for s in range(0, len(meas_series)):
        plt.figure(figsize=[30, 15])
        plt.plot(range(0, 256), meas_series[s])
        plt.title(f'AES round key differential time analysis for key byte {s:d}')
        plt.xlabel('Key byte guess')
        plt.ylabel('Timing difference in cycles')
        plt.savefig(f"aes_dta_analysis_key_byte_{s:d}.pdf", dpi=600, format="pdf")


def plot_all_key_bytes_in_one_graph(meas_series, colors):
    plt.figure(figsize=[30, 15])
    for s in range(0, len(meas_series)):
        plt.plot(range(0, 256), meas_series[s], color=colors[s])
    plt.title('AES round key differential time analysis')
    plt.xlabel('Key byte guess')
    plt.ylabel('Timing difference in cycles')
    plt.legend([f"Key byte {b:2d}" for b in range(0, len(meas_series))])
    # plt.show()
    plt.savefig("aes_dta_analysis.pdf", dpi=600, format="pdf")


def plot_key_recover_quality(meas_series_intermediate, eval_range, colors, rk=None):
    vals = {}
    # hack
    for i in range(0, 16):
        vals[str(i)] = {}
        for j in range(0, 256):
            vals[str(i)][str(j)] = []

    for max_meas_nb in meas_series_intermediate.keys():
        for ttable_access in meas_series_intermediate[max_meas_nb].keys():
            for key_byte in meas_series_intermediate[max_meas_nb][ttable_access].keys():
                vals[ttable_access][key_byte].append({
                    "max_meas_nb": int(max_meas_nb),
                    "diff": meas_series_intermediate[max_meas_nb][ttable_access][key_byte]
                })

    for i in range(0, len(vals)):
        for j in range(0, len(vals[str(i)])):
            vals[str(i)][str(j)] = sorted(vals[str(i)][str(j)], key=lambda element: element["max_meas_nb"])

    vals_array = []
    
    for i in range(0, len(vals)):
        vals_array.append([])
        for j in range(0, len(vals[str(i)])):
            vals_array[i].append([])
            for e in vals[str(i)][str(j)]:
                vals_array[i][j].append(e["diff"])

    fig, axs = plt.subplots(4, 4)
    fig.set_size_inches(60, 40)
    for i in range(0, len(vals_array)):
        for j in range(0, len(vals_array[i])):
            line_color = "lightgray"
            if rk is not None:
                rk_nb = int(i % 4)
                rk_mask = (0xFF << (8 * last_round_mask_index_map[i]))
                rk_byte = (rk[str(rk_nb)] & rk_mask) >> 8 * last_round_mask_index_map[i]
                if rk_byte == j:
                    line_color = "black"

            axs[i // 4][i % 4].plot(eval_range, vals_array[i][j], color=line_color)

        axs[i // 4][i % 4].set_title("T-Table access " + str(i), fontsize=28)
        axs[i // 4][i % 4].set(xlabel="Measurements", ylabel="Timing diff. in cycles")
        axs[i // 4][i % 4].xaxis.label.set_size(22)
        axs[i // 4][i % 4].yaxis.label.set_size(22)
        axs[i // 4][i % 4].tick_params(axis='x', labelsize=20)
        axs[i // 4][i % 4].tick_params(axis='y', labelsize=20)
        axs[i // 4][i % 4].set_ylim(bottom=-100, top=150)
    
    plt.savefig("recovery_quality.pdf", dpi=600, format="pdf")
    plt.close()

    for i in range(0, len(vals_array)):
        plt.figure(figsize=[30, 15])
        for j in range(0, len(vals_array[i])):
            line_color = "lightgray"
            if rk is not None:
                rk_nb = int(i % 4)
                rk_mask = (0xFF << (8 * last_round_mask_index_map[i]))
                rk_byte = (rk[str(rk_nb)] & rk_mask) >> 8 * last_round_mask_index_map[i]
                if rk_byte == j:
                    line_color = "black"
            plt.plot(eval_range, vals_array[i][j], color=line_color)
        plt.title("T-Table access " + str(i), fontsize=70)
        plt.xlabel("Measurements", fontsize=62)
        plt.ylabel("Timing diff. in cycles", fontsize=62)
        plt.xticks(fontsize=58)
        plt.yticks(fontsize=58)
        plt.ylim(bottom=-100, top=150)

        plt.savefig("recovery_quality_ttable_access_" + str(i) + ".pdf", dpi=600, format="pdf")
        plt.close()

def evaluate_measurements(measurement_runs, cipher_texts, attacked_offset, nb_meas_runs,
                          eval_range, meas_series, meas_series_intermediate, rk):

    for ttable_access in range(0, 16):
        meas_series.append([])
        for key_byte_guess in range(0, 256):
            mapped_measurements = {
                'attacked': [],
                'benign': []
            }
            previous_max_run_nb = 0
            for max_run_nb in eval_range:
                print("T-Table Access: " + str(ttable_access) + ", key byte guess: " + str(key_byte_guess)
                      + ", Max run number: " + str(max_run_nb) + "\r", end="")
                
                for run_nb in range(previous_max_run_nb, max_run_nb):
                    if str(int(run_nb)) not in measurement_runs.keys():
                        continue
                    cipher_text_byte = get_cipher_text_byte(run_nb, ttable_access, cipher_texts)
                    map_measurements_according_to_expected_key_byte(key_byte_guess, cipher_text_byte,
                                                                    last_round_ttable_index_map[ttable_access],
                                                                    last_round_mask_index_map[ttable_access],
                                                                    ttable_access, int(attacked_offset, 16),
                                                                    measurement_runs[str(int(run_nb))],
                                                                    mapped_measurements)
                filtered_mapped_measurements = filter_mapped_measurements_by_range(mapped_measurements)
                stats = compute_stats(filtered_mapped_measurements)
                difference_mean = stats['attacked']['mean'] - stats['benign']['mean']
                difference_median = stats['attacked']['median'] - stats['benign']['median']
                if max_run_nb == nb_meas_runs:
                    terminal_color = Bcolors.ENDC
                    if rk is not None:
                        rk_nb = int(ttable_access % 4)
                        rk_mask = (0xFF << (8 * last_round_mask_index_map[ttable_access]))
                        rk_byte = (rk[str(rk_nb)] & rk_mask) >> 8 * last_round_mask_index_map[ttable_access]
                        if rk_byte == key_byte_guess:
                            terminal_color = Bcolors.OKGREEN

                    # Remove stdev for single measurement (nist)
                    print(
                        f"{terminal_color}Last round access: {ttable_access:2d}, guessed key byte: 0x{key_byte_guess:2x}, "
                        f"{terminal_color}Difference in mean: {difference_mean:.2f}, "
                        f"{terminal_color}Difference in median: {difference_median:.2f}, "
                        f"{terminal_color}Number of measurements attacked: {len(filtered_mapped_measurements['attacked'])}, "
                        f"{terminal_color}Stdev attacked: {stats['attacked']['stdev']:.2f}, "
                        f"{terminal_color}Number of measurements benign: {len(filtered_mapped_measurements['benign'])}, "
                        f"{terminal_color}Stdev benign: {stats['benign']['stdev']:.2f}")

                    meas_series[ttable_access].append(difference_mean)


                if str(max_run_nb) not in meas_series_intermediate:
                    meas_series_intermediate[str(max_run_nb)] = {}
                if str(ttable_access) not in meas_series_intermediate[str(max_run_nb)]:
                    meas_series_intermediate[str(max_run_nb)][str(ttable_access)] = {}
                meas_series_intermediate[str(max_run_nb)][str(ttable_access)][str(key_byte_guess)] = difference_mean

                previous_max_run_nb = max_run_nb


def main(log_file, cipher_text_file, attacked_offset,
         store_preprocessed, load_preprocessed, store_plot_data, load_plot_data, rk_file):
    if store_preprocessed is True and load_preprocessed is True:
        print("You can either store or load preprocessed data. Exiting ...")
        exit(-1)

    if store_plot_data is True and load_plot_data is True:
        print("You can either store or load plot data. Exiting ...")
        exit(-1)

    if load_plot_data is True and (store_preprocessed or load_preprocessed) is True:
        print("When loading plot data, preprocessed data cannot be loaded or stored.")
        exit(-1)

    rk = None
    if rk_file is not None:
        rk = read_ground_trouth_round_key_last_round(rk_file)

    cipher_texts = read_cipher_texts(cipher_text_file)
    # eval_range = [500] + list(range(1000, 10000, 1000)) + list(range(10000, nb_meas_runs + 1, 5000))
    eval_range = [500, 1000, 5000, 10000, 20000, 30000]
    nb_meas_runs = eval_range[-1]

    meas_series = []
    meas_series_intermediate = {}

    if not load_plot_data:
        print("Loading data")
        measurement_runs = {}
        if load_preprocessed is True:
            measurement_runs = load_preprocessed_measurements(log_file)
        elif store_preprocessed is True:
            measurement_runs = parse_log_file(log_file)
            store_preprocessed_measurements(measurement_runs, log_file)
        else:
            measurement_runs = parse_log_file(log_file)

        print("Evaluating measurement data")
        evaluate_measurements(measurement_runs, cipher_texts, attacked_offset, nb_meas_runs, eval_range, meas_series,
                              meas_series_intermediate, rk)
        if store_plot_data:
            with open(log_file + ".key_byte_plot_data", 'w') as kbpd:
                json.dump(meas_series, kbpd)
            with open(log_file + ".recovery_quality_plot_data", 'w') as rqpd:
                json.dump(meas_series_intermediate, rqpd)
    else:
        with open(log_file + ".key_byte_plot_data", 'r') as kbpd:
            meas_series = json.load(kbpd)
        with open(log_file + ".recovery_quality_plot_data", 'r') as rqpd:
            meas_series_intermediate = json.load(rqpd)

    colors = [
        'blue', 'yellow', 'red', 'green',
        'cyan', 'fuchsia', 'lime', 'orange',
        'sienna', 'khaki', 'grey', 'rosybrown',
        'navy', 'peru', 'olive', 'cornflowerblue'
    ]

    plot_key_recover_quality(meas_series_intermediate, eval_range, colors, rk)

    plot_all_key_bytes_in_one_graph(meas_series, colors)
    plot_all_key_bytes_in_different_graphs(meas_series)


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(
        description='Parse and evaluate a wolfSSL trace and a plot a histogram '
                    'with the help of a ground truth')
    arg_parser.add_argument('--logFile', type=str, required=True, help="Log file name")
    arg_parser.add_argument('--cipherTextFile', type=str, required=True, help="File containing the ciphertexts")
    arg_parser.add_argument('--attackedOffset', type=str, required=True, help="Attacked offset")
    arg_parser.add_argument('--storePreprocessed', action="store_true", help="Store preprocessed")
    arg_parser.add_argument('--storePlotData', action="store_true",
                            help="Store data as json before handing it to matplotlib.")
    arg_parser.add_argument('--loadPreprocessed', action="store_true", help="Plot some results")
    arg_parser.add_argument('--loadPlotData', action="store_true",
                            help="Load data from json and hand it directly to matplotlib matplotlib.")
    arg_parser.add_argument('--rkFile', type=str, required=False, help="Path to file containing last round round keys")

    args = arg_parser.parse_args()

    main(args.logFile, args.cipherTextFile, args.attackedOffset,
         args.storePreprocessed, args.loadPreprocessed, args.storePlotData, args.loadPlotData, args.rkFile)
