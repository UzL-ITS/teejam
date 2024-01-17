import argparse
import os
import numpy as np
import ijson
import csv


class Classification:
    ATTACKED_WORD_ACCESSED = 1
    OTHER_ACCESS = 0
    UNDEFINED = -1


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


ossl_1024_bit_key = \
    'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMUwt5PUgUIj6/F3\n' \
    '3WuawCxFBeZEIBxeix2mPfR3x94qzFmvFPVrnXBI8aRAhY+CuWx6jPJ/jnQvQcsy\n' \
    'HHyFFE6h9xe31R86WUMh2uq1Ny7wGU2wRIr6YlHjKAh5gDLzCL3XGzv72dv0clbO\n' \
    'TUZHVGGFd5OX0KRk/Am0w+j8JKkzAgMBAAECgYB2Jq6YYSfh3WwuDsgZBWxIGkNi\n' \
    'qUckOHHanhVZObwEHli7E/DW7Fg1Qz+mTxK33ngDy5pQYqWUcAxYF/qBkauMM9xN\n' \
    'gwdc6JCjyztM6g0j81QHduQs+QPnRIYZDoPIc5HX0EVcwTjfH2tmQMvB7THFQuDe\n' \
    'rIMgLh/pRDd59hd5oQJBAPNdo3SJxnlvfMxjWq6naJnp1n9+E7lvo5qNNjpSnKCs\n' \
    'zo8vwpvML6hNiG0FFRKnyg8AM8QE09U/rvsw66Iz6B8CQQDPbWaaTutwOF5+x30B\n' \
    'q/os07vb3sVLh5RwNQgXnQxF7nDEP5ECqQnwVeYOjU4egrIVV0NeOnSu7GstxPcp\n' \
    'KqxtAkArlofiJZMQyPEXQmxJf95yQrmSWCh8PAyXb9dYltdKx+ivKKS4dtfKUyiu\n' \
    'LgzaLIc6LJUY9KxkM2XJw7dQc++NAkEAwG5u1FLIyugQii8JgoaIZhPb4ONvR121\n' \
    'UM9x/W4d17aX+Qg7wCsP5F3cOr3OrjFzgqbdAcrbOvhrih+DaDaFlQJBAIkoJMeT\n' \
    'MM8p8PJki3Yfsetvg/WewB71UOAdr0sJRi7w6hPjMFOgc+JJg78S/0NbFu49Hgkm\n' \
    'obNOGJpUhF3CjBk=\n'

expected_memory_accesses_1024_bit_key = 1738

# "Place holder string"
ossl_key_4096_bit = \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'


expected_memory_accesses_4096_bit_key = 6486

expected_memory_accesses = expected_memory_accesses_4096_bit_key
key = ossl_key_4096_bit
# expected_memory_accesses = expected_memory_accesses_1024_bit_key
# key = ossl_1024_bit_key


expected_chars = {
    '0x20': [' ', '!', '\"', '#', '$', '%', '&', '\''],
    '0x28': ['(', ')', '*', '+', ',', '/', '-', '.'],
    '0x30': ['0', '1', '2', '3', '4', '5', '6', '7'],
    '0x38': ['8', '9', ':', ';', '<', '=', '>', '?'],
    '0x40': ['@', 'A', 'B', 'C', 'D', 'E', 'F', 'G'],
    '0x48': ['H', 'I', 'J', 'K', 'L', 'M', 'N', 'O'],
    '0x50': ['P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W'],
    '0x58': ['X', 'Y', 'Z', '[', '\\', ']', '^', '_'],
    '0x60': ['`', 'a', 'b', 'c', 'd', 'e', 'f', 'g'],
    '0x68': ['h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'],
    '0x70': ['p', 'q', 'r', 's', 't', 'u', 'v', 'w'],
    '0x78': ['x', 'y', 'z', '{', '|', '}', '~']
}

key_cur = 0
key_buffer = []
key_buffer_cur = 0
read_buffer_start = 0
read_buffer_end = 0
key_pass = 0
key_pass_1_is_line_break = 0



evaluation_type = 'file'  # Options: 'terminal', 'file'


def reset_key_emulation():
    global key_cur, key_buffer_cur, key_buffer, read_buffer_start, read_buffer_end, key_pass, key_pass_1_is_line_break
    key_cur = 0
    key_buffer = []
    key_buffer_cur = 0
    read_buffer_start = 0
    read_buffer_end = 0
    key_pass = 0
    key_pass_1_is_line_break = 0


def get_next_key_char():
    global key_cur
    global key_buffer_cur
    global key_buffer
    global read_buffer_start
    global read_buffer_end
    global key_pass
    global key_pass_1_is_line_break

    ret = ''

    if len(key_buffer) < 64 and key_cur < len(key):
        key_pass = 1
        key_pass_1_is_line_break = 1
        ret = key[key_cur]
        key_cur += 1
        if ret != '\n':
            key_pass_1_is_line_break = 0
            key_buffer.append(ret)
    else:
        key_pass = 2
        if len(key_buffer) == 0:
            print("ERROR - Key buffer should not be empty - Should not happen!")
            exit(1)

        if read_buffer_start == 0:
            ret = key_buffer[0]
            read_buffer_start = 1
        elif read_buffer_end == 0:
            ret = key_buffer[len(key_buffer) - 1]
            read_buffer_end = 1
        else:
            ret = key_buffer[key_buffer_cur]
            key_buffer_cur += 1
            if key_buffer_cur == len(key_buffer):
                key_buffer_cur = 0
                read_buffer_start = 0
                read_buffer_end = 0
                key_buffer.clear()

    return ret


def get_relevant_measurement_data(input_file):
    global expected_memory_accesses
    measurements_filtered_correct_length = []
    run_nb = 0
    with open(input_file, 'r') as json_f:
        for run in ijson.items(json_f, 'runs.item'):
            measurements = run['run' + str(run_nb)]['measurements']
            measurements_filtered = []
            for meas in measurements:
                if meas['alut'] == 1 and meas['adecf'] == 1:
                    measurements_filtered.append(meas['st'])
            if len(measurements_filtered) == expected_memory_accesses:
                measurements_filtered_correct_length.append(measurements_filtered)

            run_nb += 1

    return measurements_filtered_correct_length


def gather_stats(measurements_filtered_correct_length):
    global expected_memory_accesses
    stepping_times_stats = []

    for data_point_idx in range(expected_memory_accesses):
        stepping_times = []
        for meas in measurements_filtered_correct_length:
            stepping_times.append(meas[data_point_idx])

        step_stats = {
            'mean': np.mean(stepping_times),
            'median': np.median(stepping_times),
            'std': np.std(stepping_times, ddof=1),
            'classification': Classification.UNDEFINED
        }
        stepping_times_stats.append(step_stats)
        stepping_times.clear()

    return stepping_times_stats


def evaluate_results(stepping_times_stats, lut_offset_str):
    global evaluation_type
    interval = 7
    for s in range(len(stepping_times_stats)):
        classify_step(stepping_times_stats=stepping_times_stats, step_idx=s, interval=interval)

        next_char = get_next_key_char()

        if evaluation_type == 'terminal':
            terminal_eval(stats=stepping_times_stats[s], next_char=next_char, lut_offset_str=lut_offset_str)
        elif evaluation_type == 'file':
            file_eval(stats=stepping_times_stats[s], lut_offset_str=lut_offset_str)
        else:
            print(stepping_times_stats[s])


def classify_step(stepping_times_stats, step_idx, interval):
    moving_avg_list = []

    if step_idx < interval:
        down = step_idx
    else:
        down = interval

    if (step_idx + interval) > (len(stepping_times_stats) - 1):
        up = len(stepping_times_stats) - 1 - step_idx
    else:
        up = interval

    for m in range(step_idx - down, step_idx + up + 1):
        moving_avg_list.append(stepping_times_stats[m]['mean'])

    moving_avg = np.mean(moving_avg_list)
    moving_std = np.std(moving_avg_list, ddof=1)
    threshold = 1 * moving_std
    if threshold < 20:
        threshold = 20
    
    threshold = threshold * 1.2

    if stepping_times_stats[step_idx]['mean'] - moving_avg >= threshold:
        stepping_times_stats[step_idx]['classification'] = Classification.ATTACKED_WORD_ACCESSED
    else:
        stepping_times_stats[step_idx]['classification'] = Classification.OTHER_ACCESS


def terminal_eval(stats, next_char, lut_offset_str):
    global expected_chars
    global key_pass
    terminal_color = Bcolors.ENDC

    if key_pass == 1:
        if stats['classification'] == Classification.ATTACKED_WORD_ACCESSED \
                and next_char in expected_chars[lut_offset_str]:
            terminal_color = Bcolors.OKGREEN
        elif stats['classification'] == Classification.OTHER_ACCESS \
                and next_char in expected_chars[lut_offset_str]:
            terminal_color = Bcolors.WARNING
        elif stats['classification'] == Classification.ATTACKED_WORD_ACCESSED \
                and next_char not in expected_chars[lut_offset_str]:
            terminal_color = Bcolors.FAIL

    print(f'{terminal_color}Mean: %.2f, ' % stats['mean']
          + 'Median: %.2f, ' % stats['median']
          + 'Std: %.2f' % stats['std']
          + '; ' + next_char + f'{Bcolors.ENDC}')


def file_eval(stats, lut_offset_str):
    global expected_chars
    global key_pass
    global key_pass_1_is_line_break

    result_file_name = 'classification_' + lut_offset_str + '.csv'

    if key_pass == 1 and key_pass_1_is_line_break == 0:
        with open(result_file_name, 'a', newline='') as csv_file:
            result_writer = csv.writer(csv_file, delimiter=';', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            if stats['classification'] == Classification.ATTACKED_WORD_ACCESSED:
                result_writer.writerow([stats['classification'], expected_chars[lut_offset_str]])
            elif stats['classification'] == Classification.OTHER_ACCESS:
                result_writer.writerow([stats['classification'], []])
            else:
                result_writer.writerow([stats['classification'], ''])


def main(filename):
    lut_offset_str = os.path.split(filename)[1][4:8]
    print('Lut offset: ' + lut_offset_str)

    measurements_filtered_correct_length = get_relevant_measurement_data(filename)

    print('All data loaded')

    stepping_times_stats = gather_stats(measurements_filtered_correct_length)

    evaluate_results(stepping_times_stats=stepping_times_stats,
                     lut_offset_str=lut_offset_str)

    reset_key_emulation()

    print('Good measurements: ' + str(len(measurements_filtered_correct_length)))


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Parsing arguments for memjam results parser')
    arg_parser.add_argument('--inputFile', type=str, help="Input file name")
    args = arg_parser.parse_args()

    main(args.inputFile)
