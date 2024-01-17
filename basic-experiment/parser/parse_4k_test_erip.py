import statistics
import json
import sys
import matplotlib.pyplot as plt
import r2pipe

step_time_min = 12500
step_time_max = 15000

def load_file(file_name):
    with open(file_name, 'r') as f:
        log = json.load(f)
    return log


def get_mem_read_disasm():
    r = r2pipe.open('./Enclave/encl.so')
    r.cmd('aaa')
    mem_read_disasm = r.cmdj('pdfj @loc.mem_read')

    return mem_read_disasm



def analyze_log(log, filename, hist_bins):
    global avg_label_inc
    stepping_times_attack = []
    stepping_times_benign = []
    erip = 0

    mem_read_disasm = get_mem_read_disasm()
    mem_read_ops = mem_read_disasm['ops']
    max_ops_offset = mem_read_ops[-1]['offset']
    ops_counter = 0
    reset_ops_counter = 0

    print('Read ops: ' + str(len(mem_read_ops)))

    for meas in log['runs'][0]['run0']['measurements']:
        # Seems that radare takes the beginning of the instruction and erip from sgx the end
        erip = meas['erip'] - 2  # in case the mov uses 3 bytes this has to be 3

        if meas['atm1'] == 1 and meas['ic'] > 10 and erip <= max_ops_offset:

            while mem_read_ops[ops_counter]['offset'] != erip:
                ops_counter += 1
                if ops_counter >= len(mem_read_ops):
                    if reset_ops_counter == 1:
                        print('Reset twice, unexpected behavior!')
                        sys.exit(1)
                    ops_counter = 0
                    reset_ops_counter = 1
            # print(ops_counter)
            reset_ops_counter = 0
            op_esil = mem_read_ops[ops_counter]['esil']

            if str(op_esil).startswith('rdi'):
                stepping_times_attack.append(meas['st'])
            elif str(op_esil).startswith('rsi'):
                stepping_times_benign.append(meas['st'])

    stepping_times_attack = [i for i in stepping_times_attack if (step_time_min < i < step_time_max)]
    stepping_times_benign = [i for i in stepping_times_benign if (step_time_min < i < step_time_max)]

    avg_stepping_time_attack = statistics.mean(stepping_times_attack)
    stdev_stepping_time_attack = statistics.stdev(stepping_times_attack)
    avg_stepping_time_benign = statistics.mean(stepping_times_benign)
    stdev_stepping_time_benign = statistics.stdev(stepping_times_benign)

    print('Access count attack (' + filename + '): ' + str(len(stepping_times_attack)))
    print('Average stepping time attack (' + filename + '): ' + str(avg_stepping_time_attack))
    print('Access count benign (' + filename + '): ' + str(len(stepping_times_benign)))
    print('Average stepping time benign (' + filename + '): ' + str(avg_stepping_time_benign))

    plt.hist(stepping_times_attack, bins=hist_bins, range=(step_time_min, step_time_max), alpha=0.5, label='attack')
    plt.axvline(avg_stepping_time_attack, color='k', linestyle='dashed', linewidth=1)
    min_ylim, max_ylim = plt.ylim()
    plt.text(avg_stepping_time_attack * 1.0001, max_ylim * 0.01 + max_ylim * avg_label_inc, 'Mean: {:.2f}\nStdev: {:.2f}'.format(avg_stepping_time_attack, stdev_stepping_time_attack))
    avg_label_inc += 0.1

    plt.hist(stepping_times_benign, bins=hist_bins, range=(step_time_min, step_time_max), alpha=0.5, label='benign')
    plt.axvline(avg_stepping_time_benign, color='k', linestyle='dashed', linewidth=1)
    min_ylim, max_ylim = plt.ylim()
    plt.text(avg_stepping_time_benign * 1.0001, max_ylim * 0.01 + max_ylim * avg_label_inc, 'Mean: {:.2f}\nStdev: {:.2f}'.format(avg_stepping_time_benign, stdev_stepping_time_benign))
    avg_label_inc += 0.1

def main():
    if 4 <= len(sys.argv) <= 6:
        plt.title(sys.argv[1])
        nb_bins = int(sys.argv[2])
        filename1 = sys.argv[3]
        log1 = load_file(filename1)
        analyze_log(log1, filename1, nb_bins)
        if len(sys.argv) >= 5:
            filename2 = sys.argv[4]
            log2 = load_file(filename2)
            analyze_log(log2, filename2, nb_bins)
        if len(sys.argv) == 6:
            filename3 = sys.argv[5]
            log3 = load_file(filename3)
            analyze_log(log3, filename3, nb_bins)
    else:
        print('Wrong argument count')
        exit(1)
    
    plt.legend(loc='upper right')
    plt.show()


if __name__ == '__main__':
    avg_label_inc = 0
    main()
