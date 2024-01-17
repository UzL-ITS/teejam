import argparse
import json

FIRST_TE_OFFSET = 0x500
STDEV_THRESHOLD = 400

def all_differences_larger_threshold(offset, threshold, results):

    for j in range(0, 0x1000, 0x400):
        key = str(hex((FIRST_TE_OFFSET + j + offset) % 0x1000))
        if key in results:
            if results[key]['attacked']['mean'] \
                    - results[key]['benign']['mean'] < threshold \
                    or results[key]['attacked']['stdev'] > STDEV_THRESHOLD \
                    or results[key]['benign']['stdev'] > STDEV_THRESHOLD:
                return False
        else:
            return False

    return True


def get_average_mean_difference(offset, results):
    average_mean_difference = 0
    for j in range(0, 0x1000, 0x400):
        average_mean_difference += results[str(hex((FIRST_TE_OFFSET + j + offset) % 0x1000))]['attacked']['mean'] \
                                   - results[str(hex((FIRST_TE_OFFSET + j + offset) % 0x1000))]['benign']['mean']

    return average_mean_difference / 4


def main(in_file, threshold):
    with open(in_file, 'r') as f:
        results = json.load(f)

    favorable_offsets = []
    for offset in range(0, 0x400, 4):
        if all_differences_larger_threshold(offset, threshold, results):
            favorable_offsets.append({
                'offsets': [str(hex((FIRST_TE_OFFSET + offset + j) % 0x1000)) for j in range(0, 0x1000, 0x400)],
                'average_mean_difference': get_average_mean_difference(offset, results)
            })
    # print(json.dumps(favorable_offsets, indent=2))
    print(json.dumps(sorted(
       favorable_offsets,
       reverse=True,
       key=lambda element: element['average_mean_difference']), indent=2))


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Parsing arguments for memjam results parser')
    arg_parser.add_argument('--inputFile', type=str, required=True, help="Input file name")
    arg_parser.add_argument('--threshold', type=int, default=100)
    args = arg_parser.parse_args()
    main(args.inputFile, args.threshold)
