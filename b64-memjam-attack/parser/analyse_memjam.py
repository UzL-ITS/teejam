import csv

import parse_memjam_multi_iteration as memjam_file_analyzer
import argparse
import os


def main(input_folder):
    directory = os.fsencode(input_folder)
    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        if filename.startswith('log-'):
            memjam_file_analyzer.main(os.path.join(input_folder, filename))

    merged_results_for_steps = []
    results_initialized = 0
    for file in os.listdir("."):
        filename = os.fsdecode(file)
        if filename.startswith('classification_0x'):
            with open(filename, 'r', newline='') as result_file:
                result_reader = csv.reader(result_file, delimiter=';', quotechar='|')
                row_count = 0
                for row in result_reader:
                    if results_initialized == 0:
                        merged_results_for_steps.append([])
                        merged_results_for_steps[row_count].append(row[1])
                    else:
                        if row[1] != '[]':
                            if merged_results_for_steps[row_count][0] == '[]':
                                merged_results_for_steps[row_count][0] = row[1]
                            else:
                                merged_results_for_steps[row_count].append(row[1])
                    row_count += 1

            results_initialized = 1

    with open('result.csv', 'w') as result_file:
        result_writer = csv.writer(result_file, delimiter=';', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for row in merged_results_for_steps:
            result_writer.writerow(row)


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Parsing a sweep of memjam log files')
    arg_parser.add_argument('--inputFolder', type=str, help="Input folder name")
    args = arg_parser.parse_args()

    main(args.inputFolder)
