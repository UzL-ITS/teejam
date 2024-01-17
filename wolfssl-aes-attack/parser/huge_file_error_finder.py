import argparse
import re

def main(lfile):
    line_pattern = re.compile('}}},, \\{')
    line_buffer = []
    with open(lfile, 'r') as f:
        cur = 1
        while line := f.readline():
            print(f'Current line: {cur:d}\r', end='')
            line_buffer.append(line.strip())
            if len(line_buffer) > 20:
                line_buffer.pop(0)
            m = line_pattern.search(line.strip())
            if m is not None:
                print(f'Found pattern in line {cur:d}: {line:s}')
                print(f'Buffer: ')
                for lbe in line_buffer:
                    print(lbe)

            cur += 1


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(
        description='Parse and evaluate a wolfSSL trace and a plot a histogram '
                    'with the help of a ground truth')
    arg_parser.add_argument('--logFile', type=str, required=True, help="Log file name")
    args = arg_parser.parse_args()

    main(args.logFile)
