import argparse
import matplotlib.pyplot as plt
from matplotlib import colors
import matplotlib.patches as mpatches
import numpy as np


INVALID_OBSERVATION = 0xFF
INVALID_OBSERVATION_DETECTED = 0x05
MISSING_OBSERVATION = 0x03
VALID_OBSERVATION = 0x01
EMPTY = 0x0F

partition_list = [
    "['(', ')', '*', '+', ',', '/', '-', '.']",
    "['0', '1', '2', '3', '4', '5', '6', '7']",
    "|['8', '9', ':', ';', '<', '=', '>', '?']|",
    "['@', 'A', 'B', 'C', 'D', 'E', 'F', 'G']",
    "['H', 'I', 'J', 'K', 'L', 'M', 'N', 'O']",
    "['P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W']",
    "['X', 'Y', 'Z', '[', '\\', ']', '^', '_']",
    "['`', 'a', 'b', 'c', 'd', 'e', 'f', 'g']",
    "['h', 'i', 'j', 'k', 'l', 'm', 'n', 'o']",
    "['p', 'q', 'r', 's', 't', 'u', 'v', 'w']",
    "|['x', 'y', 'z', '{', '||', '}', '~']|"
]


def compare_reference_and_trace(reference, recorded_trace):
    validation = []
    count_invalid_and_missing_observation = 0
    for i in range(min(len(recorded_trace), len(reference))):
        if i % 64 == 0:
            validation.append([])

        if recorded_trace[i] != '':
            if recorded_trace[i] == "[]":
                validation[-1].append(MISSING_OBSERVATION)
                count_invalid_and_missing_observation += 1
            else:
                obs = INVALID_OBSERVATION_DETECTED
                for part in partition_list:
                    if part == recorded_trace[i]:
                        obs = VALID_OBSERVATION
                        if reference[i] not in list(recorded_trace[i]):
                            # print(reference[i])
                            # print(recorded_trace[i])
                            obs = INVALID_OBSERVATION
                        break
                if obs == INVALID_OBSERVATION or obs == INVALID_OBSERVATION_DETECTED:
                    count_invalid_and_missing_observation += 1

                validation[-1].append(obs)

    print("Missing and invalid observations: " + str(count_invalid_and_missing_observation))

    return validation


def main(reference, trace):
    with open(reference, 'r') as reference_file:
        reference_file_string = reference_file.read()
        reference_file_lines = reference_file_string.split('\n')

    with open(trace, 'r') as trace_file:
        trace_file_string = trace_file.read()
        trace_file_lines = trace_file_string.split('\n')

    result = compare_reference_and_trace(reference=reference_file_lines,
                                         recorded_trace=trace_file_lines)

    for n in range(len(result[-1]), len(result[0])):
        result[-1].append(EMPTY)

    print(result)

    # cmap = colors.ListedColormap(['green', 'blue', 'yellow', 'gray', 'red'])
    color_list = ['forestgreen', 'mediumaquamarine', 'yellow', 'white', 'black']
    label_list = ['Correct classification', 'No classification', 'Multiple classifications', 'No symbol', 'Wrong classification']
    cmap = colors.ListedColormap(color_list)
    bounds = [0, 2, 4, 6, 254, 255]
    norm = colors.BoundaryNorm(bounds, cmap.N)

    plt.imshow(result, interpolation='nearest', origin='upper',
               cmap=cmap, norm=norm)
    ax = plt.gca()
    ax.set_xticks(np.arange(-.5, len(result[0]), 1), minor=True)
    ax.set_yticks(np.arange(-.5, len(result), 1), minor=True)
    # Gridlines based on minor ticks
    ax.grid(which='minor', color='w', linestyle='-', linewidth=2)

    # Remove minor ticks
    ax.tick_params(which='minor', bottom=False, left=False)
    
    patches = [mpatches.Patch(color = color_list[i], label=label_list[i]) for i in range(len(color_list))]
    plt.legend(handles=patches, loc='lower left', borderaxespad=0., bbox_to_anchor=(0,1.02), ncol=5)

    plt.show()


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description='Heatmap visualization of symbol classification')
    arg_parser.add_argument('--reference', type=str, help="Reference input file name")
    arg_parser.add_argument('--trace', type=str, help="Trace input file name")
    args = arg_parser.parse_args()

    main(args.reference, args.trace)
