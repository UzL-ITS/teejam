import parse_memjam_multi_iteration as memjam_file_analyzer

if __name__ == '__main__':

    with open('expected_trace', 'w') as trace_file:
        for i in range(len(memjam_file_analyzer.key)):
            next_char = memjam_file_analyzer.key[i]
            if next_char != '\n':
                trace_file.write(next_char + '\n')