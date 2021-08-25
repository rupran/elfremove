import os
import sys

#input: function_offsets file from elfremove, essentially a list of ranges of
# start+length pairs of functions which were removed
# Library: /lib/bla.so
# 1234 40
# 2312 300
# Splits the ranges into individual files, named by the basename of the
# corresponding library file

INPUT = sys.argv[1]

with open(INPUT, 'r') as infd:
    cur_lib = None
    cur_file = None
    for line in infd:
        line = line.strip()
        if line.startswith('Library:'):
            if cur_file:
                cur_file.close()
            cur_lib = os.path.basename(line.split(':')[1].strip())
            cur_file = open('{}_{}'.format(INPUT, cur_lib), 'w')
        elif 'blacklist' in line:
            continue
        elif not line:
            continue
        else:
            cur_file.write(line + '\n')
