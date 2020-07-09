#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2018, Linaro Limited
#

import argparse
import array
import os
import re
import sys


def get_args():

    parser = argparse.ArgumentParser(description='Converts a binary file '
                                     'into C source file defining binary '
                                     'data as a constant byte array.')

    parser.add_argument('--bin', required=True,
                        help='Path to the input binary file')

    parser.add_argument('--vname', required=True,
                        help='Variable name for the generated table in '
                        'the output C source file.')

    parser.add_argument('--out', required=True,
                        help='Path for the generated C file')

    parser.add_argument('--text', required=False, action='store_true',
                        help='Treat input as a text file')

    return parser.parse_args()


def main():

    args = get_args()

    with open(args.bin, 'rb') as indata:
        bytes = indata.read()
        if args.text:
            bytes += b'\0'
        size = len(bytes)

    f = open(args.out, 'w')
    f.write('/* Generated from ' + args.bin + ' by ' +
            os.path.basename(__file__) + ' */\n\n')
    f.write('#include <compiler.h>\n')
    f.write('#include <stdint.h>\n')
    if args.text:
        f.write('__extension__ const char ' + args.vname + '[] = {\n')
    else:
        f.write('__extension__ const uint8_t ' + args.vname + '[] ' +
                ' __aligned(__alignof__(uint64_t)) = {\n')
    i = 0
    while i < size:
        if i % 8 == 0:
            f.write('\t\t')
        if args.text and i != size - 1 and bytes[i] == b'\0':
            print('Error: null byte encountered in text file')
            sys.exit(1)
        f.write(hex(bytes[i]) + ',')
        i = i + 1
        if i % 8 == 0 or i == size:
            f.write('\n')
        else:
            f.write(' ')
    f.write('};\n')
    f.close()


if __name__ == "__main__":
    main()
